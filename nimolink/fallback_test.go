package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/NimoTech/NimoOS-Link/protocol"
)

// fallbackNAS is a TLS listener playing the NAS's remote entry: it offers protos,
// and on the fallback protocol reads the credential, answers status, then
// echoes frames back.
func fallbackNAS(t *testing.T, protos []string, status byte) (remoteURL string, creds chan string) {
	t.Helper()
	h := httptest.NewUnstartedServer(nil)
	h.StartTLS() // only for its certificate
	cert := h.TLS.Certificates[0]
	pool := x509.NewCertPool()
	pool.AddCert(h.Certificate())
	h.Close()
	old := fallbackRoots
	fallbackRoots = pool
	t.Cleanup(func() { fallbackRoots = old })

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: protos})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	creds = make(chan string, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, protocol.MaxFrame)
				cred, err := protocol.ReadFrame(c, buf)
				if err != nil {
					return
				}
				creds <- string(cred)
				if protocol.WriteFrame(c, []byte{status}) != nil || status != protocol.FallbackOK {
					return
				}
				for {
					p, err := protocol.ReadFrame(c, buf)
					if err != nil || protocol.WriteFrame(c, p) != nil {
						return
					}
				}
			}(c)
		}
	}()
	return "https://" + ln.Addr().String(), creds
}

func fallbackConfig(t *testing.T) Config {
	c := testConfig(t)
	c.DeviceToken = "PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP"
	return c
}

type delivered struct {
	mu  sync.Mutex
	got [][]byte
}

func (d *delivered) DeliverRelay(p []byte) {
	d.mu.Lock()
	d.got = append(d.got, append([]byte(nil), p...))
	d.mu.Unlock()
}

func (d *delivered) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.got)
}

func TestDialFallback(t *testing.T) {
	c := fallbackConfig(t)
	var creds chan string
	c.RemoteURL, creds = fallbackNAS(t, []string{protocol.FallbackALPN}, protocol.FallbackOK)
	fc, err := dialFallback(context.Background(), c, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer fc.Close()
	if got := <-creds; got != c.DeviceToken {
		t.Fatalf("NAS got credential %q", got)
	}
	if fc.host != "127.0.0.1" {
		t.Fatalf("host %q", fc.host)
	}
	d := &delivered{}
	go fc.Run(d)
	pkt := bytes.Repeat([]byte{4}, 148)
	if err := protocol.WriteFrame(fc, pkt); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100 && d.count() == 0; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if d.count() != 1 || !bytes.Equal(d.got[0], pkt) {
		t.Fatalf("delivered %d packets", d.count())
	}
}

func TestDialFallbackRefused(t *testing.T) {
	for _, tc := range []struct {
		name   string
		protos []string
		status byte
		want   error
	}{
		{"removed", []string{protocol.FallbackALPN}, protocol.FallbackInvalid, ErrDeviceRemoved},
		{"unavailable", []string{protocol.FallbackALPN}, protocol.FallbackUnavailable, errFallbackUnavailable},
		{"older NAS", []string{"http/1.1"}, protocol.FallbackOK, errFallbackUnsupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := fallbackConfig(t)
			c.RemoteURL, _ = fallbackNAS(t, tc.protos, tc.status)
			if _, err := dialFallback(context.Background(), c, nil); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// A NAS whose certificate does not verify gets nothing: not the credential.
func TestDialFallbackChecksTheCertificate(t *testing.T) {
	c := fallbackConfig(t)
	var creds chan string
	c.RemoteURL, creds = fallbackNAS(t, []string{protocol.FallbackALPN}, protocol.FallbackOK)
	fallbackRoots = x509.NewCertPool()
	if _, err := dialFallback(context.Background(), c, nil); err == nil {
		t.Fatal("dialed a NAS with an untrusted certificate")
	}
	select {
	case got := <-creds:
		t.Fatalf("the credential was sent: %q", got)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestFallbackAddr(t *testing.T) {
	for in, want := range map[string]string{
		"https://5wmfzvxpsm.relay-test.nimotech.ai":       "5wmfzvxpsm.relay-test.nimotech.ai:443",
		"https://5wmfzvxpsm.relay-test.nimotech.ai/":      "5wmfzvxpsm.relay-test.nimotech.ai:443",
		"https://5wmfzvxpsm.relay-test.nimotech.ai:8443/": "5wmfzvxpsm.relay-test.nimotech.ai:8443",
	} {
		if _, got, err := fallbackAddr(in); err != nil || got != want {
			t.Errorf("%s: %q %v", in, got, err)
		}
	}
	if _, _, err := fallbackAddr(""); err == nil {
		t.Error("an empty remote address was accepted")
	}
}

func TestNoRelayWhenAlive(t *testing.T) {
	if relayDue(time.Now(), relayState{}, true) {
		t.Fatal("relay while the current path answers")
	}
}

func TestRelayWhenDead(t *testing.T) {
	now := time.Now()
	if !relayDue(now, relayState{}, false) {
		t.Fatal("no relay with the current path dead")
	}
	if relayDue(now, relayState{conn: &fallbackConn{}}, false) {
		t.Fatal("a second connection while one is open")
	}
	older := relayState{next: now.Add(relayUnsupportedWait)}
	if relayDue(now.Add(59*time.Minute), older, false) || !relayDue(now.Add(relayUnsupportedWait), older, false) {
		t.Fatal("an older NAS is retried within the hour, or never")
	}
}

func TestRelayBackoff(t *testing.T) {
	now := time.Now()
	var s relayState
	var waits []time.Duration
	for i := 0; i < 7; i++ {
		s.failed(now)
		waits = append(waits, s.next.Sub(now))
	}
	want := []time.Duration{1, 2, 4, 8, 16, 30, 30}
	for i := range want {
		if waits[i] != want[i]*time.Second {
			t.Fatalf("waits %v", waits)
		}
	}
}

func TestRelayCloseAfter30s(t *testing.T) {
	left := time.Now()
	s := relayState{conn: &fallbackConn{}, left: left}
	if relayCloseDue(left.Add(29*time.Second), s, false) {
		t.Fatal("closed after 29 s")
	}
	if !relayCloseDue(left.Add(30*time.Second), s, false) {
		t.Fatal("still open after 30 s")
	}
	if relayCloseDue(left.Add(time.Hour), s, true) {
		t.Fatal("closed while the tunnel is on it")
	}
	if relayCloseDue(left.Add(time.Hour), relayState{conn: &fallbackConn{}}, false) {
		t.Fatal("closed without having left it")
	}
}

func TestPathModeFlag(t *testing.T) {
	for _, ok := range [][2]string{{"", ""}, {"relay", ""}, {"direct", ""}, {"direct", "192.168.1.118:51900"}} {
		if err := checkPathMode(ok[0], ok[1]); err != nil {
			t.Errorf("%q %q: %v", ok[0], ok[1], err)
		}
	}
	for _, bad := range [][2]string{{"stun", ""}, {"relay", "192.168.1.118:51900"}} {
		if checkPathMode(bad[0], bad[1]) == nil {
			t.Errorf("%q %q accepted", bad[0], bad[1])
		}
	}
}
