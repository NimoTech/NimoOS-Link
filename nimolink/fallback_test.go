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
	"sync/atomic"
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
		"https://k7f3x2ab2m.relay-test.nimotech.ai":       "k7f3x2ab2m.relay-test.nimotech.ai:443",
		"https://k7f3x2ab2m.relay-test.nimotech.ai/":      "k7f3x2ab2m.relay-test.nimotech.ai:443",
		"https://k7f3x2ab2m.relay-test.nimotech.ai:8443/": "k7f3x2ab2m.relay-test.nimotech.ai:8443",
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

type fakeRelayConn struct{ closed atomic.Bool }

func (f *fakeRelayConn) Close() error { f.closed.Store(true); return nil }

func TestAwaitPairing(t *testing.T) {
	const grace, dialAfter, poll = 200 * time.Millisecond, 50 * time.Millisecond, 5 * time.Millisecond
	type dialed struct {
		at   time.Duration
		conn *fakeRelayConn
	}
	run := func(fresh func(time.Duration) bool, dialErr error) (bool, *earlyRelay[*fakeRelayConn], []dialed) {
		var mu sync.Mutex
		var calls []dialed
		start := time.Now()
		home, early := awaitPairing(context.Background(), grace, dialAfter, poll,
			func() bool { return fresh(time.Since(start)) },
			func(context.Context) (*fakeRelayConn, error) {
				time.Sleep(30 * time.Millisecond) // the relay takes a while
				c := &fakeRelayConn{}
				mu.Lock()
				calls = append(calls, dialed{time.Since(start), c})
				mu.Unlock()
				if dialErr != nil {
					return nil, dialErr
				}
				return c, nil
			})
		time.Sleep(60 * time.Millisecond) // a connection closed in the background
		mu.Lock()
		defer mu.Unlock()
		return home, early, calls
	}

	// at home: the endpoint answers at once, the relay is never dialed
	home, early, calls := run(func(time.Duration) bool { return true }, nil)
	if !home || early != nil || len(calls) != 0 {
		t.Fatalf("at home at once: home %v, early %v, %d dials", home, early, len(calls))
	}

	// at home, but late: the early connection is closed, not handed back
	home, early, calls = run(func(d time.Duration) bool { return d > 120*time.Millisecond }, nil)
	if !home || early != nil || len(calls) != 1 || !calls[0].conn.closed.Load() {
		t.Fatalf("at home late: home %v, early %v, calls %+v", home, early, calls)
	}

	// away: dialed once after dialAfter, during the grace, and handed back open
	start := time.Now()
	home, early, calls = run(func(time.Duration) bool { return false }, nil)
	took := time.Since(start) - 60*time.Millisecond
	if home || early == nil || early.err != nil || len(calls) != 1 || early.conn != calls[0].conn || early.conn.closed.Load() {
		t.Fatalf("away: home %v, early %+v, calls %+v", home, early, calls)
	}
	if calls[0].at < dialAfter || calls[0].at > grace {
		t.Fatalf("dialed at %s, want between %s and %s", calls[0].at, dialAfter, grace)
	}
	if took > grace+100*time.Millisecond {
		t.Fatalf("the grace took %s: the dial was not overlapped with it", took)
	}

	// the endpoint answers while the relay is still being dialed after the
	// grace: at home after all, that connection is closed
	slow := func(context.Context) (*fakeRelayConn, error) {
		time.Sleep(250 * time.Millisecond)
		return &fakeRelayConn{}, nil
	}
	start = time.Now()
	var late *fakeRelayConn
	home, early = awaitPairing(context.Background(), grace, dialAfter, poll,
		func() bool { return time.Since(start) > grace+50*time.Millisecond },
		func(ctx context.Context) (*fakeRelayConn, error) { c, err := slow(ctx); late = c; return c, err })
	if !home || early != nil || late == nil || !late.closed.Load() {
		t.Fatalf("answered during the dial: home %v, early %+v, conn %+v", home, early, late)
	}

	// -path=direct: no dial at all, only the wait
	home, early = awaitPairing[*fakeRelayConn](context.Background(), grace, dialAfter, poll, func() bool { return false }, nil)
	if home || early != nil {
		t.Fatalf("no dial: home %v, early %+v", home, early)
	}

	// away, the dial failed: the error comes back for the usual backoff
	boom := errors.New("boom")
	_, early, _ = run(func(time.Duration) bool { return false }, boom)
	if early == nil || !errors.Is(early.err, boom) || early.conn != nil {
		t.Fatalf("failed dial: %+v", early)
	}

	// up ends during the grace: nothing handed back, a connection made is closed
	ctx, cancel := context.WithCancel(context.Background())
	var made atomic.Pointer[fakeRelayConn]
	go func() { time.Sleep(70 * time.Millisecond); cancel() }()
	home, early2 := awaitPairing(ctx, grace, dialAfter, poll, func() bool { return false },
		func(context.Context) (*fakeRelayConn, error) {
			time.Sleep(40 * time.Millisecond)
			c := &fakeRelayConn{}
			made.Store(c)
			return c, nil
		})
	time.Sleep(80 * time.Millisecond)
	if home || early2 != nil || made.Load() == nil || !made.Load().closed.Load() {
		t.Fatalf("cancelled: home %v, early %+v, made %+v", home, early2, made.Load())
	}
}
