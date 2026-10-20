package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/NimoTech/NimoOS-Link/protocol"
)

// The relay fallback (PROTOCOL.md §6): when no direct path answers, WireGuard
// travels in frames over TLS to the NAS's remote address, through the relay.

var (
	errFallbackUnsupported = errors.New("this NAS does not offer the relay fallback (older NimoOS); trying only direct paths for an hour")
	errFallbackUnavailable = errors.New("the NAS cannot carry the tunnel over the relay right now")
)

const (
	fallbackTimeout      = 10 * time.Second // dial, handshake and the status frame
	fallbackWriteTimeout = 10 * time.Second
	relayKeep            = 30 * time.Second // keep the connection this long after leaving it
	relayBackoffMin      = time.Second
	relayBackoffMax      = 30 * time.Second
	relayUnsupportedWait = time.Hour
)

// fallbackRoots: the CAs the NAS's certificate must chain to; nil is the
// system's. Tests replace it.
var fallbackRoots *x509.CertPool

// fallbackConn is an open fallback connection the NAS accepted.
type fallbackConn struct {
	host   string // the remote address's host, for status
	opened time.Time
	c      *tls.Conn
	wmu    sync.Mutex
}

// fallbackAddr: the remote address's host, and where to dial it (443 unless
// the address names a port).
func fallbackAddr(remote string) (host, addr string, err error) {
	u, err := url.Parse(remote)
	if err != nil || u.Hostname() == "" {
		return "", "", fmt.Errorf("no usable remote address (%q)", remote)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return u.Hostname(), net.JoinHostPort(u.Hostname(), port), nil
}

// dialFallback opens the fallback connection and presents the device
// credential. Status 1 is ErrDeviceRemoved; a NAS that does not speak the
// protocol is errFallbackUnsupported.
func dialFallback(ctx context.Context, c Config, trace io.Writer) (*fallbackConn, error) {
	host, addr, err := fallbackAddr(c.RemoteURL)
	if err != nil {
		return nil, err
	}
	if trace != nil {
		fmt.Fprintf(trace, "fallback: dialing %s\n", addr)
	}
	ctx, cancel := context.WithTimeout(ctx, fallbackTimeout)
	defer cancel()
	d := tls.Dialer{Config: &tls.Config{
		ServerName: host,
		NextProtos: []string{protocol.FallbackALPN},
		MinVersion: tls.VersionTLS12,
		RootCAs:    fallbackRoots,
	}}
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		// An older NAS refuses the protocol in the handshake.
		if strings.Contains(err.Error(), "no application protocol") {
			return nil, errFallbackUnsupported
		}
		return nil, fmt.Errorf("fallback: %v", err)
	}
	tc := nc.(*tls.Conn)
	if tc.ConnectionState().NegotiatedProtocol != protocol.FallbackALPN {
		tc.Close()
		return nil, errFallbackUnsupported
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = tc.SetDeadline(dl)
	}
	if err := protocol.WriteFrame(tc, []byte(c.DeviceToken)); err != nil {
		tc.Close()
		return nil, fmt.Errorf("fallback: %v", err)
	}
	st, err := protocol.ReadFrame(tc, make([]byte, protocol.MaxFrame))
	if err == nil && len(st) != 1 {
		err = errors.New("status frame is not one byte")
	}
	if err != nil {
		tc.Close()
		return nil, fmt.Errorf("fallback: no status from the NAS: %v", err)
	}
	if trace != nil {
		fmt.Fprintf(trace, "fallback: status %d\n", st[0])
	}
	switch st[0] {
	case protocol.FallbackOK:
	case protocol.FallbackInvalid:
		tc.Close()
		return nil, ErrDeviceRemoved
	case protocol.FallbackUnavailable:
		tc.Close()
		return nil, errFallbackUnavailable
	default:
		tc.Close()
		return nil, fmt.Errorf("fallback: unknown status %d", st[0])
	}
	_ = tc.SetDeadline(time.Time{})
	return &fallbackConn{host: host, opened: time.Now(), c: tc}, nil
}

// Write sends frames the Bind built; the Bind may call it from several
// goroutines.
func (f *fallbackConn) Write(p []byte) (int, error) {
	f.wmu.Lock()
	defer f.wmu.Unlock()
	_ = f.c.SetWriteDeadline(time.Now().Add(fallbackWriteTimeout))
	return f.c.Write(p)
}

// Run hands every frame to WireGuard until the connection fails or is closed.
func (f *fallbackConn) Run(to interface{ DeliverRelay([]byte) }) error {
	buf := make([]byte, protocol.MaxFrame)
	for {
		p, err := protocol.ReadFrame(f.c, buf)
		if err != nil {
			return err
		}
		to.DeliverRelay(p)
	}
}

func (f *fallbackConn) Close() error { return f.c.Close() }

// relayState is what connectLoop knows about the fallback.
type relayState struct {
	conn    *fallbackConn // open, or nil
	left    time.Time     // when the tunnel moved from it to a direct path; zero while on it
	next    time.Time     // no new connection before this (backoff, or an older NAS)
	backoff time.Duration
}

// earlyRelay is the result of a relay dial made during the start's grace.
type earlyRelay[C any] struct {
	conn C
	err  error
}

// awaitPairing gives the pairing endpoint up to grace to shake hands (at home
// it does, and there the relay is not wanted). Once dialAfter has passed
// without a handshake it already dials the relay, so that a client away from
// home has it ready when the grace ends instead of starting then. home: the
// endpoint answered; a connection dialed meanwhile is closed. Otherwise early
// is that dial's result (waited for), or nil when none was started or ctx
// ended. A nil dial never dials (-path=direct).
func awaitPairing[C interface{ Close() error }](ctx context.Context, grace, dialAfter, poll time.Duration,
	fresh func() bool, dial func(context.Context) (C, error)) (home bool, early *earlyRelay[C]) {
	start := time.Now()
	var ch chan earlyRelay[C]
	discard := func() {
		if ch != nil {
			go func() {
				if r := <-ch; r.err == nil {
					r.conn.Close()
				}
			}()
		}
	}
	for time.Since(start) < grace {
		if fresh() {
			discard()
			return true, nil
		}
		if ch == nil && dial != nil && time.Since(start) >= dialAfter {
			ch = make(chan earlyRelay[C], 1)
			go func() {
				c, err := dial(ctx)
				ch <- earlyRelay[C]{c, err}
			}()
		}
		select {
		case <-ctx.Done():
			discard()
			return false, nil
		case <-time.After(poll):
		}
	}
	if ch == nil {
		return false, nil
	}
	select {
	case r := <-ch:
		if fresh() { // it answered while the relay was still being dialed
			if r.err == nil {
				r.conn.Close()
			}
			return true, nil
		}
		return false, &r
	case <-ctx.Done():
		discard()
		return false, nil
	}
}

// relayDue: open a fallback connection now? Only when the current path does
// not answer, none is open, and nothing says wait.
func relayDue(now time.Time, s relayState, curAlive bool) bool {
	return !curAlive && s.conn == nil && !now.Before(s.next)
}

// relayCloseDue: close the connection kept after moving to a direct path?
func relayCloseDue(now time.Time, s relayState, onRelay bool) bool {
	return s.conn != nil && !onRelay && !s.left.IsZero() && now.Sub(s.left) >= relayKeep
}

// failed sets the next attempt after a failed or lost connection: 1 s,
// doubling to 30 s.
func (s *relayState) failed(now time.Time) {
	if s.backoff < relayBackoffMin {
		s.backoff = relayBackoffMin
	}
	s.next = now.Add(s.backoff)
	if s.backoff *= 2; s.backoff > relayBackoffMax {
		s.backoff = relayBackoffMax
	}
}
