package client

import (
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/NimoTech/NimoOS-Link/protocol"
)

// Listener turns the relay's streams into visitor connections. Each stream's
// PROXY header is read in its own goroutine, so one stream that never sends a
// header cannot hold up the others. Streams with a bad header are dropped.
// At most 256 streams may be reading their header or waiting for Accept at
// once; a stream beyond that is closed immediately.
type Listener struct {
	sess          *yamux.Session
	timeout       time.Duration
	ch            chan net.Conn
	done          chan struct{}
	once          sync.Once
	allowLoopback bool // allow loopback sources (tests only)
	maxPending    int  // streams reading their header or waiting for Accept; tests lower it
	pending       chan struct{}
}

// defaultMaxPending bounds what a hostile relay can make the device hold by
// opening streams: beyond it new streams are closed at once.
const defaultMaxPending = 256

// withMaxPending overrides defaultMaxPending (tests only).
func withMaxPending(n int) ListenerOption { return func(l *Listener) { l.maxPending = n } }

// ListenerOption configures a Listener.
type ListenerOption func(*Listener)

// AllowLoopbackForTesting lets streams whose PROXY source is a loopback
// address through. ONLY for tests that run the relay and the visitor on one
// host; never use in a device build — the device treats loopback as trusted.
// All other rejected source classes stay rejected.
func AllowLoopbackForTesting() ListenerOption { return func(l *Listener) { l.allowLoopback = true } }

// validSource reports whether a PROXY source may be handed to the application.
// The relay is untrusted, and devices treat loopback as authenticated, so a
// forged local or unspecified source must never be delivered.
func (l *Listener) validSource(a net.Addr) bool {
	t, ok := a.(*net.TCPAddr)
	if !ok || t == nil || t.Port == 0 {
		return false
	}
	ip := t.IP
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if len(ip) != net.IPv4len && len(ip) != net.IPv6len {
		return false
	}
	if ip.IsLoopback() {
		return l.allowLoopback
	}
	if len(ip) == net.IPv4len {
		if ip[0] == 0 || ip.Equal(net.IPv4bcast) { // 0.0.0.0/8, limited broadcast
			return false
		}
	} else if isZero(ip[:12]) { // ::/96, deprecated IPv4-compatible (and ::, ::1 handled above/below)
		return false
	}
	return !(ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast())
}

func isZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// NewListener wraps sess. headerTimeout <= 0 means 5 seconds.
func NewListener(sess *yamux.Session, headerTimeout time.Duration, opts ...ListenerOption) *Listener {
	if headerTimeout <= 0 {
		headerTimeout = 5 * time.Second
	}
	l := &Listener{sess: sess, timeout: headerTimeout, ch: make(chan net.Conn), done: make(chan struct{}), maxPending: defaultMaxPending}
	for _, o := range opts {
		o(l)
	}
	if l.maxPending <= 0 {
		l.maxPending = defaultMaxPending
	}
	l.pending = make(chan struct{}, l.maxPending)
	go l.loop()
	return l
}

func (l *Listener) loop() {
	for {
		st, err := l.sess.Accept()
		if err != nil {
			l.Close()
			return
		}
		select {
		case l.pending <- struct{}{}:
		default:
			st.Close() // too many streams not yet handed to the application
			continue
		}
		go func() {
			defer func() { <-l.pending }()
			pc, err := protocol.AcceptProxy(st, l.timeout)
			if err != nil {
				return // AcceptProxy closed the stream
			}
			if !l.validSource(pc.RemoteAddr()) {
				pc.Close()
				return
			}
			select {
			case l.ch <- pc:
			case <-l.done:
				pc.Close()
			}
		}()
	}
}

func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Close stops accepting and closes the session.
func (l *Listener) Close() error {
	l.once.Do(func() {
		close(l.done)
		l.sess.Close()
	})
	return nil
}

func (l *Listener) Addr() net.Addr { return l.sess.Addr() }
