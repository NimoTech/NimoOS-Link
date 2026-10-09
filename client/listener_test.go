package client

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/NimoTech/NimoOS-Link/protocol"
)

func sessions(t *testing.T) (relay, nas *yamux.Session) {
	t.Helper()
	a, b := net.Pipe()
	relay, _ = yamux.Client(a, protocol.YamuxConfig())
	nas, _ = yamux.Server(b, protocol.YamuxConfig())
	t.Cleanup(func() { relay.Close(); nas.Close() })
	return relay, nas
}

func TestListener(t *testing.T) {
	relay, nas := sessions(t)
	l := NewListener(nas, 5*time.Second)
	defer l.Close()

	slow, err := relay.Open() // never sends a header
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Close()

	good, err := relay.Open()
	if err != nil {
		t.Fatal(err)
	}
	src := &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 51234}
	dst := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 443}
	go func() {
		_ = protocol.WriteProxyHeader(good, src, dst)
		_, _ = good.Write([]byte("hi"))
	}()

	done := make(chan net.Conn, 1)
	go func() { c, _ := l.Accept(); done <- c }()
	select {
	case c := <-done:
		if c == nil || c.RemoteAddr().String() != "203.0.113.7:51234" {
			t.Fatalf("accepted %v", c)
		}
		buf := make([]byte, 2)
		if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "hi" {
			t.Errorf("read %q, %v", buf, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a stream without a header blocked the next one")
	}

	l.Close()
	if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Accept after Close = %v", err)
	}
	if !nas.IsClosed() {
		t.Error("Close did not close the session")
	}
}

func hdr(t *testing.T, src string, port int) []byte {
	t.Helper()
	var b bytes.Buffer
	dst := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 443}
	if err := protocol.WriteProxyHeader(&b, &net.TCPAddr{IP: net.ParseIP(src), Port: port}, dst); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// neverAccepted sends payload on a new relay-side stream and asserts the
// stream is closed and never reaches Accept.
func neverAccepted(t *testing.T, payload []byte, timeout time.Duration, opts ...ListenerOption) {
	t.Helper()
	relay, nas := sessions(t)
	l := NewListener(nas, timeout, opts...)
	defer l.Close()
	acc := make(chan net.Conn, 1)
	go func() {
		if c, err := l.Accept(); err == nil {
			acc <- c
		}
	}()
	st, err := relay.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if payload != nil {
		_, _ = st.Write(payload)
	}
	select {
	case c := <-acc:
		t.Fatalf("stream delivered with source %v", c.RemoteAddr())
	case <-time.After(300 * time.Millisecond):
	}
	_ = st.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := st.Read(make([]byte, 1)); err == nil {
		t.Error("stream was not closed")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Errorf("stream still open: %v", err)
	}
}

func TestListenerDropsBadStreams(t *testing.T) {
	local := hdr(t, "203.0.113.7", 1000)
	local[12] = 0x20
	t.Run("garbage", func(t *testing.T) { neverAccepted(t, []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), 5*time.Second) })
	t.Run("local command", func(t *testing.T) { neverAccepted(t, local, 5*time.Second) })
	t.Run("no header", func(t *testing.T) { neverAccepted(t, nil, 100*time.Millisecond) })
	for _, src := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1", "0.0.0.0", "169.254.1.1", "fe80::1", "224.0.0.1"} {
		src := src
		t.Run(src, func(t *testing.T) { neverAccepted(t, hdr(t, src, 4000), 5*time.Second) })
	}
	t.Run("port 0", func(t *testing.T) { neverAccepted(t, hdr(t, "203.0.113.7", 0), 5*time.Second) })
	t.Run("loopback option keeps others rejected", func(t *testing.T) {
		neverAccepted(t, hdr(t, "169.254.1.1", 4000), 5*time.Second, AllowLoopbackForTesting())
	})
}

func acceptWith(t *testing.T, src string, opts ...ListenerOption) (net.Conn, bool) {
	relay, nas := sessions(t)
	l := NewListener(nas, 0, opts...) // 0: default timeout
	defer l.Close()
	st, err := relay.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_, _ = st.Write(hdr(t, src, 4000))
	acc := make(chan net.Conn, 1)
	go func() {
		if c, err := l.Accept(); err == nil {
			acc <- c
		}
	}()
	select {
	case c := <-acc:
		return c, true
	case <-time.After(500 * time.Millisecond):
		return nil, false
	}
}

func TestListenerSourcePolicy(t *testing.T) {
	if _, ok := acceptWith(t, "203.0.113.7"); !ok {
		t.Error("public source not delivered by default (and zero timeout must default)")
	}
	if _, ok := acceptWith(t, "127.0.0.1"); ok {
		t.Error("loopback delivered without the option")
	}
	if _, ok := acceptWith(t, "127.0.0.1", AllowLoopbackForTesting()); !ok {
		t.Error("loopback not delivered with AllowLoopbackForTesting")
	}
}

func TestValidSource(t *testing.T) {
	ip16 := func(s string) net.IP {
		ip := net.ParseIP(s).To16()
		if len(ip) != 16 {
			t.Fatalf("%s: len %d", s, len(ip))
		}
		return ip
	}
	ip4 := func(s string) net.IP { return net.ParseIP(s).To4() }
	tcp := func(ip net.IP) net.Addr { return &net.TCPAddr{IP: ip, Port: 4000} }
	type tc struct {
		name         string
		addr         net.Addr
		def, withLoc bool
	}
	var cases []tc
	rej := func(name string, a net.Addr) { cases = append(cases, tc{name, a, false, false}) }
	for _, s := range []string{"::ffff:0.0.0.0", "::ffff:169.254.1.1", "fe80::1", "ff01::1", "ff02::1", "ff0e::1",
		"::ffff:224.0.0.1", "::ffff:239.1.1.1", "::ffff:0.1.2.3", "::127.0.0.1", "::7f00:1", "::203.0.113.7", "::"} {
		rej(s, tcp(ip16(s)))
	}
	for _, s := range []string{"0.0.0.0", "169.254.1.1", "224.0.0.1", "239.1.1.1", "0.1.2.3", "255.255.255.255"} {
		rej(s+" (4-byte)", tcp(ip4(s)))
	}
	rej("public port 0", &net.TCPAddr{IP: ip4("203.0.113.7")})
	rej("nil ip", &net.TCPAddr{Port: 4000})
	rej("non-TCP", &net.UDPAddr{IP: ip4("203.0.113.7"), Port: 4000})
	for _, s := range []string{"127.0.0.1", "::ffff:127.0.0.1", "::ffff:127.9.9.9", "::1"} {
		a := tcp(ip16(s))
		cases = append(cases, tc{s, a, false, true})
		if s == "127.0.0.1" {
			cases = append(cases, tc{s + " (4-byte)", tcp(ip4(s)), false, true})
		}
	}
	for _, s := range []string{"203.0.113.7", "::ffff:203.0.113.7", "2001:db8::1", "10.0.0.5", "fc00::1"} {
		cases = append(cases, tc{s, tcp(ip16(s)), true, true})
	}
	plain, loop := &Listener{}, &Listener{allowLoopback: true}
	for _, c := range cases {
		if got := plain.validSource(c.addr); got != c.def {
			t.Errorf("%s: default = %v, want %v", c.name, got, c.def)
		}
		if got := loop.validSource(c.addr); got != c.withLoc {
			t.Errorf("%s: with loopback option = %v, want %v", c.name, got, c.withLoc)
		}
	}
}

func tcp6Header(src string) []byte {
	h := append([]byte("\r\n\r\n\x00\r\nQUIT\n"), 0x21, 0x21, 0, 36)
	h = append(h, net.ParseIP(src).To16()...)
	h = append(h, net.ParseIP("2001:db8::1").To16()...)
	return append(h, 0x0f, 0xa0, 0x01, 0xbb) // ports 4000 -> 443
}

func TestListenerDropsTCP6MappedLoopback(t *testing.T) {
	h := tcp6Header("::ffff:127.0.0.1")
	// Prove the header really carries a 16-byte mapped source with a real port,
	// so the drop below is the source filter's doing and not a parse failure.
	src, _, err := protocol.ReadProxyHeader(bytes.NewReader(append([]byte(nil), h...)))
	if err != nil {
		t.Fatalf("header does not parse: %v", err)
	}
	if len(src.IP) != 16 || !src.IP.Equal(net.ParseIP("127.0.0.1")) || src.Port != 4000 {
		t.Fatalf("parsed source %v (len %d)", src, len(src.IP))
	}
	neverAccepted(t, h, 5*time.Second)
}

func TestListenerDeliversTCP6MappedPublic(t *testing.T) {
	relay, nas := sessions(t)
	l := NewListener(nas, 5*time.Second)
	defer l.Close()
	st, err := relay.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_, _ = st.Write(tcp6Header("::ffff:203.0.113.7"))
	acc := make(chan net.Conn, 1)
	go func() {
		if c, err := l.Accept(); err == nil {
			acc <- c
		}
	}()
	select {
	case c := <-acc:
		if got := c.RemoteAddr().String(); got != "203.0.113.7:4000" {
			t.Errorf("RemoteAddr = %s", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("public mapped source not delivered")
	}
}

// A hostile relay cannot make the device hold unlimited streams that are still
// sending their PROXY header or waiting for Accept.
func TestListenerCapsPendingStreams(t *testing.T) {
	relay, nas := sessions(t)
	l := NewListener(nas, 30*time.Second, withMaxPending(2))
	defer l.Close()

	open := func(src string) net.Conn {
		t.Helper()
		st, err := relay.Open()
		if err != nil {
			t.Fatal(err)
		}
		if src != "" {
			if _, err := st.Write(hdr(t, src, 4000)); err != nil {
				t.Fatal(err)
			}
		}
		return st
	}
	silent := open("")             // reading the header (30 s timeout)
	waiting := open("203.0.113.7") // header read, nobody calls Accept yet
	extra := open("203.0.113.8")   // no slot left
	defer extra.Close()
	_ = extra.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := extra.Read(make([]byte, 1)); err == nil {
		t.Fatal("excess stream received data")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("excess stream was kept open")
	}

	// The stream that was waiting is still delivered, not the excess one.
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if got := c.RemoteAddr().String(); got != "203.0.113.7:4000" {
		t.Fatalf("accepted %s, want the stream that held a slot", got)
	}
	c.Close()
	waiting.Close()
	silent.Close() // frees the other slot

	// Freed slots take new streams (freeing is asynchronous: retry briefly).
	acc := make(chan net.Conn, 1)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			if c.RemoteAddr().String() == "203.0.113.9:4000" {
				acc <- c
				return
			}
			c.Close()
		}
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		st := open("203.0.113.9")
		defer st.Close()
		select {
		case <-acc:
			return
		case <-time.After(50 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("no stream accepted after slots were freed")
		}
	}
}

func TestListenerDefaultPendingCap(t *testing.T) {
	_, nas := sessions(t)
	l := NewListener(nas, 0)
	defer l.Close()
	if cap(l.pending) != 256 {
		t.Errorf("default pending cap = %d, want 256", cap(l.pending))
	}
}
