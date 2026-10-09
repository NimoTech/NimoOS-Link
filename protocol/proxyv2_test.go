package protocol

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func tcp(ip string, port int) *net.TCPAddr { return &net.TCPAddr{IP: net.ParseIP(ip), Port: port} }

func TestProxyRoundTrip(t *testing.T) {
	cases := []struct{ src, dst *net.TCPAddr }{
		{tcp("203.0.113.7", 51234), tcp("10.0.0.5", 443)},
		{tcp("2001:db8::1", 40000), tcp("2001:db8::2", 443)},
		{tcp("203.0.113.7", 1), tcp("2001:db8::2", 443)}, // mixed → IPv6 family
	}
	for _, c := range cases {
		var buf bytes.Buffer
		if err := WriteProxyHeader(&buf, c.src, c.dst); err != nil {
			t.Fatal(err)
		}
		buf.WriteString("rest")
		src, dst, err := ReadProxyHeader(&buf)
		if err != nil {
			t.Fatalf("%v -> %v: %v", c.src, c.dst, err)
		}
		if !src.IP.Equal(c.src.IP) || src.Port != c.src.Port || !dst.IP.Equal(c.dst.IP) || dst.Port != c.dst.Port {
			t.Errorf("got %v -> %v, want %v -> %v", src, dst, c.src, c.dst)
		}
		if rest, _ := io.ReadAll(&buf); string(rest) != "rest" {
			t.Errorf("reader position wrong, rest = %q", rest)
		}
	}
}

func header(t *testing.T) []byte {
	var buf bytes.Buffer
	if err := WriteProxyHeader(&buf, tcp("203.0.113.7", 51234), tcp("10.0.0.5", 443)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestProxyTruncated(t *testing.T) {
	h := header(t)
	for n := 0; n < len(h); n++ {
		if _, _, err := ReadProxyHeader(bytes.NewReader(h[:n])); !errors.Is(err, ErrBadProxyHeader) {
			t.Errorf("truncated at %d: err = %v", n, err)
		}
	}
}

func TestProxyRejectsBadHeaders(t *testing.T) {
	mut := func(f func(h []byte) []byte) []byte { return f(header(t)) }
	cases := map[string][]byte{
		"bad signature":    mut(func(h []byte) []byte { h[0] = 'X'; return h }),
		"LOCAL command":    mut(func(h []byte) []byte { h[12] = 0x20; return h }),
		"version 1":        mut(func(h []byte) []byte { h[12] = 0x11; return h }),
		"UDP family":       mut(func(h []byte) []byte { h[13] = 0x12; return h }),
		"length too big":   mut(func(h []byte) []byte { h[14], h[15] = 0xff, 0xff; return h }),
		"length too small": mut(func(h []byte) []byte { h[14], h[15] = 0, 4; return h }),
		"plain HTTP":       []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
	}
	for name, h := range cases {
		if _, _, err := ReadProxyHeader(bytes.NewReader(h)); !errors.Is(err, ErrBadProxyHeader) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestProxySkipsTLVs(t *testing.T) {
	h := header(t)
	h[15] += 5 // address block 12 + 5 bytes of TLV
	h = append(h, 0x04, 0x00, 0x02, 'h', 'i')
	h = append(h, []byte("payload")...)
	r := bytes.NewReader(h)
	if _, _, err := ReadProxyHeader(r); err != nil {
		t.Fatal(err)
	}
	if rest, _ := io.ReadAll(r); string(rest) != "payload" {
		t.Errorf("rest = %q", rest)
	}
}

func TestAcceptProxy(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	go func() {
		_ = WriteProxyHeader(a, tcp("203.0.113.7", 51234), tcp("10.0.0.5", 443))
		_, _ = a.Write([]byte("hello"))
	}()
	pc, err := AcceptProxy(b, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got := pc.RemoteAddr().String(); got != "203.0.113.7:51234" {
		t.Errorf("RemoteAddr = %s", got)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(pc, buf); err != nil || string(buf) != "hello" {
		t.Errorf("read %q, %v", buf, err)
	}
}

func TestAcceptProxyTimeout(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	start := time.Now()
	if _, err := AcceptProxy(b, 100*time.Millisecond); err == nil {
		t.Fatal("want error")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("took %v", d)
	}
	if _, err := b.Write([]byte("x")); err == nil {
		t.Error("connection should be closed after a failed header")
	}
}

func TestPrefixConn(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	go func() { _, _ = a.Write([]byte(" world")) }()
	pc := NewPrefixConn(b, []byte("hello"))
	buf := make([]byte, 11)
	if _, err := io.ReadFull(pc, buf); err != nil || string(buf) != "hello world" {
		t.Errorf("read %q, %v", buf, err)
	}
}
