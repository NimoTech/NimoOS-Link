package protocol

import (
	"bytes"
	"io"
	"net"
	"time"
)

// ProxyConn is a relayed visitor connection whose addresses come from its PROXY header.
type ProxyConn struct {
	net.Conn
	src, dst *net.TCPAddr
}

// RemoteAddr is the visitor's address as seen by the relay.
func (c *ProxyConn) RemoteAddr() net.Addr { return c.src }

// LocalAddr is the relay address the visitor connected to.
func (c *ProxyConn) LocalAddr() net.Addr { return c.dst }

// AcceptProxy reads the PROXY header from c within timeout. On any failure it
// closes c: a stream without a valid header must never be served.
func AcceptProxy(c net.Conn, timeout time.Duration) (*ProxyConn, error) {
	if err := c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		c.Close()
		return nil, err
	}
	src, dst, err := ReadProxyHeader(c)
	if err != nil {
		c.Close()
		return nil, err
	}
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		c.Close()
		return nil, err
	}
	return &ProxyConn{Conn: c, src: src, dst: dst}, nil
}

// PrefixConn replays bytes that were already read from Conn before reading it again.
type PrefixConn struct {
	net.Conn
	r io.Reader
}

func NewPrefixConn(c net.Conn, prefix []byte) *PrefixConn {
	return &PrefixConn{Conn: c, r: io.MultiReader(bytes.NewReader(prefix), c)}
}

func (p *PrefixConn) Read(b []byte) (int, error) { return p.r.Read(b) }
