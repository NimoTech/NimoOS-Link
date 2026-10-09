package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// PROXY protocol v2 (haproxy proxy-protocol.txt §2.2), TCP over IPv4/IPv6 only.
var proxySig = []byte("\r\n\r\n\x00\r\nQUIT\n")

const (
	proxyV2Proxy = 0x21 // version 2, command PROXY
	famTCP4      = 0x11
	famTCP6      = 0x21
	maxProxyLen  = 512 // address block plus TLVs; anything bigger is hostile
)

// ErrBadProxyHeader is returned for a missing, truncated or malformed header.
var ErrBadProxyHeader = errors.New("protocol: bad PROXY v2 header")

// WriteProxyHeader writes the PROXY v2 header for a TCP connection src → dst.
func WriteProxyHeader(w io.Writer, src, dst *net.TCPAddr) error {
	buf := make([]byte, 0, 16+36)
	buf = append(buf, proxySig...)
	buf = append(buf, proxyV2Proxy)
	if s4, d4 := src.IP.To4(), dst.IP.To4(); s4 != nil && d4 != nil {
		buf = append(buf, famTCP4, 0, 12)
		buf = append(buf, s4...)
		buf = append(buf, d4...)
	} else {
		s16, d16 := src.IP.To16(), dst.IP.To16()
		if s16 == nil || d16 == nil {
			return fmt.Errorf("protocol: invalid PROXY addresses %v -> %v", src, dst)
		}
		buf = append(buf, famTCP6, 0, 36)
		buf = append(buf, s16...)
		buf = append(buf, d16...)
	}
	buf = binary.BigEndian.AppendUint16(buf, uint16(src.Port))
	buf = binary.BigEndian.AppendUint16(buf, uint16(dst.Port))
	_, err := w.Write(buf)
	return err
}

// ReadProxyHeader reads exactly one PROXY v2 header from r (never more) and
// returns the visitor (src) and destination (dst) addresses.
func ReadProxyHeader(r io.Reader) (src, dst *net.TCPAddr, err error) {
	var hdr [16]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrBadProxyHeader, err)
	}
	if !bytes.Equal(hdr[:12], proxySig) || hdr[12] != proxyV2Proxy {
		return nil, nil, ErrBadProxyHeader
	}
	var alen int
	switch hdr[13] {
	case famTCP4:
		alen = 12
	case famTCP6:
		alen = 36
	default:
		return nil, nil, ErrBadProxyHeader
	}
	n := int(binary.BigEndian.Uint16(hdr[14:16]))
	if n < alen || n > maxProxyLen {
		return nil, nil, ErrBadProxyHeader
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrBadProxyHeader, err)
	}
	ipLen := (alen - 4) / 2
	src = &net.TCPAddr{
		IP:   net.IP(append([]byte(nil), body[:ipLen]...)),
		Port: int(binary.BigEndian.Uint16(body[2*ipLen:])),
	}
	dst = &net.TCPAddr{
		IP:   net.IP(append([]byte(nil), body[ipLen:2*ipLen]...)),
		Port: int(binary.BigEndian.Uint16(body[2*ipLen+2:])),
	}
	return src, dst, nil
}
