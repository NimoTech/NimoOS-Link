package protocol

import (
	"encoding/binary"
	"errors"
	"io"
)

// The relay fallback of a direct connection: when a client cannot punch
// through, it opens TLS to the NAS's remote address with FallbackALPN as the
// only protocol. The relay forwards it like any visitor (it reads the ALPN
// only to hold such connections to their own rate); the NAS ends the TLS.
//
// On it everything is a frame: a uint16 big-endian length (1–MaxFrame), then
// that many bytes. The client's first frame is its device credential; the
// NAS answers with one frame of one status byte and, on FallbackOK, every
// frame after that in either direction is one WireGuard packet.
const (
	FallbackALPN = "nimolink-wg/1"

	FallbackOK          byte = 0 // carry packets from now on
	FallbackInvalid     byte = 1 // the credential is no good: the device was removed
	FallbackUnavailable byte = 2 // not now (user service down, tunnel not up); try again later

	MaxFrame = 65535
)

var (
	ErrEmptyFrame   = errors.New("protocol: empty frame")
	ErrFrameTooLong = errors.New("protocol: frame longer than 65535 bytes")
)

// WriteFrame writes p as one frame, in one Write so that TLS does not split
// the length from its bytes.
func WriteFrame(w io.Writer, p []byte) error {
	switch {
	case len(p) == 0:
		return ErrEmptyFrame
	case len(p) > MaxFrame:
		return ErrFrameTooLong
	}
	b := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(b, uint16(len(p)))
	copy(b[2:], p)
	_, err := w.Write(b)
	return err
}

// ReadFrame reads one frame into buf (at least MaxFrame bytes) and returns
// it. A stream that ends between frames gives io.EOF, inside one
// io.ErrUnexpectedEOF.
func ReadFrame(r io.Reader, buf []byte) ([]byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(h[:]))
	if n == 0 {
		return nil, ErrEmptyFrame
	}
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return buf[:n], nil
}
