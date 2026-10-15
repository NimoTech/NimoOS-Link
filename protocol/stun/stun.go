// Package stun is the part of STUN (RFC 5389) NimoLink uses: Binding
// requests and success responses with XOR-MAPPED-ADDRESS, USERNAME,
// MESSAGE-INTEGRITY and FINGERPRINT. Nothing else is written; other
// attributes are skipped when reading. The relay's STUN service, the NAS
// (whose WireGuard port answers signed connectivity checks) and the client
// all use it.
package stun

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"net/netip"
)

const (
	MagicCookie = 0x2112A442
	HeaderLen   = 20

	TypeBindingRequest = 0x0001
	TypeBindingSuccess = 0x0101

	// MaxUsername bounds USERNAME (RFC 5389: less than 513 bytes).
	MaxUsername = 512

	attrMappedAddress    = 0x0001
	attrUsername         = 0x0006
	attrMessageIntegrity = 0x0008
	attrXORMappedAddress = 0x0020
	attrFingerprint      = 0x8028

	fingerprintXOR = 0x5354554e
)

type TxID [12]byte

func NewTxID() TxID {
	var t TxID
	if _, err := rand.Read(t[:]); err != nil {
		panic(err) // crypto/rand does not fail on supported systems
	}
	return t
}

var ErrMalformed = errors.New("stun: malformed message")

// IsMessage reports whether b is shaped like one STUN message: top two bits
// zero, the magic cookie, and a length that is a multiple of 4 and matches.
func IsMessage(b []byte) bool {
	if len(b) < HeaderLen || b[0]&0xC0 != 0 {
		return false
	}
	if binary.BigEndian.Uint32(b[4:8]) != MagicCookie {
		return false
	}
	n := int(binary.BigEndian.Uint16(b[2:4]))
	return n%4 == 0 && HeaderLen+n == len(b)
}

type Message struct {
	Type     uint16
	TxID     TxID
	Username string
	// Mapped is XOR-MAPPED-ADDRESS, else MAPPED-ADDRESS; zero when absent.
	Mapped netip.AddrPort

	raw   []byte
	miAt  int  // offset of MESSAGE-INTEGRITY; -1: none
	hasFP bool // FINGERPRINT present (and, since Parse got this far, correct)
}

// Parse reads a message. Attributes after MESSAGE-INTEGRITY other than
// FINGERPRINT are ignored (RFC 5389 §15.4); nothing may follow FINGERPRINT,
// and a FINGERPRINT that does not match makes the message malformed.
func Parse(b []byte) (Message, error) {
	if !IsMessage(b) {
		return Message{}, ErrMalformed
	}
	m := Message{Type: binary.BigEndian.Uint16(b[0:2]), raw: b, miAt: -1}
	copy(m.TxID[:], b[8:20])
	var plain netip.AddrPort
	for i := HeaderLen; i < len(b); {
		if m.hasFP || i+4 > len(b) {
			return Message{}, ErrMalformed
		}
		typ := binary.BigEndian.Uint16(b[i:])
		l := int(binary.BigEndian.Uint16(b[i+2:]))
		v0 := i + 4
		if v0+l > len(b) {
			return Message{}, ErrMalformed
		}
		v := b[v0 : v0+l]
		before := m.miAt < 0
		switch typ {
		case attrUsername:
			if l > MaxUsername {
				return Message{}, ErrMalformed
			}
			if before {
				m.Username = string(v)
			}
		case attrXORMappedAddress:
			if a, ok := readAddr(v, true, m.TxID); ok && before {
				m.Mapped = a
			}
		case attrMappedAddress:
			if a, ok := readAddr(v, false, m.TxID); ok && before {
				plain = a
			}
		case attrMessageIntegrity:
			if l != sha1.Size {
				return Message{}, ErrMalformed
			}
			if before {
				m.miAt = i
			}
		case attrFingerprint:
			if l != 4 {
				return Message{}, ErrMalformed
			}
			// RFC 5389 §7.3: present but wrong means discard the message
			if binary.BigEndian.Uint32(v) != fingerprint(b[:i]) {
				return Message{}, ErrMalformed
			}
			m.hasFP = true
		}
		i = v0 + (l+3)&^3
	}
	if !m.Mapped.IsValid() {
		m.Mapped = plain
	}
	return m, nil
}

// Verify checks MESSAGE-INTEGRITY with key (short-term credential: the key
// is the password as is).
func (m Message) Verify(key []byte) bool {
	if m.miAt < 0 || key == nil {
		return false
	}
	return hmac.Equal(m.raw[m.miAt+4:m.miAt+4+sha1.Size], integrity(m.raw[:m.miAt], key))
}

// FingerprintOK reports that the message carries a FINGERPRINT; a wrong one
// never parses.
func (m Message) FingerprintOK() bool { return m.hasFP }

// integrity is HMAC-SHA1 over prefix with the header length counting up to
// the end of the MESSAGE-INTEGRITY attribute that follows prefix.
func integrity(prefix, key []byte) []byte {
	var hdr [HeaderLen]byte
	copy(hdr[:], prefix[:HeaderLen])
	binary.BigEndian.PutUint16(hdr[2:], uint16(len(prefix)-HeaderLen+4+sha1.Size))
	h := hmac.New(sha1.New, key)
	h.Write(hdr[:])
	h.Write(prefix[HeaderLen:])
	return h.Sum(nil)
}

// fingerprint covers prefix as it is: FINGERPRINT is the last attribute, so
// the header length already counts it.
func fingerprint(prefix []byte) uint32 { return crc32.ChecksumIEEE(prefix) ^ fingerprintXOR }

func readAddr(v []byte, xor bool, tx TxID) (netip.AddrPort, bool) {
	if len(v) < 4 {
		return netip.AddrPort{}, false
	}
	port := binary.BigEndian.Uint16(v[2:4])
	var k [16]byte
	binary.BigEndian.PutUint32(k[:4], MagicCookie)
	copy(k[4:], tx[:])
	if xor {
		port ^= uint16(MagicCookie >> 16)
	}
	switch v[1] {
	case 1:
		if len(v) != 8 {
			return netip.AddrPort{}, false
		}
		var a [4]byte
		copy(a[:], v[4:8])
		if xor {
			for i := range a {
				a[i] ^= k[i]
			}
		}
		return netip.AddrPortFrom(netip.AddrFrom4(a), port), true
	case 2:
		if len(v) != 20 {
			return netip.AddrPort{}, false
		}
		var a [16]byte
		copy(a[:], v[4:20])
		if xor {
			for i := range a {
				a[i] ^= k[i]
			}
		}
		return netip.AddrPortFrom(netip.AddrFrom16(a), port), true
	}
	return netip.AddrPort{}, false
}

func xorAddr(ap netip.AddrPort, tx TxID) []byte {
	var k [16]byte
	binary.BigEndian.PutUint32(k[:4], MagicCookie)
	copy(k[4:], tx[:])
	a := ap.Addr().Unmap()
	ip := a.AsSlice()
	v := make([]byte, 4+len(ip))
	v[1] = 1
	if a.Is6() {
		v[1] = 2
	}
	binary.BigEndian.PutUint16(v[2:], ap.Port()^uint16(MagicCookie>>16))
	for i := range ip {
		v[4+i] = ip[i] ^ k[i]
	}
	return v
}

func appendAttr(b []byte, typ uint16, v []byte) []byte {
	var h [4]byte
	binary.BigEndian.PutUint16(h[0:], typ)
	binary.BigEndian.PutUint16(h[2:], uint16(len(v)))
	b = append(b, h[:]...)
	b = append(b, v...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func setLen(b []byte) { binary.BigEndian.PutUint16(b[2:], uint16(len(b)-HeaderLen)) }

// Build writes a message: USERNAME when username is not empty,
// XOR-MAPPED-ADDRESS when mapped is valid, MESSAGE-INTEGRITY when key is not
// nil, and always FINGERPRINT. username longer than MaxUsername is cut.
func Build(typ uint16, tx TxID, username string, mapped netip.AddrPort, key []byte) []byte {
	b := make([]byte, HeaderLen, 128)
	binary.BigEndian.PutUint16(b[0:], typ)
	binary.BigEndian.PutUint32(b[4:], MagicCookie)
	copy(b[8:], tx[:])
	if len(username) > MaxUsername {
		username = username[:MaxUsername]
	}
	if username != "" {
		b = appendAttr(b, attrUsername, []byte(username))
	}
	if mapped.IsValid() {
		b = appendAttr(b, attrXORMappedAddress, xorAddr(mapped, tx))
	}
	if key != nil {
		at := len(b)
		b = appendAttr(b, attrMessageIntegrity, make([]byte, sha1.Size))
		setLen(b)
		copy(b[at+4:], integrity(b[:at], key))
	}
	at := len(b)
	b = appendAttr(b, attrFingerprint, make([]byte, 4))
	setLen(b)
	binary.BigEndian.PutUint32(b[at+4:], fingerprint(b[:at]))
	return b
}

func BindingRequest(tx TxID, username string, key []byte) []byte {
	return Build(TypeBindingRequest, tx, username, netip.AddrPort{}, key)
}

func BindingSuccess(tx TxID, mapped netip.AddrPort, key []byte) []byte {
	return Build(TypeBindingSuccess, tx, "", mapped, key)
}
