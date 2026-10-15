package stun

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 5769 §2.1 sample request: SOFTWARE, PRIORITY, ICE-CONTROLLED (skipped
// as unknown), USERNAME "evtj:h6vY", MESSAGE-INTEGRITY, FINGERPRINT.
// If a byte here disagrees with the RFC text, the RFC wins.
const rfc5769Request = `
00 01 00 58 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86 fa 87 df ae
80 22 00 10 53 54 55 4e 20 74 65 73 74 20 63 6c 69 65 6e 74
00 24 00 04 6e 00 01 ff
80 29 00 08 93 2f f9 b1 51 26 3b 36
00 06 00 09 65 76 74 6a 3a 68 36 76 59 20 20 20
00 08 00 14 9a ea a7 0c bf d8 cb 56 78 1e f2 b5 b2 d3 f2 49 c1 b5 71 a2
80 28 00 04 e5 7a 3b cf`

// RFC 5769 §2.2 sample IPv4 response: XOR-MAPPED-ADDRESS 192.0.2.1:32853.
const rfc5769Response = `
01 01 00 3c 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86 fa 87 df ae
80 22 00 0b 74 65 73 74 20 76 65 63 74 6f 72 20
00 20 00 08 00 01 a1 47 e1 12 a6 43
00 08 00 14 2b 91 f5 99 fd 9e 90 c3 8c 74 89 f9 2a f9 ba 53 f0 6b e7 d7
80 28 00 04 c0 7d 4c 96`

const rfc5769Password = "VOkJxbRl1RmTxUk/WvJxBt"

func TestRFC5769Request(t *testing.T) {
	b := unhex(t, rfc5769Request)
	if !IsMessage(b) {
		t.Fatal("not recognised as STUN")
	}
	m, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if m.Type != TypeBindingRequest || m.Username != "evtj:h6vY" {
		t.Fatalf("parsed %+v", m)
	}
	if !m.FingerprintOK() {
		t.Error("fingerprint")
	}
	if !m.Verify([]byte(rfc5769Password)) {
		t.Error("message integrity with the right key")
	}
	if m.Verify([]byte("wrong")) {
		t.Error("message integrity with a wrong key")
	}
}

func TestRFC5769Response(t *testing.T) {
	m, err := Parse(unhex(t, rfc5769Response))
	if err != nil {
		t.Fatal(err)
	}
	if m.Type != TypeBindingSuccess || m.Mapped != netip.MustParseAddrPort("192.0.2.1:32853") {
		t.Fatalf("parsed %+v", m)
	}
	if !m.FingerprintOK() || !m.Verify([]byte(rfc5769Password)) {
		t.Error("fingerprint / integrity")
	}
}

func TestRoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	for _, mapped := range []string{"203.0.113.7:51446", "[2001:db8::5]:51900"} {
		tx := NewTxID()
		ap := netip.MustParseAddrPort(mapped)
		m, err := Parse(BindingSuccess(tx, ap, key))
		if err != nil {
			t.Fatal(err)
		}
		if m.TxID != tx || m.Mapped != ap || !m.Verify(key) || !m.FingerprintOK() {
			t.Errorf("%s: %+v", mapped, m)
		}
	}
	tx := NewTxID()
	m, err := Parse(BindingRequest(tx, "session-id", key))
	if err != nil || m.Username != "session-id" || !m.Verify(key) || !m.FingerprintOK() {
		t.Fatalf("request: %+v %v", m, err)
	}
	// unsigned: no integrity to verify, fingerprint still there
	m, err = Parse(BindingRequest(tx, "", nil))
	if err != nil || m.Verify(key) || !m.FingerprintOK() {
		t.Fatalf("plain request: %+v %v", m, err)
	}
}

func TestTamperingIsCaught(t *testing.T) {
	key := []byte("k")
	b := BindingRequest(NewTxID(), "sess", key)
	for i := HeaderLen; i < len(b); i++ {
		c := bytes.Clone(b)
		c[i] ^= 0x01
		m, err := Parse(c)
		if err == nil && m.Verify(key) && m.FingerprintOK() {
			t.Fatalf("byte %d flipped and still verifies", i)
		}
	}
}

func TestRejects(t *testing.T) {
	good := BindingRequest(NewTxID(), "", nil)
	wgInit := make([]byte, 148)
	wgInit[0] = 1 // WireGuard handshake initiation
	cases := map[string][]byte{
		"short":                 good[:19],
		"top bits":              append([]byte{0x40}, good[1:]...),
		"wrong cookie":          append(append(bytes.Clone(good[:4]), 0, 0, 0, 0), good[8:]...),
		"length mismatch":       append(bytes.Clone(good), 0, 0, 0, 0),
		"wireguard":             wgInit,
		"attribute after print": appendRaw(bytes.Clone(good), 0x0006, []byte("late")),
	}
	for name, b := range cases {
		if _, err := Parse(b); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	if IsMessage(wgInit) {
		t.Error("a WireGuard packet looks like STUN")
	}
}

// appendRaw adds an attribute and fixes the header length (tests only).
func appendRaw(b []byte, typ uint16, v []byte) []byte {
	b = appendAttr(b, typ, v)
	setLen(b)
	return b
}

// RFC 5389 §7.3: a message whose FINGERPRINT is present but wrong is
// discarded, not taken as a message without one.
func TestBadFingerprintIsMalformed(t *testing.T) {
	b := BindingRequest(NewTxID(), "", nil)
	b[len(b)-1] ^= 0xFF
	if _, err := Parse(b); err == nil {
		t.Fatal("a message with a wrong fingerprint parsed")
	}
}
