package main

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
)

func TestKeyPair(t *testing.T) {
	priv, pub, err := newKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if len(priv) != 44 || len(pub) != 44 || priv == pub {
		t.Fatalf("priv %q pub %q", priv, pub)
	}
	b, _ := base64.StdEncoding.DecodeString(priv)
	if len(b) != 32 || b[0]&7 != 0 || b[31]&128 != 0 || b[31]&64 == 0 {
		t.Fatalf("private key is not clamped: %x", b)
	}
	p2, _, _ := newKeyPair()
	if p2 == priv {
		t.Fatal("two calls gave the same key")
	}
	h, err := hexKey(pub)
	if err != nil || len(h) != 64 {
		t.Fatalf("hex %q %v", h, err)
	}
	if raw, _ := hex.DecodeString(h); base64.StdEncoding.EncodeToString(raw) != pub {
		t.Fatal("hexKey does not round-trip")
	}
	for _, bad := range []string{"", "short", pub[:43], pub + "A"} {
		if _, err := hexKey(bad); err == nil {
			t.Errorf("hexKey(%q) accepted", bad)
		}
	}
}

func TestCheckNASKey(t *testing.T) {
	stored := base64.StdEncoding.EncodeToString(make([]byte, 32))
	other := make([]byte, 32)
	other[0] = 1
	if err := checkNASKey(stored, stored); err != nil {
		t.Fatalf("same key: %v", err)
	}
	for name, got := range map[string]string{
		"another NAS": base64.StdEncoding.EncodeToString(other),
		"missing":     "",
		"not a key":   "pk",
	} {
		if err := checkNASKey(stored, got); !errors.Is(err, ErrNASKeyChanged) {
			t.Errorf("%s: %v, want ErrNASKeyChanged", name, err)
		}
	}
}
