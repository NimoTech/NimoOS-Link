package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/curve25519"
)

// newKeyPair makes a WireGuard key pair, both in standard base64.
func newKeyPair() (priv, pub string, err error) {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		return "", "", err
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	p, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(k[:]), base64.StdEncoding.EncodeToString(p), nil
}

// hexKey turns a base64 key into the hex form wireguard-go's configuration takes.
func hexKey(b64 string) (string, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(b64)
	if err != nil || len(b) != 32 {
		return "", errors.New("not a WireGuard key")
	}
	return hex.EncodeToString(b), nil
}

var ErrNASKeyChanged = errors.New("connect: the NAS answered with another key than the one paired (reinstalled NAS, or the remote address leads elsewhere): pair again at home")

// checkNASKey refuses a connect answer whose NAS key is not the stored one:
// its session and addresses would come from some other machine.
func checkNASKey(stored, got string) error {
	want, err := hexKey(stored)
	if err != nil {
		return ErrNASKeyChanged
	}
	if have, err := hexKey(got); err != nil || have != want {
		return ErrNASKeyChanged
	}
	return nil
}
