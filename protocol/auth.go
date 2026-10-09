package protocol

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

var (
	ErrBadAuthorization = errors.New("protocol: malformed Authorization header")
	ErrClockSkew        = errors.New("protocol: request timestamp outside the allowed clock skew")
	ErrBadSignature     = errors.New("protocol: bad request signature")
	ErrBadPublicKey     = errors.New("protocol: bad public key")
)

// SigningString is the exact byte string a device signs for one request.
func SigningString(method, path string, ts int64, body []byte) string {
	sum := sha256.Sum256(body)
	return signPrefix + method + "\n" + path + "\n" + strconv.FormatInt(ts, 10) + "\n" + hex.EncodeToString(sum[:])
}

// SignRequest returns the Authorization header value for one request.
func SignRequest(priv ed25519.PrivateKey, id, method, path string, ts int64, body []byte) string {
	sig := ed25519.Sign(priv, []byte(SigningString(method, path, ts, body)))
	return fmt.Sprintf("%s id=%s,ts=%d,sig=%s", AuthScheme, id, ts, base64.StdEncoding.EncodeToString(sig))
}

// Credential is a parsed Authorization header.
type Credential struct {
	ID     string
	TS     int64
	Sig    []byte
	SigB64 string
}

// ParseAuthorization parses "NimoLink id=<id>,ts=<unix>,sig=<base64>".
func ParseAuthorization(h string) (Credential, error) {
	rest, ok := strings.CutPrefix(h, AuthScheme+" ")
	if !ok {
		return Credential{}, ErrBadAuthorization
	}
	fields := map[string]string{}
	for _, part := range strings.Split(rest, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return Credential{}, ErrBadAuthorization
		}
		if _, dup := fields[k]; dup {
			return Credential{}, ErrBadAuthorization
		}
		fields[k] = v
	}
	if len(fields) != 3 {
		return Credential{}, ErrBadAuthorization
	}
	id, tsStr, sigStr := fields["id"], fields["ts"], fields["sig"]
	if !ValidDeviceID(id) {
		return Credential{}, ErrBadAuthorization
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return Credential{}, ErrBadAuthorization
	}
	sig, err := base64.StdEncoding.DecodeString(sigStr)
	if err != nil || len(sig) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(sig) != sigStr {
		// Canonical encoding only: one signature must map to one sig= string,
		// or the replay cache keyed on SigB64 can be bypassed.
		return Credential{}, ErrBadAuthorization
	}
	return Credential{ID: id, TS: ts, Sig: sig, SigB64: sigStr}, nil
}

// Verify checks the timestamp against now, then the signature.
func (c Credential) Verify(pub ed25519.PublicKey, method, path string, body []byte, now time.Time) error {
	// Compare in whole seconds: time.Duration arithmetic saturates for
	// far-future timestamps and would wrongly pass the check.
	skew := int64(MaxClockSkew / time.Second)
	n := now.Unix()
	if c.TS > n+skew || c.TS < n-skew {
		return ErrClockSkew
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, []byte(SigningString(method, path, c.TS, body)), c.Sig) {
		return ErrBadSignature
	}
	return nil
}

func EncodePublicKey(pub ed25519.PublicKey) string { return base64.StdEncoding.EncodeToString(pub) }

func DecodePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(b) != s {
		return nil, ErrBadPublicKey
	}
	return ed25519.PublicKey(b), nil
}
