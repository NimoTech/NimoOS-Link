package protocol

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

func key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestSigningString(t *testing.T) {
	got := SigningString("POST", "/v1/devices/abcdefghij/cert", 1700000000, []byte("{}"))
	want := "nimolink-v1\nPOST\n/v1/devices/abcdefghij/cert\n1700000000\n44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestSignVerify(t *testing.T) {
	pub, priv := key(t)
	now := time.Unix(1700000000, 0)
	body := []byte(`{"csr":"x"}`)
	h := SignRequest(priv, "abcdefghij", "POST", "/v1/x", now.Unix(), body)
	if !strings.HasPrefix(h, "NimoLink id=abcdefghij,ts=1700000000,sig=") {
		t.Fatalf("header = %q", h)
	}
	cred, err := ParseAuthorization(h)
	if err != nil {
		t.Fatal(err)
	}
	if err := cred.Verify(pub, "POST", "/v1/x", body, now); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	if err := cred.Verify(pub, "POST", "/v1/x", body, now.Add(300*time.Second)); err != nil {
		t.Errorf("+300s rejected: %v", err)
	}
	for name, f := range map[string]func() error{
		"method":  func() error { return cred.Verify(pub, "GET", "/v1/x", body, now) },
		"path":    func() error { return cred.Verify(pub, "POST", "/v1/y", body, now) },
		"body":    func() error { return cred.Verify(pub, "POST", "/v1/x", []byte("{}"), now) },
		"key":     func() error { other, _ := key(t); return cred.Verify(other, "POST", "/v1/x", body, now) },
		"bad key": func() error { return cred.Verify(pub[:10], "POST", "/v1/x", body, now) },
	} {
		if err := f(); !errors.Is(err, ErrBadSignature) {
			t.Errorf("tampered %s: err = %v", name, err)
		}
	}
	for _, d := range []time.Duration{301 * time.Second, -301 * time.Second} {
		if err := cred.Verify(pub, "POST", "/v1/x", body, now.Add(d)); !errors.Is(err, ErrClockSkew) {
			t.Errorf("skew %v: err = %v", d, err)
		}
	}
}

func TestParseAuthorizationRejects(t *testing.T) {
	_, priv := key(t)
	good := SignRequest(priv, "abcdefghij", "GET", "/", 1700000000, nil)
	sig := good[strings.Index(good, "sig=")+4:]
	cases := []string{
		"",
		"Bearer abc",
		"NimoLink",
		"NimoLink id=abcdefghij,ts=1700000000",
		"NimoLink id=abcdefghij,sig=" + sig,
		"NimoLink ts=1700000000,sig=" + sig,
		"NimoLink id=ABCDEFGHIJ,ts=1700000000,sig=" + sig,
		"NimoLink id=abcdefghij,ts=soon,sig=" + sig,
		"NimoLink id=abcdefghij,ts=1700000000,sig=!!!",
		"NimoLink id=abcdefghij,ts=1700000000,sig=" + sig[:20],
		"NimoLink id=abcdefghij,id=abcdefghij,ts=1700000000,sig=" + sig,
		"NimoLink id=abcdefghij,ts=1700000000,sig=" + sig + ",x=1",
	}
	for _, h := range cases {
		if _, err := ParseAuthorization(h); !errors.Is(err, ErrBadAuthorization) {
			t.Errorf("ParseAuthorization(%q) err = %v", h, err)
		}
	}
	if _, err := ParseAuthorization(strings.ReplaceAll(good, ",", ", ")); err != nil {
		t.Errorf("spaces after commas should be accepted: %v", err)
	}
}

func TestPublicKeyEncoding(t *testing.T) {
	pub, _ := key(t)
	got, err := DecodePublicKey(EncodePublicKey(pub))
	if err != nil || !got.Equal(pub) {
		t.Fatalf("round trip: %v", err)
	}
	for _, s := range []string{"", "!!", EncodePublicKey(pub[:31])} {
		if _, err := DecodePublicKey(s); !errors.Is(err, ErrBadPublicKey) {
			t.Errorf("DecodePublicKey(%q) err = %v", s, err)
		}
	}
}

func TestSkewOverflow(t *testing.T) {
	pub, priv := key(t)
	now := time.Unix(1700000000, 0)
	for _, ts := range []int64{1 << 40, math.MaxInt64, math.MinInt64} {
		h := SignRequest(priv, "abcdefghij", "POST", "/v1/x", ts, nil)
		cred, err := ParseAuthorization(h)
		if err != nil {
			t.Fatalf("ts=%d: parse: %v", ts, err)
		}
		if err := cred.Verify(pub, "POST", "/v1/x", nil, now); !errors.Is(err, ErrClockSkew) {
			t.Errorf("ts=%d: err = %v, want ErrClockSkew", ts, err)
		}
	}
}

// otherEncoding returns a different string that decodes to the same bytes as
// s (only possible through unused trailing bits of the final base64 quantum).
func otherEncoding(t *testing.T, s string, pos int) string {
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	want, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(alpha); i++ {
		if alpha[i] == s[pos] {
			continue
		}
		cand := s[:pos] + string(alpha[i]) + s[pos+1:]
		if got, err := base64.StdEncoding.DecodeString(cand); err == nil && bytes.Equal(got, want) {
			return cand
		}
	}
	t.Fatal("no alternate encoding found")
	return ""
}

func TestCanonicalBase64(t *testing.T) {
	pub, priv := key(t)
	good := SignRequest(priv, "abcdefghij", "GET", "/", 1700000000, nil)
	sig := good[strings.Index(good, "sig=")+4:]
	// Signature is 64 bytes: the last quantum is "XX==", so the char before
	// "==" carries 4 unused low bits.
	alt := otherEncoding(t, sig, len(sig)-3)
	if alt == sig {
		t.Fatal("alternate encoding equals original")
	}
	nl := sig[:40] + "\n" + sig[40:]
	for name, s := range map[string]string{"unused bits": alt, "newline": nl} {
		h := strings.Replace(good, "sig="+sig, "sig="+s, 1)
		if _, err := ParseAuthorization(h); !errors.Is(err, ErrBadAuthorization) {
			t.Errorf("sig %s: err = %v", name, err)
		}
	}

	// Public key is 32 bytes: the last quantum is "XXX=", 2 unused bits.
	k := EncodePublicKey(pub)
	altK := otherEncoding(t, k, len(k)-2)
	for name, s := range map[string]string{"unused bits": altK, "newline": k[:20] + "\n" + k[20:]} {
		if _, err := DecodePublicKey(s); !errors.Is(err, ErrBadPublicKey) {
			t.Errorf("pubkey %s: err = %v", name, err)
		}
	}
}
