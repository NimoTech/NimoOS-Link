package protocol

import (
	"crypto/rand"
	"regexp"
	"strings"
)

var deviceIDRe = regexp.MustCompile(`^[a-z2-7]{10}$`)

const idAlphabet = "abcdefghijklmnopqrstuvwxyz234567"

// ValidDeviceID reports whether s is a well-formed device ID (10 base32 chars, lowercase).
func ValidDeviceID(s string) bool { return deviceIDRe.MatchString(s) }

// NewDeviceID returns a random device ID (50 bits).
func NewDeviceID() (string, error) {
	var b [10]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	out := make([]byte, len(b))
	for i, v := range b {
		out[i] = idAlphabet[v&31] // 256 is a multiple of 32: uniform
	}
	return string(out), nil
}

// HostFor is the public host name of a device.
func HostFor(id, domain string) string { return id + "." + domain }

// ControlHost is the host name of the relay's own control API.
func ControlHost(domain string) string { return "link." + domain }

// DeviceIDFromHost extracts the device ID from a host name under domain.
// It accepts exactly one label in front of domain, any letter case and a
// trailing dot; everything else is rejected.
func DeviceIDFromHost(host, domain string) (string, bool) {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	suffix := "." + strings.ToLower(domain)
	if !strings.HasSuffix(h, suffix) {
		return "", false
	}
	id := strings.TrimSuffix(h, suffix)
	if !ValidDeviceID(id) {
		return "", false
	}
	return id, true
}
