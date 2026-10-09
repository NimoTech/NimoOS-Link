package protocol

import "testing"

func TestValidDeviceID(t *testing.T) {
	cases := map[string]bool{
		"k7f3x2ab2m":  true,
		"abcdefghij":  true,
		"2345672345":  true,
		"K7F3X2AB2M":  false,
		"k7f3x9ab2":   false,
		"k7f3x2ab2mm": false,
		"k7f3x9ab1m":  false,
		"k7f3x9ab0m":  false,
		"k7f3x9ab-m":  false,
		"":            false,
	}
	for in, want := range cases {
		if got := ValidDeviceID(in); got != want {
			t.Errorf("ValidDeviceID(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestNewDeviceID(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id, err := NewDeviceID()
		if err != nil {
			t.Fatal(err)
		}
		if !ValidDeviceID(id) {
			t.Fatalf("NewDeviceID() = %q, not valid", id)
		}
		if seen[id] {
			t.Fatalf("duplicate id %q after %d draws", id, i)
		}
		seen[id] = true
	}
}

func TestDeviceIDFromHost(t *testing.T) {
	const domain = "relay-test.nimotech.ai"
	cases := []struct {
		host string
		id   string
		ok   bool
	}{
		{"k7f3x2ab2m.relay-test.nimotech.ai", "k7f3x2ab2m", true},
		{"K7F3X2AB2M.Relay-Test.Nimotech.AI", "k7f3x2ab2m", true},
		{"k7f3x2ab2m.relay-test.nimotech.ai.", "k7f3x2ab2m", true},
		{"link.relay-test.nimotech.ai", "", false},
		{"a.k7f3x2ab2m.relay-test.nimotech.ai", "", false},
		{"k7f3x2ab2m.evil-relay-test.nimotech.ai", "", false},
		{"k7f3x2ab2m.relay-test.nimotech.ai.evil.com", "", false},
		{"relay-test.nimotech.ai", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		id, ok := DeviceIDFromHost(c.host, domain)
		if id != c.id || ok != c.ok {
			t.Errorf("DeviceIDFromHost(%q) = %q, %v; want %q, %v", c.host, id, ok, c.id, c.ok)
		}
	}
	if got := HostFor("k7f3x2ab2m", domain); got != "k7f3x2ab2m.relay-test.nimotech.ai" {
		t.Errorf("HostFor = %q", got)
	}
	if got := ControlHost(domain); got != "link.relay-test.nimotech.ai" {
		t.Errorf("ControlHost = %q", got)
	}
}
