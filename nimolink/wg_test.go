package main

import (
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	priv, _, err := newKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, nasPub, _ := newKeyPair()
	return Config{NAS: "http://192.168.1.118", PrivateKey: priv, NASPublicKey: nasPub, NASAddress: "100.64.7.1",
		ClientAddress: "100.64.7.5", Subnet: "100.64.7.0/24", Port: 51900, Endpoints: []string{"10.0.0.5:51900"}, Keepalive: 25, MTU: 1280}
}

func TestUAPIConfig(t *testing.T) {
	c := testConfig(t)
	got, err := uapiConfig(c, "192.168.1.118:51900", nil)
	if err != nil {
		t.Fatal(err)
	}
	privHex, _ := hexKey(c.PrivateKey)
	pubHex, _ := hexKey(c.NASPublicKey)
	want := "private_key=" + privHex + "\nreplace_peers=true\npublic_key=" + pubHex +
		"\nendpoint=192.168.1.118:51900\npersistent_keepalive_interval=25\nreplace_allowed_ips=true\nallowed_ip=100.64.7.0/24\n"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	// extra networks (testing only) come after the NAS's own
	got, _ = uapiConfig(c, "192.168.1.118:51900", []string{"192.168.1.0/24"})
	if !strings.HasSuffix(got, "allowed_ip=100.64.7.0/24\nallowed_ip=192.168.1.0/24\n") {
		t.Fatalf("extra allowed: %s", got)
	}
	for name, mut := range map[string]func(*Config){
		"no private key": func(c *Config) { c.PrivateKey = "" },
		"bad NAS key":    func(c *Config) { c.NASPublicKey = "nope" },
		"bad subnet":     func(c *Config) { c.Subnet = "100.64.7.0" },
	} {
		bad := testConfig(t)
		mut(&bad)
		if _, err := uapiConfig(bad, "192.168.1.118:51900", nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := uapiConfig(c, "not-an-endpoint", nil); err == nil {
		t.Error("an endpoint without a port was accepted")
	}
	if _, err := uapiConfig(c, "192.168.1.118:51900", []string{"nonsense"}); err == nil {
		t.Error("a bad extra network was accepted")
	}
}

func TestChooseEndpoint(t *testing.T) {
	c := testConfig(t)
	// by default: the address the client paired with, on the tunnel's port
	if got, err := chooseEndpoint(c, ""); err != nil || got != "192.168.1.118:51900" {
		t.Fatalf("default: %q %v", got, err)
	}
	if got, _ := chooseEndpoint(c, "203.0.113.9:40000"); got != "203.0.113.9:40000" {
		t.Fatalf("override: %q", got)
	}
	c.NAS = "http://[fd00::5]:8080"
	if got, _ := chooseEndpoint(c, ""); got != "[fd00::5]:51900" {
		t.Fatalf("ipv6: %q", got)
	}
	c.NAS = ""
	if got, _ := chooseEndpoint(c, ""); got != "10.0.0.5:51900" {
		t.Fatalf("no NAS address: fall back to what pairing listed, got %q", got)
	}
	c.Endpoints = nil
	if _, err := chooseEndpoint(c, ""); err == nil {
		t.Fatal("no endpoint at all, yet no error")
	}
}

func TestParseStatus(t *testing.T) {
	st := parseStatus("private_key=00\nlisten_port=4242\npublic_key=ab\nendpoint=192.168.1.118:51900\nlast_handshake_time_sec=1760000000\nlast_handshake_time_nsec=5\nrx_bytes=1234\ntx_bytes=99\nerrno=0\n\n")
	if st.Endpoint != "192.168.1.118:51900" || st.Rx != 1234 || st.Tx != 99 || !st.LastHandshake.Equal(time.Unix(1760000000, 0)) {
		t.Fatalf("%+v", st)
	}
	// never shaken hands: the zero time, which the status line reports as "no handshake yet"
	st = parseStatus("public_key=ab\nendpoint=192.168.1.118:51900\nlast_handshake_time_sec=0\nrx_bytes=0\ntx_bytes=148\n\n")
	if !st.LastHandshake.IsZero() || st.Tx != 148 {
		t.Fatalf("%+v", st)
	}
	if got := statusLine(st, time.Unix(1760000100, 0)); !strings.Contains(got, "no handshake yet") {
		t.Fatalf("status line %q", got)
	}
	st.LastHandshake = time.Unix(1760000000, 0)
	if got := statusLine(st, time.Unix(1760000042, 0)); !strings.Contains(got, "direct") || !strings.Contains(got, "42s ago") || !strings.Contains(got, "192.168.1.118:51900") {
		t.Fatalf("status line %q", got)
	}
	relayed := st
	relayed.Endpoint = "127.77.0.1:9"
	if got := statusLine(relayed, time.Unix(1760000042, 0)); !strings.HasPrefix(got, "over the relay") || strings.Contains(got, "127.77") {
		t.Fatalf("status line on the relay %q", got)
	}
	// a handshake older than three minutes is a dead tunnel, and is called that
	if got := statusLine(st, time.Unix(1760000000+600, 0)); !strings.Contains(got, "stale") {
		t.Fatalf("stale: %q", got)
	}
	if st := parseStatus(""); st.Endpoint != "" || !st.LastHandshake.IsZero() {
		t.Fatalf("empty: %+v", st)
	}
}

func TestClassifyControlErr(t *testing.T) {
	if got := classifyControlErr(&net.OpError{Op: "dial", Err: &os.SyscallError{Syscall: "connect", Err: syscall.ENOENT}}); got != errTunnelDown {
		t.Errorf("not-exist: %v", got)
	}
	if got := classifyControlErr(&net.OpError{Op: "dial", Err: &os.SyscallError{Syscall: "connect", Err: syscall.EACCES}}); got != errNeedRoot {
		t.Errorf("permission: %v", got)
	}
	if got := classifyControlErr(&net.OpError{Op: "dial", Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}}); got != errTunnelDown {
		t.Errorf("refused: %v", got)
	}
	if got := classifyControlErr(syscall.ESRCH); got != errTunnelDown {
		t.Errorf("no such process: %v", got)
	}
	other := errors.New("boom")
	if got := classifyControlErr(other); got != other {
		t.Errorf("other: %v", got)
	}
}

func TestValidatePairing(t *testing.T) {
	if err := validatePairing(testConfig(t)); err != nil {
		t.Fatalf("a good answer was refused: %v", err)
	}
	for name, mut := range map[string]func(*Config){
		"default route": func(c *Config) { c.Subnet = "0.0.0.0/0" },
		"private 10/8":  func(c *Config) { c.Subnet = "10.0.0.0/8" },
		"a /16":         func(c *Config) { c.Subnet = "100.64.0.0/16" },
		"outside CGNAT": func(c *Config) {
			c.Subnet = "100.128.7.0/24"
			c.NASAddress = "100.128.7.1"
			c.ClientAddress = "100.128.7.5"
		},
		"host bits in net":   func(c *Config) { c.Subnet = "100.64.7.5/24" },
		"not a network":      func(c *Config) { c.Subnet = "nope" },
		"NAS not .1":         func(c *Config) { c.NASAddress = "100.64.7.2" },
		"NAS elsewhere":      func(c *Config) { c.NASAddress = "100.64.8.1" },
		"client is host 1":   func(c *Config) { c.ClientAddress = "100.64.7.1" },
		"client is host 0":   func(c *Config) { c.ClientAddress = "100.64.7.0" },
		"client is host 255": func(c *Config) { c.ClientAddress = "100.64.7.255" },
		"client elsewhere":   func(c *Config) { c.ClientAddress = "100.64.8.5" },
		"client not an IP":   func(c *Config) { c.ClientAddress = "x" },
		"port 0":             func(c *Config) { c.Port = 0 },
		"port too big":       func(c *Config) { c.Port = 70000 },
		"mtu tiny":           func(c *Config) { c.MTU = 100 },
		"mtu huge":           func(c *Config) { c.MTU = 70000 },
		"keepalive huge":     func(c *Config) { c.Keepalive = 100000 },
		"keepalive negative": func(c *Config) { c.Keepalive = -1 },
	} {
		c := testConfig(t)
		mut(&c)
		if err := validatePairing(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// the edges that are fine
	c := testConfig(t)
	c.ClientAddress = "100.64.7.2"
	if err := validatePairing(c); err != nil {
		t.Errorf("host 2: %v", err)
	}
	c.ClientAddress = "100.64.7.254"
	if err := validatePairing(c); err != nil {
		t.Errorf("host 254: %v", err)
	}
}

func TestDecideDown(t *testing.T) {
	const own = "/usr/local/bin/nimolink"
	enoent := &os.PathError{Op: "readlink", Path: "/proc/4242/exe", Err: syscall.ENOENT}
	cases := []struct {
		name    string
		pidText string
		exe     string
		exeErr  error
		pid     int
		want    downOutcome
	}{
		{"this program", "4242\n", own, nil, 4242, downSignal},
		{"other program", "4242", "/usr/bin/sshd", nil, 4242, downForeign},
		{"program deleted", "4242", own + " (deleted)", nil, 4242, downForeign},
		{"no such process", "4242", "", enoent, 0, downStale},
		{"unreadable exe, not ENOENT", "4242", "", syscall.EIO, 4242, downForeign},
		{"garbage", "abc", own, nil, 0, downStale},
		{"empty", "", own, nil, 0, downStale},
		{"pid 1", "1", own, nil, 0, downStale},
		{"negative", "-5", own, nil, 0, downStale},
	}
	for _, tc := range cases {
		pid, got := decideDown(tc.pidText, tc.exe, tc.exeErr, own)
		if got != tc.want || pid != tc.pid {
			t.Errorf("%s: got (%d, %v), want (%d, %v)", tc.name, pid, got, tc.pid, tc.want)
		}
	}
}
