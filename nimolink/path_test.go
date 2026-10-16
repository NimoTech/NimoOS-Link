package main

import (
	"strings"
	"testing"
	"time"
)

// Switching costs a re-handshake; it happens only when it helps.
func TestPathSwitchRules(t *testing.T) {
	lan := Path{"lan", "192.168.1.118:51900"}
	ep := Path{"endpoint", "192.168.1.118:51900"}
	refl := Path{"stun", "203.0.113.7:51446"}
	refl2 := Path{"stun", "203.0.113.7:40000"}
	for _, c := range []struct {
		cur   Path
		alive bool
		found Path
		want  bool
	}{
		{Path{}, false, refl, true}, // nothing yet
		{ep, true, lan, false},      // same address, only the label differs
		{lan, true, refl, false},    // at home: never trade the LAN for the internet
		{refl, true, lan, true},     // came home
		{refl, true, refl2, false},  // the old mapping still works
		{refl, false, refl2, true},  // the old mapping died
		{lan, false, refl, true},    // left home
		{refl, true, refl, false},   // nothing new
	} {
		if got := shouldSwitch(c.cur, c.alive, c.found); got != c.want {
			t.Errorf("cur=%v alive=%v found=%v: %v, want %v", c.cur, c.alive, c.found, got, c.want)
		}
	}
}

func TestUAPIWithoutEndpoint(t *testing.T) {
	c := testConfig(t) // the helper wg_test.go uses for a valid paired Config
	conf, err := uapiConfig(c, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(conf, "endpoint=") {
		t.Fatalf("an endpoint was set: %s", conf)
	}
	if got := endpointConfig(c, "203.0.113.7:51446"); !strings.Contains(got, "endpoint=203.0.113.7:51446") || !strings.Contains(got, "public_key=") {
		t.Fatalf("%s", got)
	}
}

// A search starts when the address set changes, once when the current path
// dies, and otherwise only when the backoff says so — a dead path does not
// mean "ask every 5 seconds".
func TestAttemptDue(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	later := now.Add(time.Minute)
	for _, c := range []struct {
		next          time.Time
		died, changed bool
		want          bool
	}{
		{now, false, false, true},    // time for the periodic search
		{later, false, false, false}, // backing off
		{later, true, false, true},   // the path just died: once
		{later, false, true, true},   // moved to another network
	} {
		if got := attemptDue(now, c.next, c.died, c.changed); got != c.want {
			t.Errorf("%+v: %v, want %v", c, got, c.want)
		}
	}
}

// Right after the network changed, the old path counts as alive only if it
// answered a check in this round: a fresh handshake from before the move
// says nothing (leaving home must not wait 135 s).
func TestAliveForSwitch(t *testing.T) {
	for _, c := range []struct {
		fresh, changed, answered, want bool
	}{
		{true, false, false, true},
		{false, false, true, false},
		{true, true, false, false}, // left home: the LAN path no longer answers
		{true, true, true, true},   // a new Wi-Fi in the same house
	} {
		if got := aliveForSwitch(c.fresh, c.changed, c.answered); got != c.want {
			t.Errorf("%+v: %v", c, got)
		}
	}
	lan := Path{"lan", "192.168.1.118:51900"}
	refl := Path{"stun", "203.0.113.7:51446"}
	if !shouldSwitch(lan, aliveForSwitch(true, true, false), refl) {
		t.Fatal("left home: no switch to the internet path")
	}
}

// A path is alive while a handshake is due at most: WireGuard re-handshakes
// 120 s after the last one once a packet is sent, and keepalive sends one
// every Keepalive seconds.
func TestStaleAfter(t *testing.T) {
	for k, want := range map[int]time.Duration{0: 160 * time.Second, 25: 160 * time.Second, 300: 435 * time.Second} {
		if got := pathStaleAfter(k); got != want {
			t.Errorf("keepalive %d: %s, want %s", k, got, want)
		}
	}
}

// Paired by a name only the home network resolves (nas.local): away from
// home the automatic endpoint is dropped and connect finds the way; an
// endpoint the user gave is kept (and fails loudly if it does not resolve).
func TestInitialEndpoint(t *testing.T) {
	resolves := func(s string) bool { return !strings.HasPrefix(s, "nas.local") }
	remote := Config{NAS: "http://nas.local", Port: 51900, RemoteURL: "https://abc.relay-test.nimotech.ai"}
	if ep, forced, err := initialEndpoint(remote, "", resolves); err != nil || ep != "" || forced {
		t.Errorf("away from home: %q %v %v, want no endpoint", ep, forced, err)
	}
	if ep, _, err := initialEndpoint(Config{NAS: "http://192.168.1.118", Port: 51900, RemoteURL: remote.RemoteURL}, "", resolves); err != nil || ep != "192.168.1.118:51900" {
		t.Errorf("numeric pairing address: %q %v", ep, err)
	}
	if ep, forced, err := initialEndpoint(remote, "nas.local:51900", resolves); err != nil || ep != "nas.local:51900" || !forced {
		t.Errorf("given by the user: %q %v %v", ep, forced, err)
	}
	// no remote address: step 1 as it was (a name that does not resolve fails
	// later, in uapiConfig, with a plain message)
	if ep, forced, err := initialEndpoint(Config{NAS: "http://nas.local", Port: 51900}, "", resolves); err != nil || ep != "nas.local:51900" || forced {
		t.Errorf("no remote address: %q %v %v", ep, forced, err)
	}
}
