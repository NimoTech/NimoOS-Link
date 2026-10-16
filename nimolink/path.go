package main

import (
	"net"
	"time"
)

// Path is where WireGuard packets go and how that was found.
type Path struct {
	Type     string // lan, ipv6, stun, or endpoint (pairing's, or -endpoint)
	Endpoint string
}

var rank = map[string]int{"lan": 0, "endpoint": 0, "ipv6": 1, "stun": 2}

// shouldSwitch: take found when there is no path yet, when the current one
// stopped answering, or when found is better (home beats the internet).
// The same address under another name is no change.
func shouldSwitch(cur Path, curAlive bool, found Path) bool {
	if found.Endpoint == "" || found.Endpoint == cur.Endpoint {
		return false
	}
	if cur.Endpoint == "" || !curAlive {
		return true
	}
	return rank[found.Type] < rank[cur.Type]
}

// attemptDue: look for a path when the address set changed, once when the
// current path just died, and otherwise only when the backoff allows.
func attemptDue(now, next time.Time, died, addrsChanged bool) bool {
	return addrsChanged || died || !now.Before(next)
}

// aliveForSwitch: is the current path still good, for shouldSwitch? Right
// after a network change only an answer in this round counts — a handshake
// from before the move says nothing.
func aliveForSwitch(fresh, addrsChanged, answered bool) bool {
	if addrsChanged {
		return answered
	}
	return fresh
}

// pathStaleAfter: how long without a handshake before the current path counts
// as dead. WireGuard shakes hands again 120 s after the last handshake once a
// packet is sent; keepalive sends one every keepalive seconds (25 by default);
// 15 s of slack.
func pathStaleAfter(keepalive int) time.Duration {
	if keepalive <= 0 {
		keepalive = 25
	}
	return time.Duration(120+keepalive+15) * time.Second
}

// initialEndpoint picks where WireGuard starts sending. One the user gave is
// used as it is (forced: no connect). Otherwise pairing's endpoint — unless
// the NAS has a remote address and that endpoint does not resolve here (a
// home-only name away from home): then none, and connect finds the way.
func initialEndpoint(c Config, override string, resolves func(string) bool) (ep string, forced bool, err error) {
	if override != "" {
		return override, true, nil
	}
	ep, err = chooseEndpoint(c, "")
	if c.RemoteURL == "" {
		return ep, false, err
	}
	if err != nil || !resolves(ep) {
		return "", false, nil
	}
	return ep, false, nil
}

func udpResolves(hostport string) bool {
	_, err := net.ResolveUDPAddr("udp", hostport)
	return err == nil
}
