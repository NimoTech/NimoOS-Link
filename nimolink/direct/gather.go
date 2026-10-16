package direct

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const maxLocal = 6

// LocalCandidates: this machine's usable addresses with port — IPv4 and
// global / unique-local IPv6, never loopback, link-local, multicast or inside
// skip (the tunnel's own network). IPv4 first; at most six.
func LocalCandidates(addrs []netip.Prefix, port uint16, skip netip.Prefix) []Candidate {
	var v4, v6 []Candidate
	seen := map[netip.Addr]bool{}
	for _, p := range addrs {
		a := p.Addr().Unmap()
		if !a.IsValid() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() ||
			(skip.IsValid() && skip.Contains(a)) || seen[a] {
			continue
		}
		seen[a] = true
		addr := net.JoinHostPort(a.String(), strconv.Itoa(int(port)))
		if a.Is4() {
			v4 = append(v4, Candidate{"lan", addr})
		} else {
			v6 = append(v6, Candidate{"ipv6", addr})
		}
	}
	out := append(v4, v6...)
	if len(out) > maxLocal {
		out = out[:maxLocal]
	}
	return out
}

// usableInterface: up, not loopback or a tunnel, and not a bridge that
// containers or VMs live behind (their addresses, 172.17.0.1 and the like,
// are the same on every machine and are not where the NAS can reach us).
func usableInterface(name string, flags net.Flags) bool {
	if flags&net.FlagUp == 0 || flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 {
		return false
	}
	for _, p := range []string{"docker", "br-", "veth", "virbr", "cni", "flannel"} {
		if strings.HasPrefix(name, p) {
			return false
		}
	}
	return true
}

// SystemCandidates: LocalCandidates over this machine's usable interfaces.
func SystemCandidates(port uint16, skip netip.Prefix) []Candidate {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var ps []netip.Prefix
	for _, i := range ifs {
		if !usableInterface(i.Name, i.Flags) {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, x := range addrs {
			if p, err := netip.ParsePrefix(x.String()); err == nil {
				ps = append(ps, p)
			}
		}
	}
	return LocalCandidates(ps, port, skip)
}
