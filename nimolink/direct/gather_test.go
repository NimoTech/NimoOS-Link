package direct

import (
	"net"
	"net/netip"
	"testing"
)

func TestLocalCandidates(t *testing.T) {
	var addrs []netip.Prefix
	for _, s := range []string{"192.168.43.5/24", "127.0.0.1/8", "::1/128", "fe80::1/64",
		"2001:db8:9::5/64", "100.91.200.2/24", "172.31.5.5/20"} {
		addrs = append(addrs, netip.MustParsePrefix(s))
	}
	got := LocalCandidates(addrs, 40000, netip.MustParsePrefix("100.91.200.0/24"))
	want := []Candidate{{"lan", "192.168.43.5:40000"}, {"lan", "172.31.5.5:40000"}, {"ipv6", "[2001:db8:9::5]:40000"}}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: %v want %v", i, got[i], want[i])
		}
	}
	many := make([]netip.Prefix, 10)
	for i := range many {
		many[i] = netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)}), 8)
	}
	if n := len(LocalCandidates(many, 1, netip.Prefix{})); n != 6 {
		t.Fatalf("%d candidates, want at most 6", n)
	}
}

// Bridges that containers and VMs live behind are not where the NAS can reach
// this machine, and their addresses (172.17.0.1 ...) are the same everywhere.
func TestUsableInterface(t *testing.T) {
	up := net.FlagUp | net.FlagBroadcast
	for name, c := range map[string]struct {
		flags net.Flags
		want  bool
	}{
		"wlan0": {up, true}, "enp3s0": {up, true},
		"docker0": {up, false}, "br-1a2b3c": {up, false}, "veth12ab": {up, false},
		"virbr0": {up, false}, "cni0": {up, false}, "flannel.1": {up, false},
		"eth1": {net.FlagBroadcast, false}, // down
		"lo":   {net.FlagUp | net.FlagLoopback, false},
		"tun0": {net.FlagUp | net.FlagPointToPoint, false},
	} {
		if got := usableInterface(name, c.flags); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}
