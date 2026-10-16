package direct

import (
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/NimoTech/NimoOS-Link/protocol/stun"
)

// fakeInner is a Bind whose one receive function hands out what the test queued.
type fakeInner struct {
	conn.Bind
	queue [][]byte
	from  string
	sent  [][]byte
	to    []string
}

type fakeEP struct{ dst string }

func (e fakeEP) ClearSrc()           {}
func (e fakeEP) SrcToString() string { return "" }
func (e fakeEP) DstToString() string { return e.dst }
func (e fakeEP) DstToBytes() []byte  { return []byte(e.dst) }
func (e fakeEP) DstIP() netip.Addr   { return netip.MustParseAddrPort(e.dst).Addr() }
func (e fakeEP) SrcIP() netip.Addr   { return netip.Addr{} }

func (f *fakeInner) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	return []conn.ReceiveFunc{func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n := 0
		for n < len(f.queue) && n < len(packets) {
			sizes[n] = copy(packets[n], f.queue[n])
			eps[n] = fakeEP{f.from}
			n++
		}
		f.queue = f.queue[n:]
		return n, nil
	}}, 51820, nil
}
func (f *fakeInner) ParseEndpoint(s string) (conn.Endpoint, error) { return fakeEP{s}, nil }
func (f *fakeInner) Send(bufs [][]byte, ep conn.Endpoint) error {
	for _, b := range bufs {
		f.sent = append(f.sent, append([]byte(nil), b...))
		f.to = append(f.to, ep.DstToString())
	}
	return nil
}
func (f *fakeInner) BatchSize() int { return 4 }

func TestBindDivertsSTUNAndLeavesWireGuardAlone(t *testing.T) {
	wg := make([]byte, 148)
	wg[0] = 1
	st := stun.BindingRequest(stun.NewTxID(), "", nil)
	in := &fakeInner{queue: [][]byte{wg, st, wg}, from: "203.0.113.9:51900"}
	b := NewBind(in)
	var got [][]byte
	var gotFrom netip.AddrPort
	b.OnSTUN(func(p []byte, from netip.AddrPort) { got = append(got, p); gotFrom = from })
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	packets := make([][]byte, 4)
	bufs := make([][1500]byte, 4)
	for i := range packets {
		packets[i] = bufs[i][:]
	}
	sizes := make([]int, 4)
	eps := make([]conn.Endpoint, 4)
	n, err := fns[0](packets, sizes, eps)
	if err != nil || n != 3 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if sizes[0] != 148 || sizes[1] != 0 || sizes[2] != 148 {
		t.Fatalf("sizes %v: STUN must be blanked, WireGuard untouched", sizes[:3])
	}
	if &packets[2][0] != &bufs[2][0] {
		t.Fatal("buffers were moved: wireguard-go reuses them by index")
	}
	if len(got) != 1 || gotFrom != netip.MustParseAddrPort("203.0.113.9:51900") {
		t.Fatalf("STUN handler got %d from %s", len(got), gotFrom)
	}
	if err := b.SendTo(st, netip.MustParseAddrPort("52.15.161.48:3478")); err != nil || in.to[0] != "52.15.161.48:3478" {
		t.Fatalf("SendTo: %v %v", err, in.to)
	}
}
