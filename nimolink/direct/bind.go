// Package direct is the client side of NimoLink's direct connection: a
// WireGuard Bind that shares its UDP port with STUN, and the agent that
// learns the reflexive address and checks which of the NAS's addresses
// answers. Usable from any wireguard-go host (the iOS bridge included).
package direct

import (
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/NimoTech/NimoOS-Link/protocol/stun"
)

// Bind wraps a WireGuard Bind: received STUN messages go to the STUN handler
// (their size is set to 0, which wireguard-go skips), everything else to
// WireGuard; SendTo writes from the same socket, so the NAT maps both alike.
type Bind struct {
	conn.Bind

	mu     sync.RWMutex
	onSTUN func(pkt []byte, from netip.AddrPort)
	send   func(pkt []byte, to netip.AddrPort) error // tests replace it
}

func NewBind(inner conn.Bind) *Bind {
	b := &Bind{Bind: inner}
	b.send = func(pkt []byte, to netip.AddrPort) error {
		ep, err := b.Bind.ParseEndpoint(to.String())
		if err != nil {
			return err
		}
		return b.Bind.Send([][]byte{pkt}, ep)
	}
	return b
}

func (b *Bind) OnSTUN(f func(pkt []byte, from netip.AddrPort)) {
	b.mu.Lock()
	b.onSTUN = f
	b.mu.Unlock()
}

func (b *Bind) SendTo(pkt []byte, to netip.AddrPort) error { return b.send(pkt, to) }

func (b *Bind) dispatch(pkt []byte, from netip.AddrPort) {
	b.mu.RLock()
	f := b.onSTUN
	b.mu.RUnlock()
	if f != nil {
		f(pkt, from)
	}
}

func (b *Bind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	out := make([]conn.ReceiveFunc, len(fns))
	for i, fn := range fns {
		fn := fn
		out[i] = func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			n, err := fn(packets, sizes, eps)
			for j := 0; j < n; j++ {
				p := packets[j][:sizes[j]]
				if sizes[j] == 0 || !stun.IsMessage(p) {
					continue
				}
				if from, perr := netip.ParseAddrPort(eps[j].DstToString()); perr == nil {
					b.dispatch(append([]byte(nil), p...), netip.AddrPortFrom(from.Addr().Unmap(), from.Port()))
				}
				sizes[j] = 0 // not for WireGuard; the buffer stays where it is
			}
			return n, err
		}
	}
	return out, actual, nil
}
