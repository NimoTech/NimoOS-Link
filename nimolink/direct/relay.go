package direct

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/NimoTech/NimoOS-Link/protocol"
)

// RelayEndpoint is where WireGuard sends to reach the NAS through the relay
// fallback. It is a made-up address: packets for it never reach the network,
// the Bind writes them into the fallback connection instead, and packets from
// that connection reach WireGuard as if they came from it.
var RelayEndpoint = netip.MustParseAddrPort("127.77.0.1:9")

// relayQueue: packets from the fallback connection waiting for WireGuard.
const relayQueue = 256

// SetRelay hands the Bind the fallback connection to use (nil: none). With
// none, packets to RelayEndpoint are dropped and so are packets delivered
// from a connection, those already queued included: a connection kept open
// after leaving the relay must not make WireGuard roam back to it. Call it
// with nil before pointing WireGuard elsewhere.
func (b *Bind) SetRelay(w io.Writer) {
	b.mu.Lock()
	b.relay = w
	in := b.relayIn
	b.mu.Unlock()
	if w != nil || in == nil {
		return
	}
	for {
		select {
		case <-in:
		default:
			return
		}
	}
}

// DeliverRelay passes a packet read from the fallback connection to
// WireGuard. It never blocks: when WireGuard is behind, the packet is dropped.
func (b *Bind) DeliverRelay(pkt []byte) {
	p := append([]byte(nil), pkt...)
	// Held while queueing (which never blocks): once SetRelay(nil) has
	// returned, nothing more gets in.
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.relay == nil || b.relayIn == nil {
		return
	}
	select {
	case b.relayIn <- p:
	default:
	}
}

func isRelay(ep conn.Endpoint) bool {
	return ep != nil && ep.DstToString() == RelayEndpoint.String()
}

// sendRelay writes bufs as frames, in one Write.
func (b *Bind) sendRelay(bufs [][]byte) error {
	b.mu.RLock()
	w := b.relay
	b.mu.RUnlock()
	if w == nil {
		return nil // no fallback connection: dropped, like a lost datagram
	}
	n := 0
	for _, p := range bufs {
		n += 2 + len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range bufs {
		if len(p) == 0 || len(p) > protocol.MaxFrame {
			continue
		}
		out = binary.BigEndian.AppendUint16(out, uint16(len(p)))
		out = append(out, p...)
	}
	if len(out) == 0 {
		return nil
	}
	_, err := w.Write(out)
	return err
}

// relayReceive is the extra receive function Open returns: it hands out what
// DeliverRelay queued, as coming from RelayEndpoint, until done is closed.
func relayReceive(in <-chan []byte, done <-chan struct{}, ep conn.Endpoint) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		var p []byte
		select {
		case p = <-in:
		case <-done:
			return 0, net.ErrClosed
		}
		n := 0
		for {
			sizes[n] = copy(packets[n], p)
			eps[n] = ep
			n++
			if n == len(packets) {
				return n, nil
			}
			select {
			case p = <-in:
			default:
				return n, nil
			}
		}
	}
}
