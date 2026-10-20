package direct

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/NimoTech/NimoOS-Link/protocol"
)

func (f *fakeInner) Close() error { return nil }

// frames records what the Bind writes into the fallback connection.
type frames struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (f *frames) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.buf.Write(p)
}

func (f *frames) read(t *testing.T) [][]byte {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	var out [][]byte
	for f.buf.Len() > 0 {
		p, err := protocol.ReadFrame(&f.buf, make([]byte, protocol.MaxFrame))
		if err != nil {
			t.Fatalf("not a frame: %v", err)
		}
		out = append(out, append([]byte(nil), p...))
	}
	return out
}

func relayEP(t *testing.T, b *Bind) conn.Endpoint {
	t.Helper()
	ep, err := b.ParseEndpoint(RelayEndpoint.String())
	if err != nil {
		t.Fatal(err)
	}
	return ep
}

func TestRelaySend(t *testing.T) {
	in := &fakeInner{}
	b := NewBind(in)
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	a, c := bytes.Repeat([]byte{1}, 148), bytes.Repeat([]byte{4}, 1420)
	if err := b.Send([][]byte{a}, relayEP(t, b)); err != nil {
		t.Fatalf("without a fallback connection: %v", err)
	}
	f := &frames{}
	b.SetRelay(f)
	if err := b.Send([][]byte{a, c}, relayEP(t, b)); err != nil {
		t.Fatal(err)
	}
	got := f.read(t)
	if len(got) != 2 || !bytes.Equal(got[0], a) || !bytes.Equal(got[1], c) {
		t.Fatalf("fallback connection got %d frames", len(got))
	}
}

func TestRelayNotOnWire(t *testing.T) {
	in := &fakeInner{}
	b := NewBind(in)
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	b.SetRelay(&frames{})
	_ = b.Send([][]byte{{1, 2, 3}}, relayEP(t, b))
	if len(in.sent) != 0 {
		t.Fatalf("a relay packet went out on the socket to %v", in.to)
	}
	ep, _ := b.ParseEndpoint("203.0.113.9:51900")
	_ = b.Send([][]byte{{1, 2, 3}}, ep)
	if len(in.sent) != 1 || in.to[0] != "203.0.113.9:51900" {
		t.Fatalf("a direct packet did not go out: %v", in.to)
	}
}

func TestRelayReceive(t *testing.T) {
	b := NewBind(&fakeInner{})
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(fns) != 2 {
		t.Fatalf("%d receive functions, want the socket's and the relay's", len(fns))
	}
	recv := fns[len(fns)-1]
	b.DeliverRelay([]byte{9}) // no connection set: dropped
	b.SetRelay(&frames{})
	pkt := bytes.Repeat([]byte{2}, 92)
	b.DeliverRelay(pkt)
	b.DeliverRelay(pkt)
	packets := [][]byte{make([]byte, 1500), make([]byte, 1500), make([]byte, 1500)}
	sizes := make([]int, 3)
	eps := make([]conn.Endpoint, 3)
	n, err := recv(packets, sizes, eps)
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if !bytes.Equal(packets[0][:sizes[0]], pkt) || eps[0].DstToString() != "127.77.0.1:9" {
		t.Fatalf("got %d bytes from %s", sizes[0], eps[0].DstToString())
	}
	// Leaving the relay: what the connection still delivers, or delivered
	// before, must not reach WireGuard (it would roam back).
	b.DeliverRelay(pkt)
	b.SetRelay(nil)
	b.DeliverRelay(pkt)
	done := make(chan error, 1)
	go func() { _, err := recv(packets, sizes, eps); done <- err }()
	select {
	case err := <-done:
		t.Fatalf("a packet after SetRelay(nil) was received (%v)", err)
	case <-time.After(100 * time.Millisecond):
	}
	b.Close()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("after Close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the relay receive function did not end on Close")
	}
}

// A full queue drops instead of blocking the fallback connection's reader.
func TestRelayDeliverNeverBlocks(t *testing.T) {
	b := NewBind(&fakeInner{})
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	b.SetRelay(&frames{})
	done := make(chan struct{})
	go func() {
		for i := 0; i < relayQueue*2; i++ {
			b.DeliverRelay([]byte{1})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("DeliverRelay blocked")
	}
}
