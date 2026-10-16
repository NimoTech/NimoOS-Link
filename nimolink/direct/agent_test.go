package direct

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/NimoTech/NimoOS-Link/protocol/stun"
)

// loopNet connects an Agent's Bind to fake remote answerers.
type loopNet struct {
	mu      sync.Mutex
	answer  map[netip.AddrPort]func(req stun.Message) []byte // nil reply: silence
	deliver func([]byte, netip.AddrPort)
}

func newAgentEnv(t *testing.T) (*Agent, *loopNet) {
	ln := &loopNet{answer: map[netip.AddrPort]func(stun.Message) []byte{}}
	b := &Bind{}
	b.send = func(pkt []byte, to netip.AddrPort) error {
		ln.mu.Lock()
		f := ln.answer[to]
		ln.mu.Unlock()
		if f == nil {
			return nil
		}
		m, err := stun.Parse(pkt)
		if err != nil {
			return nil
		}
		if r := f(m); r != nil {
			go b.dispatch(r, to)
		}
		return nil
	}
	return NewAgent(b), ln
}

func TestReflexive(t *testing.T) {
	a, ln := newAgentEnv(t)
	server := netip.MustParseAddrPort("52.15.161.48:3478")
	mapped := netip.MustParseAddrPort("172.31.5.5:40000")
	ln.answer[server] = func(m stun.Message) []byte { return stun.BindingSuccess(m.TxID, mapped, nil) }
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	got, err := a.Reflexive(ctx, server)
	if err != nil || got != mapped {
		t.Fatalf("%s %v", got, err)
	}
}

func TestCheckPicksAnAnsweringPathAndVerifiesIt(t *testing.T) {
	a, ln := newAgentEnv(t)
	key := []byte("0123456789abcdef0123456789abcdef")
	lan := netip.MustParseAddrPort("192.168.1.118:51900")
	refl := netip.MustParseAddrPort("203.0.113.7:51446")
	forged := netip.MustParseAddrPort("198.51.100.1:51900")
	ln.answer[refl] = func(m stun.Message) []byte {
		if m.Username != "sess" || !m.Verify(key) {
			return nil
		}
		return stun.BindingSuccess(m.TxID, netip.MustParseAddrPort("203.0.113.9:61000"), key)
	}
	ln.answer[forged] = func(m stun.Message) []byte { return stun.BindingSuccess(m.TxID, refl, []byte("other key")) }
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	got, err := a.Check(ctx, []Candidate{{"lan", lan.String()}, {"stun", forged.String()}, {"stun", refl.String()}}, "sess", key)
	if err != nil || got.Addr != refl.String() {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestCheckGivesUp(t *testing.T) {
	a, _ := newAgentEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if _, err := a.Check(ctx, []Candidate{{"stun", "203.0.113.7:1"}}, "s", []byte("k")); !errors.Is(err, ErrNoPath) {
		t.Fatalf("%v", err)
	}
}

func TestAgentAnswersTheNASPunchesOfItsSession(t *testing.T) {
	a, _ := newAgentEnv(t)
	var replies [][]byte
	a.bind.send = func(pkt []byte, to netip.AddrPort) error { replies = append(replies, pkt); return nil }
	key := []byte("k1")
	a.SetSession("sess", key)
	nas := netip.MustParseAddrPort("203.0.113.7:51446")
	a.bind.dispatch(stun.BindingRequest(stun.NewTxID(), "sess", key), nas)
	a.bind.dispatch(stun.BindingRequest(stun.NewTxID(), "sess", []byte("wrong")), nas)
	a.bind.dispatch(stun.BindingRequest(stun.NewTxID(), "", nil), nas)
	if len(replies) != 1 {
		t.Fatalf("%d replies, want 1 (only to the signed punch of our session)", len(replies))
	}
	m, _ := stun.Parse(replies[0])
	if m.Type != stun.TypeBindingSuccess || !m.Verify(key) {
		t.Fatalf("%+v", m)
	}
}

// Once a candidate answers, the others stop probing, whatever the caller's context.
func TestCheckStopsTheLosers(t *testing.T) {
	a, ln := newAgentEnv(t)
	key := []byte("k")
	win := netip.MustParseAddrPort("203.0.113.7:51446")
	silent := netip.MustParseAddrPort("198.51.100.1:51900")
	var mu sync.Mutex
	toSilent := 0
	ln.answer[win] = func(m stun.Message) []byte { return stun.BindingSuccess(m.TxID, win, key) }
	ln.answer[silent] = func(stun.Message) []byte { mu.Lock(); toSilent++; mu.Unlock(); return nil }
	if _, err := a.Check(context.Background(), []Candidate{{"stun", win.String()}, {"lan", silent.String()}}, "s", key); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	before := toSilent
	mu.Unlock()
	time.Sleep(700 * time.Millisecond)
	mu.Lock()
	after := toSilent
	mu.Unlock()
	if after != before {
		t.Fatalf("the losing probe kept sending after Check returned (%d → %d)", before, after)
	}
}
