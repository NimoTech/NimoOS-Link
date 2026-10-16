package direct

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/NimoTech/NimoOS-Link/protocol/stun"
)

type Candidate struct {
	Type string `json:"type"` // lan, ipv6, stun
	Addr string `json:"addr"` // host:port
}

var ErrNoPath = errors.New("no address of the NAS answered")

const resendEvery = 200 * time.Millisecond

type reply struct {
	m    stun.Message
	from netip.AddrPort
}

// Agent speaks STUN on the Bind's port: questions to the STUN service and
// signed checks to the NAS; it answers the NAS's signed punches of the
// current session (that answer also opens this side's NAT).
type Agent struct {
	bind *Bind

	mu      sync.Mutex
	waiters map[stun.TxID]chan reply
	session string
	key     []byte
}

func NewAgent(b *Bind) *Agent {
	a := &Agent{bind: b, waiters: map[stun.TxID]chan reply{}}
	b.OnSTUN(a.handle)
	return a
}

func (a *Agent) SetSession(id string, key []byte) {
	a.mu.Lock()
	a.session, a.key = id, append([]byte(nil), key...)
	a.mu.Unlock()
}

func (a *Agent) handle(pkt []byte, from netip.AddrPort) {
	m, err := stun.Parse(pkt)
	if err != nil {
		return
	}
	switch m.Type {
	case stun.TypeBindingSuccess:
		a.mu.Lock()
		ch := a.waiters[m.TxID]
		a.mu.Unlock()
		if ch != nil {
			select {
			case ch <- reply{m, from}:
			default:
			}
		}
	case stun.TypeBindingRequest:
		a.mu.Lock()
		id, key := a.session, a.key
		a.mu.Unlock()
		if id == "" || m.Username != id || !m.FingerprintOK() || !m.Verify(key) {
			return
		}
		_ = a.bind.SendTo(stun.BindingSuccess(m.TxID, from, key), from)
	}
}

func (a *Agent) wait(tx stun.TxID) (chan reply, func()) {
	ch := make(chan reply, 4)
	a.mu.Lock()
	a.waiters[tx] = ch
	a.mu.Unlock()
	return ch, func() { a.mu.Lock(); delete(a.waiters, tx); a.mu.Unlock() }
}

// Reflexive asks the STUN service which address it sees this port as.
func (a *Agent) Reflexive(ctx context.Context, server netip.AddrPort) (netip.AddrPort, error) {
	tx := stun.NewTxID()
	ch, done := a.wait(tx)
	defer done()
	req := stun.BindingRequest(tx, "", nil)
	t := time.NewTicker(resendEvery * 2)
	defer t.Stop()
	_ = a.bind.SendTo(req, server)
	for {
		select {
		case r := <-ch:
			if r.from == server && r.m.Mapped.IsValid() {
				return r.m.Mapped, nil
			}
		case <-t.C:
			_ = a.bind.SendTo(req, server)
		case <-ctx.Done():
			return netip.AddrPort{}, ctx.Err()
		}
	}
}

// Check sends signed checks to every candidate (lan first, then ipv6, then
// stun, staggered by 100 ms) until one answers with a success signed by the
// same key from the address it was sent to.
func (a *Agent) Check(ctx context.Context, cands []Candidate, id string, key []byte) (Candidate, error) {
	type probe struct {
		c   Candidate
		to  netip.AddrPort
		tx  stun.TxID
		req []byte
		at  time.Duration
	}
	order := map[string]int{"lan": 0, "ipv6": 1, "stun": 2}
	var probes []probe
	for _, c := range cands {
		to, err := netip.ParseAddrPort(c.Addr)
		if err != nil {
			continue
		}
		tx := stun.NewTxID()
		probes = append(probes, probe{c, netip.AddrPortFrom(to.Addr().Unmap(), to.Port()), tx,
			stun.BindingRequest(tx, id, key), time.Duration(order[c.Type]) * 100 * time.Millisecond})
	}
	if len(probes) == 0 {
		return Candidate{}, ErrNoPath
	}
	// the losers stop when Check returns, whatever ctx the caller passed
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	won := make(chan Candidate, len(probes))
	for _, p := range probes {
		ch, done := a.wait(p.tx)
		defer done()
		go func(p probe, ch chan reply) {
			select {
			case <-time.After(p.at):
			case <-ctx.Done():
				return
			}
			t := time.NewTicker(resendEvery)
			defer t.Stop()
			_ = a.bind.SendTo(p.req, p.to)
			for {
				select {
				case r := <-ch:
					if r.from == p.to && r.m.FingerprintOK() && r.m.Verify(key) {
						won <- p.c
						return
					}
				case <-t.C:
					_ = a.bind.SendTo(p.req, p.to)
				case <-ctx.Done():
					return
				}
			}
		}(p, ch)
	}
	select {
	case c := <-won:
		return c, nil
	case <-ctx.Done():
		return Candidate{}, ErrNoPath
	}
}
