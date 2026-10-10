// Package client is the device side of NimoLink: register with the relay,
// open the tunnel, and get a certificate for the device's public host name.
package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/NimoTech/NimoOS-Link/protocol"
)

var (
	ErrUnauthorized        = errors.New("nimolink: unauthorized")
	ErrClockSkew           = errors.New("nimolink: device clock differs from the relay's by more than 5 minutes")
	ErrDeviceDisabled      = errors.New("nimolink: device disabled by the relay operator")
	ErrRegistrationLimited = errors.New("nimolink: too many registrations from this address today")
	ErrCertRateLimited     = errors.New("nimolink: weekly certificate request limit reached")
	ErrRateLimited         = errors.New("nimolink: too many requests, slow down")
	ErrNotFound            = errors.New("nimolink: not found")
)

// Client talks to one relay. Do not copy a Client after first use. Signing is
// throttled to about 1 request/second when sustained (see nextTS).
type Client struct {
	RelayURL  string // https://link.<domain>
	ID        string
	Key       ed25519.PrivateKey
	TLSConfig *tls.Config                                                       // nil: system roots
	Dial      func(ctx context.Context, network, addr string) (net.Conn, error) // nil: net.Dialer
	Now       func() time.Time                                                  // nil: time.Now

	once   sync.Once
	httpc  *http.Client
	mu     sync.Mutex
	lastTS int64
	sleep  func(time.Duration) // nil: time.Sleep
}

type CertStatus struct {
	Status string `json:"status"`
	Chain  string `json:"chain"`
	Error  string `json:"error"`
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// nextTS is strictly greater than every ts this client signed before: two
// identical requests in one second would otherwise carry identical signatures,
// and the relay rejects a repeated signature as a replay. The lead over the
// wall clock is bounded: when ts would run 5 s or more ahead, nextTS waits for
// the clock, so sustained signing above 1 request/second is throttled. If the
// clock stepped back by more than 10 s, signing restarts from the clock.
func (c *Client) nextTS() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	sleep := c.sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	for {
		now := c.now().Unix()
		lead := c.lastTS - now
		switch {
		case lead < 0:
			c.lastTS = now
			return now
		case lead < 5:
			c.lastTS++
			return c.lastTS
		case lead > 10:
			// Clock stepped back. A later identical request may reuse a ts the
			// relay already saw and be rejected once as a replay (surfacing as
			// ErrUnauthorized), so callers must treat ErrUnauthorized from a
			// signed call as retryable, not as "re-register".
			c.lastTS = now
			return now
		}
		sleep(250 * time.Millisecond)
	}
}

func (c *Client) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if c.Dial != nil {
		return c.Dial(ctx, network, addr)
	}
	d := net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	return d.DialContext(ctx, network, addr)
}

// dialTimeout bounds one TCP connect to the relay. Without it a lost SYN
// leaves the device waiting for the kernel's own limit (over two minutes)
// before it can retry.
var dialTimeout = 10 * time.Second

func (c *Client) tlsConfig() *tls.Config {
	cfg := &tls.Config{}
	if c.TLSConfig != nil {
		cfg = c.TLSConfig.Clone()
	}
	cfg.NextProtos = []string{"http/1.1"}
	return cfg
}

func (c *Client) http() *http.Client {
	c.once.Do(func() {
		c.httpc = &http.Client{
			Timeout: time.Minute,
			Transport: &http.Transport{
				DialContext:           c.dial,
				TLSClientConfig:       c.tlsConfig(),
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 30 * time.Second,
			},
		}
	})
	return c.httpc
}

func errorFor(resp *http.Response) error {
	var e struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&e)
	switch e.Error {
	case "clock_skew":
		return ErrClockSkew
	case "device_disabled":
		return ErrDeviceDisabled
	case "registration_limited":
		return ErrRegistrationLimited
	case "cert_rate_limited":
		return ErrCertRateLimited
	case "rate_limited":
		return ErrRateLimited
	}
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusNotFound:
		return ErrNotFound
	}
	return fmt.Errorf("nimolink: relay answered %d %s", resp.StatusCode, e.Error)
}

// Register creates a device for pub and returns its ID.
func (c *Client) Register(ctx context.Context, pub ed25519.PublicKey) (string, error) {
	body, _ := json.Marshal(map[string]string{"public_key": protocol.EncodePublicKey(pub)})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.RelayURL+"/v1/devices", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return "", errorFor(resp)
	}
	var out struct {
		DeviceID string `json:"device_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if !protocol.ValidDeviceID(out.DeviceID) {
		return "", fmt.Errorf("nimolink: relay returned invalid device id %q", out.DeviceID)
	}
	return out.DeviceID, nil
}

func (c *Client) signed(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.RelayURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", protocol.SignRequest(c.Key, c.ID, method, path, c.nextTS(), body))
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.http().Do(req)
}

func (c *Client) RequestCert(ctx context.Context, csrPEM []byte) (string, error) {
	body, _ := json.Marshal(map[string]string{"csr": string(csrPEM)})
	resp, err := c.signed(ctx, http.MethodPost, "/v1/devices/"+c.ID+"/cert", body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		return "", errorFor(resp)
	}
	var out struct {
		OrderID string `json:"order_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.OrderID, nil
}

func (c *Client) CertStatus(ctx context.Context, orderID string) (CertStatus, error) {
	resp, err := c.signed(ctx, http.MethodGet, "/v1/devices/"+c.ID+"/cert/"+orderID, nil)
	if err != nil {
		return CertStatus{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return CertStatus{}, errorFor(resp)
	}
	var st CertStatus
	err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&st)
	return st, err
}

func (c *Client) Delete(ctx context.Context) error {
	resp, err := c.signed(ctx, http.MethodDelete, "/v1/devices/"+c.ID, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return errorFor(resp)
	}
	return nil
}

// DialTunnel opens the device's tunnel. The relay opens one stream per visitor;
// accept them with NewListener.
func (c *Client) DialTunnel(ctx context.Context) (*yamux.Session, error) {
	u, err := url.Parse(c.RelayURL)
	if err != nil {
		return nil, err
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	raw, err := c.dial(ctx, "tcp", net.JoinHostPort(u.Hostname(), port))
	if err != nil {
		return nil, err
	}
	cfg := c.tlsConfig()
	if cfg.ServerName == "" {
		cfg.ServerName = u.Hostname()
	}
	tc := tls.Client(raw, cfg)
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(30 * time.Second)
	}
	_ = tc.SetDeadline(deadline)
	if err := tc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	const path = "/v1/tunnel"
	req, _ := http.NewRequest(http.MethodGet, "https://"+u.Host+path, nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", protocol.TunnelUpgrade)
	req.Header.Set("Authorization", protocol.SignRequest(c.Key, c.ID, http.MethodGet, path, c.nextTS(), nil))
	if err := req.Write(tc); err != nil {
		tc.Close()
		return nil, err
	}
	br := bufio.NewReader(tc)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		tc.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		err := errorFor(resp)
		resp.Body.Close()
		tc.Close()
		return nil, err
	}
	_ = tc.SetDeadline(time.Time{})
	var conn net.Conn = tc
	if n := br.Buffered(); n > 0 {
		b, _ := br.Peek(n)
		conn = protocol.NewPrefixConn(tc, append([]byte(nil), b...))
	}
	sess, err := yamux.Server(conn, protocol.YamuxConfig())
	if err != nil {
		tc.Close()
		return nil, err
	}
	return sess, nil
}
