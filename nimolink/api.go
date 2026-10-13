package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// API talks to the NAS's panel address.
type API struct {
	Base  string
	HTTP  *http.Client
	Trace io.Writer // nil: quiet
}

// PairResult mirrors the answer of POST /v1/gateway/direct/pair.
type PairResult struct {
	DeviceID      int      `json:"device_id"`
	DeviceToken   string   `json:"device_token"`
	NASPublicKey  string   `json:"nas_public_key"`
	NASAddress    string   `json:"nas_address"`
	ClientAddress string   `json:"client_address"`
	Subnet        string   `json:"subnet"`
	Port          int      `json:"port"`
	Endpoints     []string `json:"endpoints"`
	RemoteURL     string   `json:"remote_url"`
	Keepalive     int      `json:"keepalive"`
	MTU           int      `json:"mtu"`
}

// newHTTPClient returns the client used against the NAS. It never follows a
// redirect: the NAS answers its own address, and a redirect would send the
// credentials somewhere else.
func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout:       15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// normalizeBase accepts "192.168.1.118", "host:port" or an http(s) URL
// without a path, and returns scheme://host[:port].
func normalizeBase(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !strings.HasSuffix(s, "://") {
		s = strings.TrimRight(s, "/")
	}
	if s == "" || strings.HasSuffix(s, "://") {
		return "", errors.New("no NAS address given")
	}
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("%q is not a NAS address (use an IP address, or http://host)", s)
	}
	return u.Scheme + "://" + u.Host, nil
}

// secretFields never appear in a trace.
var secretFields = map[string]bool{"password": true, "access_token": true, "refresh_token": true, "device_token": true, "token": true, "challenge": true}

func redact(v interface{}) interface{} {
	switch x := v.(type) {
	case map[string]interface{}:
		out := map[string]interface{}{}
		for k, val := range x {
			if secretFields[k] {
				if _, isMap := val.(map[string]interface{}); !isMap {
					out[k] = "<hidden>"
					continue
				}
			}
			out[k] = redact(val)
		}
		return out
	case []interface{}:
		for i := range x {
			x[i] = redact(x[i])
		}
	}
	return v
}

func (a *API) trace(format string, args ...interface{}) {
	if a.Trace != nil {
		fmt.Fprintf(a.Trace, format+"\n", args...)
	}
}

func (a *API) traceJSON(prefix string, raw []byte) {
	if a.Trace == nil {
		return
	}
	var v interface{}
	if json.Unmarshal(raw, &v) != nil {
		a.trace("%s <%d bytes, not JSON>", prefix, len(raw))
		return
	}
	b, _ := json.Marshal(redact(v))
	a.trace("%s %s", prefix, b)
}

func (a *API) post(path, authorization string, body interface{}) (int, []byte, error) {
	return a.do(http.MethodPost, path, authorization, body)
}

func (a *API) do(method, path, authorization string, body interface{}) (int, []byte, error) {
	var raw []byte
	var rd io.Reader
	if body != nil {
		raw, _ = json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, a.Base+path, rd)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	a.trace("> %s %s", method, path)
	if body != nil {
		a.traceJSON(">", raw)
	}
	resp, err := a.HTTP.Do(req)
	if err != nil {
		a.trace("< %v", err)
		return 0, nil, fmt.Errorf("cannot reach the NAS at %s: %v", a.Base, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	a.trace("< %d", resp.StatusCode)
	a.traceJSON("<", out)
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return resp.StatusCode, out, fmt.Errorf("the NAS at %s answered with a redirect (HTTP %d); give its own address (an IP address, or http://host)", a.Base, resp.StatusCode)
	}
	return resp.StatusCode, out, nil
}

// Login signs in with the account's password and returns an access token.
func (a *API) Login(user, pass string) (string, error) {
	status, body, err := a.post("/v1/users/login", "", map[string]string{"username": user, "password": pass})
	if err != nil {
		return "", err
	}
	var out struct {
		Message string `json:"message"`
		Data    struct {
			MFARequired bool `json:"mfa_required"`
			Token       struct {
				AccessToken string `json:"access_token"`
			} `json:"token"`
		} `json:"data"`
	}
	_ = json.Unmarshal(body, &out)
	switch {
	case out.Data.MFARequired:
		return "", errors.New("the NAS asked for a second factor, which it only does away from the home network: pair on the home network")
	case status == http.StatusOK && out.Data.Token.AccessToken != "":
		return out.Data.Token.AccessToken, nil
	case status == http.StatusTooManyRequests:
		return "", errors.New("the NAS is temporarily refusing sign-ins (too many attempts): wait a few minutes and try again")
	case out.Message != "":
		return "", errors.New("sign-in refused: " + out.Message + " (check the user name and password)")
	}
	return "", fmt.Errorf("sign-in failed (HTTP %d)", status)
}

// pairErrors says in words what the pairing codes mean.
var pairErrors = map[string]string{
	"LAN_ONLY":           "pairing only works on the home network",
	"TOKEN_REQUIRED":     "the NAS did not accept the sign-in: sign in again",
	"TOKEN_INVALID":      "the NAS did not accept the sign-in: sign in again (after a password change, sign in with the new password)",
	"KEY_INVALID":        "the NAS rejected this client's key",
	"KEY_EXISTS":         "this client is already paired with the NAS: remove it in the panel's device list first",
	"NO_ADDRESS":         "the NAS already has 253 paired clients: remove one in the panel's device list",
	"DIRECT_OFF":         "remote access is switched off on the NAS: switch it on in Settings → Remote access",
	"DIRECT_UNSUPPORTED": "this NAS's system has no WireGuard, so it cannot accept clients",
	"AUTH_UNAVAILABLE":   "the NAS cannot check accounts right now: try again in a moment",
}

// Pair registers this client's public key with the NAS.
func (a *API) Pair(token, pub, name, platform string) (PairResult, error) {
	status, body, err := a.post("/v1/gateway/direct/pair", token, map[string]string{"public_key": pub, "name": name, "platform": platform})
	if err != nil {
		return PairResult{}, err
	}
	var out struct {
		Message string     `json:"message"`
		Data    PairResult `json:"data"`
	}
	_ = json.Unmarshal(body, &out)
	if status != http.StatusOK {
		if msg, ok := pairErrors[out.Message]; ok {
			return PairResult{}, errors.New(msg)
		}
		return PairResult{}, fmt.Errorf("pairing failed: %s (HTTP %d)", out.Message, status)
	}
	r := out.Data
	if r.DeviceToken == "" || r.NASPublicKey == "" || r.NASAddress == "" || r.ClientAddress == "" || r.Subnet == "" || r.Port == 0 {
		return PairResult{}, errors.New("the NAS answered, but not with what a tunnel needs")
	}
	return r, nil
}

// RevokeDevice removes a paired device from the NAS (the panel's device list
// uses the same call). It answers HTTP 200 when the device is gone.
func (a *API) RevokeDevice(token string, id int) error {
	status, _, err := a.do(http.MethodDelete, fmt.Sprintf("/v1/users/remote/devices/%d", id), token, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("the NAS answered HTTP %d", status)
	}
	return nil
}
