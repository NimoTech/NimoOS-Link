package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NimoTech/NimoOS-Link/nimolink/direct"
)

func TestNormalizeBase(t *testing.T) {
	for in, want := range map[string]string{
		"192.168.1.118":           "http://192.168.1.118",
		"192.168.1.118:8080/":     "http://192.168.1.118:8080",
		"http://nas.local/":       "http://nas.local",
		"https://192.168.1.118":   "https://192.168.1.118",
		" http://192.168.1.118  ": "http://192.168.1.118",
	} {
		if got, err := normalizeBase(in); err != nil || got != want {
			t.Errorf("%q → %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "ftp://x", "http://", "http://a b", "http://x/path", "http://user@x"} {
		if _, err := normalizeBase(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func fakeNAS(t *testing.T, h http.HandlerFunc) *API {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &API{Base: srv.URL, HTTP: srv.Client()}
}

func TestLogin(t *testing.T) {
	a := fakeNAS(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if r.Method != http.MethodPost || r.URL.Path != "/v1/users/login" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		switch body["password"] {
		case "right":
			_, _ = io.WriteString(w, `{"success":200,"message":"ok","data":{"token":{"access_token":"ACCESS","refresh_token":"R"},"user":{"username":"alice"}}}`)
		case "mfa":
			_, _ = io.WriteString(w, `{"success":200,"message":"mfa required","data":{"mfa_required":true,"challenge":"C"}}`)
		default:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"success":10013,"message":"User does not exist or password is invalid"}`)
		}
	})
	if tok, err := a.Login("alice", "right"); err != nil || tok != "ACCESS" {
		t.Fatalf("login: %q %v", tok, err)
	}
	if _, err := a.Login("alice", "wrong"); err == nil || !strings.Contains(err.Error(), "password") {
		t.Fatalf("wrong password: %v", err)
	}
	// pairing is done at home, where no second factor is asked: being asked means this is not home
	if _, err := a.Login("alice", "mfa"); err == nil || !strings.Contains(err.Error(), "home network") {
		t.Fatalf("second factor asked: %v", err)
	}
	down := &API{Base: "http://127.0.0.1:1", HTTP: http.DefaultClient}
	if _, err := down.Login("alice", "right"); err == nil {
		t.Fatal("no error although nothing listens")
	}
}

func TestPairCall(t *testing.T) {
	var auth string
	var body map[string]string
	status, answer := http.StatusOK, `{"success":200,"message":"ok","data":{"device_id":7,"device_token":"DEVTOKEN","nas_public_key":"NASPUB","nas_address":"100.64.7.1","client_address":"100.64.7.5","subnet":"100.64.7.0/24","port":51900,"endpoints":["192.168.1.118:51900"],"remote_url":"https://x.example.test","keepalive":25,"mtu":1280}}`
	a := fakeNAS(t, func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&body)
		if r.URL.Path != "/v1/gateway/direct/pair" {
			t.Errorf("path %s", r.URL.Path)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, answer)
	})
	res, err := a.Pair("ACCESS", "PUB", "laptop", "linux")
	if err != nil || res.DeviceToken != "DEVTOKEN" || res.ClientAddress != "100.64.7.5" || res.Port != 51900 || res.Endpoints[0] != "192.168.1.118:51900" {
		t.Fatalf("%+v %v", res, err)
	}
	if auth != "ACCESS" || body["public_key"] != "PUB" || body["name"] != "laptop" || body["platform"] != "linux" {
		t.Fatalf("sent auth=%q body=%v", auth, body)
	}
	for code, want := range map[string]string{
		"LAN_ONLY": "home network", "KEY_EXISTS": "already paired", "NO_ADDRESS": "253",
		"DIRECT_OFF": "remote access", "DIRECT_UNSUPPORTED": "WireGuard", "TOKEN_INVALID": "sign in",
		"SOMETHING_NEW": "SOMETHING_NEW",
	} {
		status, answer = http.StatusForbidden, `{"success":403,"message":"`+code+`","data":null}`
		if _, err := a.Pair("ACCESS", "PUB", "", "linux"); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want a message about %q", code, err, want)
		}
	}
	// a 200 that registered no device is not a success
	status, answer = http.StatusOK, `{"success":200,"message":"ok","data":{"device_token":"DEVTOKEN"}}`
	if _, err := a.Pair("ACCESS", "PUB", "", "linux"); err == nil {
		t.Fatal("an answer without a device was accepted")
	}
	// one that did but is missing the rest comes back, so that savePairing
	// can refuse it and remove the device again
	status, answer = http.StatusOK, `{"success":200,"message":"ok","data":{"device_id":7}}`
	if res, err := a.Pair("ACCESS", "PUB", "", "linux"); err != nil || res.DeviceID != 7 {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestTraceShowsNoSecrets(t *testing.T) {
	var trace bytes.Buffer
	a := fakeNAS(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/login") {
			_, _ = io.WriteString(w, `{"success":200,"data":{"token":{"access_token":"ACCESSSECRET","refresh_token":"REFRESHSECRET"}}}`)
			return
		}
		_, _ = io.WriteString(w, `{"success":200,"message":"ok","data":{"device_id":7,"device_token":"DEVICESECRET","nas_public_key":"NASPUB","nas_address":"100.64.7.1","client_address":"100.64.7.5","subnet":"100.64.7.0/24","port":51900,"keepalive":25,"mtu":1280}}`)
	})
	a.Trace = &trace
	tok, _ := a.Login("alice", "PASSWORDSECRET")
	_, _ = a.Pair(tok, "PUB", "laptop", "linux")
	out := trace.String()
	for _, secret := range []string{"PASSWORDSECRET", "ACCESSSECRET", "REFRESHSECRET", "DEVICESECRET"} {
		if strings.Contains(out, secret) {
			t.Errorf("the trace shows %s", secret)
		}
	}
	for _, shown := range []string{"POST /v1/users/login", "POST /v1/gateway/direct/pair", "alice", "NASPUB", "100.64.7.5", "200"} {
		if !strings.Contains(out, shown) {
			t.Errorf("the trace does not show %q:\n%s", shown, out)
		}
	}
}

func TestRedirectIsAnError(t *testing.T) {
	var followed bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			followed = true
			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	a := &API{Base: srv.URL, HTTP: newHTTPClient()}
	_, err := a.Login("alice", "pw")
	if err == nil || !strings.Contains(err.Error(), "302") {
		t.Fatalf("error %v does not name the status", err)
	}
	if followed {
		t.Fatal("the redirect was followed")
	}
}

func TestLoginRateLimited(t *testing.T) {
	a := fakeNAS(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"message":"too many attempts"}`)
	})
	_, err := a.Login("alice", "pw")
	if err == nil || strings.Contains(err.Error(), "check the user name") || !strings.Contains(err.Error(), "temporarily") {
		t.Fatalf("429: %v", err)
	}
}

func TestTraceHidesChallenge(t *testing.T) {
	var trace bytes.Buffer
	a := fakeNAS(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"success":200,"message":"mfa required","data":{"mfa_required":true,"challenge":"CHALLENGESECRET"}}`)
	})
	a.Trace = &trace
	_, _ = a.Login("alice", "pw")
	if strings.Contains(trace.String(), "CHALLENGESECRET") {
		t.Fatalf("the trace shows the challenge:\n%s", trace.String())
	}
}

func TestRevokeDevice(t *testing.T) {
	var method, path, auth string
	status := http.StatusOK
	a := fakeNAS(t, func(w http.ResponseWriter, r *http.Request) {
		method, path, auth = r.Method, r.URL.Path, r.Header.Get("Authorization")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, `{"success":200,"message":"ok"}`)
	})
	if err := a.RevokeDevice("ACCESS", 7); err != nil {
		t.Fatal(err)
	}
	if method != http.MethodDelete || path != "/v1/users/remote/devices/7" || auth != "ACCESS" {
		t.Fatalf("%s %s auth=%q", method, path, auth)
	}
	status = http.StatusInternalServerError
	if err := a.RevokeDevice("ACCESS", 7); err == nil {
		t.Fatal("HTTP 500 counted as removed")
	}
}

func TestSavePairingRevokesOnFailure(t *testing.T) {
	var method, path, auth string
	status := http.StatusOK
	a := fakeNAS(t, func(w http.ResponseWriter, r *http.Request) {
		method, path, auth = r.Method, r.URL.Path, r.Header.Get("Authorization")
		w.WriteHeader(status)
	})
	// a config directory that save refuses
	dir := filepath.Join(t.TempDir(), "open")
	_ = os.Mkdir(dir, 0o755)
	_ = os.Chmod(dir, 0o755)
	t.Setenv("NIMOLINK_CONFIG", dir)
	c := Config{DeviceID: 7}
	err := savePairing(a, "ACCESS", c)
	if err == nil || method != http.MethodDelete || path != "/v1/users/remote/devices/7" || auth != "ACCESS" {
		t.Fatalf("err=%v %s %s %q", err, method, path, auth)
	}
	if !strings.Contains(err.Error(), "removed") {
		t.Errorf("the error does not say the device was removed: %v", err)
	}
	// an answer that is not usable (here: no device token) is not saved,
	// and the device goes again
	t.Setenv("NIMOLINK_CONFIG", t.TempDir())
	bad := testConfig(t)
	bad.DeviceID, bad.DeviceToken = 8, ""
	method, path = "", ""
	if err := savePairing(a, "ACCESS", bad); err == nil || method != http.MethodDelete || path != "/v1/users/remote/devices/8" {
		t.Fatalf("err=%v %s %s", err, method, path)
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("NIMOLINK_CONFIG"), "config.json")); !os.IsNotExist(err) {
		t.Fatalf("an unusable pairing was saved: %v", err)
	}
	t.Setenv("NIMOLINK_CONFIG", dir)
	status = http.StatusInternalServerError
	err = savePairing(a, "ACCESS", c)
	if err == nil || !strings.Contains(err.Error(), "7") || !strings.Contains(err.Error(), "panel") {
		t.Fatalf("a failed removal must name the device and the panel: %v", err)
	}
}
func TestConnect(t *testing.T) {
	var gotHdr, gotAuth string
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/gateway/direct/connect" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		gotHdr, gotAuth = r.Header.Get("X-NimoLink-Device"), r.Header.Get("Authorization")
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.Write([]byte(`{"success":200,"message":"ok","data":{"session":"s","check_key":"a2V5","expires_in":60,"nas_public_key":"pk","candidates":[{"type":"stun","addr":"203.0.113.7:51446"}]}}`))
	}))
	defer srv.Close()
	api := &API{Base: srv.URL, HTTP: srv.Client()}
	res, err := api.Connect("devtok", []direct.Candidate{{Type: "lan", Addr: "192.168.43.5:40000"}})
	if err != nil {
		t.Fatal(err)
	}
	if gotHdr != "devtok" || gotAuth != "" {
		t.Fatalf("headers: device=%q authorization=%q", gotHdr, gotAuth)
	}
	if res.Session != "s" || res.CheckKey != "a2V5" || len(res.Candidates) != 1 || res.Candidates[0].Addr != "203.0.113.7:51446" {
		t.Fatalf("%+v", res)
	}
	if c, _ := gotBody["candidates"].([]interface{}); len(c) != 1 {
		t.Fatalf("body %v", gotBody)
	}
}

func TestConnectErrors(t *testing.T) {
	for _, c := range []struct {
		status int
		body   string
		want   error
	}{
		{404, "404 page not found", ErrNoConnect},
		{404, `{"success":404,"message":"DIRECT_OFF"}`, ErrDirectOff},
		{401, `{"success":401,"message":"TOKEN_INVALID"}`, ErrDeviceRemoved},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(c.status)
			w.Write([]byte(c.body))
		}))
		_, err := (&API{Base: srv.URL, HTTP: srv.Client()}).Connect("t", nil)
		srv.Close()
		if !errors.Is(err, c.want) {
			t.Errorf("%d %s: %v, want %v", c.status, c.body, err, c.want)
		}
	}
}

func TestTraceHidesTheCheckKey(t *testing.T) {
	if v := redact(map[string]interface{}{"check_key": "secret"}); v.(map[string]interface{})["check_key"] == "secret" {
		t.Fatal("check_key in the trace")
	}
}

// What a NAS really answers through its remote address: the gate speaks first.
func TestConnectErrorsFromTheGate(t *testing.T) {
	for _, c := range []struct {
		status int
		body   string
		want   error
	}{
		{401, `{"code":"CLIENT_INVALID","message":"CLIENT_INVALID","success":401}`, ErrDeviceRemoved},
		{403, `{"code":"REMOTE_AUTH_REQUIRED","message":"REMOTE_AUTH_REQUIRED","success":403}`, ErrNoConnect}, // an older NAS
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(c.status)
			w.Write([]byte(c.body))
		}))
		_, err := (&API{Base: srv.URL, HTTP: srv.Client()}).Connect("t", nil)
		srv.Close()
		if !errors.Is(err, c.want) {
			t.Errorf("%d %s: %v, want %v", c.status, c.body, err, c.want)
		}
	}
}

// The device credential never follows a redirect to another host.
func TestConnectDoesNotFollowRedirects(t *testing.T) {
	leaked := make(chan string, 1)
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked <- r.Header.Get("X-NimoLink-Device")
	}))
	defer other.Close()
	nas := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer nas.Close()
	_, err := connectAPI(Config{RemoteURL: nas.URL}, nil).Connect("devtok", nil)
	if err == nil {
		t.Fatal("a redirect was taken for an answer")
	}
	select {
	case h := <-leaked:
		t.Fatalf("followed the redirect; the other host got %q", h)
	default:
	}
}

func TestOpenSessionChecksTheNASKey(t *testing.T) {
	paired := base64.StdEncoding.EncodeToString(make([]byte, 32))
	other := make([]byte, 32)
	other[0] = 1
	answer := func(key string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"success":200,"message":"ok","data":{"session":"s","check_key":"a2V5","expires_in":60,"nas_public_key":"` + key + `","candidates":[]}}`))
		}))
	}
	srv := answer(paired)
	defer srv.Close()
	res, key, err := openSession(&API{Base: srv.URL, HTTP: srv.Client()}, Config{DeviceToken: "t", NASPublicKey: paired}, nil)
	if err != nil || res.Session != "s" || string(key) != "key" {
		t.Fatalf("paired NAS: %+v %q %v", res, key, err)
	}
	srv2 := answer(base64.StdEncoding.EncodeToString(other))
	defer srv2.Close()
	if _, _, err := openSession(&API{Base: srv2.URL, HTTP: srv2.Client()}, Config{DeviceToken: "t", NASPublicKey: paired}, nil); !errors.Is(err, ErrNASKeyChanged) {
		t.Fatalf("another NAS: %v, want ErrNASKeyChanged", err)
	}
}
