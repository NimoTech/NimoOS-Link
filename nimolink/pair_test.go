package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

// pairNAS is a fake NAS that signs in, pairs and revokes, and records what it saw.
type pairNAS struct {
	srv        *httptest.Server
	mu         sync.Mutex
	requests   []string
	revoked    []string // "id:token"
	revokeSt   int
	newID      int
	nasPubKey  string
	clientAddr string
}

func newPairNAS(t *testing.T, nasPub string) *pairNAS {
	t.Helper()
	n := &pairNAS{revokeSt: http.StatusOK, newID: 9, nasPubKey: nasPub, clientAddr: "100.64.7.6"}
	n.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.mu.Lock()
		defer n.mu.Unlock()
		n.requests = append(n.requests, r.Method+" "+r.URL.Path)
		switch {
		case r.URL.Path == "/v1/users/login":
			_, _ = io.WriteString(w, `{"success":200,"message":"ok","data":{"token":{"access_token":"ACCESS"}}}`)
		case r.URL.Path == "/v1/gateway/direct/pair":
			_, _ = fmt.Fprintf(w, `{"success":200,"message":"ok","data":{"device_id":%d,"device_token":"DEVTOKEN","nas_public_key":%q,"nas_address":"100.64.7.1","client_address":%q,"subnet":"100.64.7.0/24","port":51900,"endpoints":["10.0.0.5:51900"],"keepalive":25,"mtu":1280}}`, n.newID, n.nasPubKey, n.clientAddr)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/users/remote/devices/"):
			n.revoked = append(n.revoked, strings.TrimPrefix(r.URL.Path, "/v1/users/remote/devices/")+":"+r.Header.Get("Authorization"))
			w.WriteHeader(n.revokeSt)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(n.srv.Close)
	return n
}

func (n *pairNAS) count() int { n.mu.Lock(); defer n.mu.Unlock(); return len(n.requests) }

// pairSetup points the config at a private temp directory and stubs the process state.
func pairSetup(t *testing.T) *bytes.Buffer {
	t.Helper()
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	t.Setenv("NIMOLINK_CONFIG", dir)
	t.Setenv("NIMOLINK_PASSWORD", "SECRETPW")
	var warn bytes.Buffer
	oldW, oldO, oldT := stderrW, stdoutW, tunnelRunning
	stderrW, stdoutW, tunnelRunning = &warn, io.Discard, func() bool { return false }
	t.Cleanup(func() { stderrW, stdoutW, tunnelRunning = oldW, oldO, oldT })
	return &warn
}

func oldPairing(t *testing.T, nasPub string) Config {
	t.Helper()
	c := testConfig(t)
	c.DeviceID, c.DeviceToken, c.Username = 3, "OLDTOKEN", "alice"
	c.NASPublicKey = nasPub
	if err := c.save(); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestPairRefusesWhenPaired(t *testing.T) {
	pairSetup(t)
	_, nasPub, _ := newKeyPair()
	old := oldPairing(t, nasPub)
	n := newPairNAS(t, nasPub)
	err := cmdPair([]string{n.srv.URL, "-user", "alice"}, nil)
	if err == nil {
		t.Fatal("paired again without -replace")
	}
	for _, want := range []string{"already paired", old.NAS, "3", "-replace"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message lacks %q: %v", want, err)
		}
	}
	if n.count() != 0 {
		t.Errorf("the NAS was contacted: %v", n.requests)
	}
	if got, _ := loadConfig(); got.DeviceID != 3 {
		t.Errorf("config changed: %d", got.DeviceID)
	}
}

func TestPairReplaceRevokesOldAfterSave(t *testing.T) {
	warn := pairSetup(t)
	_, nasPub, _ := newKeyPair()
	oldPairing(t, nasPub)
	n := newPairNAS(t, nasPub)
	if err := cmdPair([]string{n.srv.URL, "-user", "alice", "-replace"}, nil); err != nil {
		t.Fatal(err)
	}
	if len(n.revoked) != 1 || n.revoked[0] != "3:ACCESS" {
		t.Fatalf("revoked %v, want the old id 3 with the access token", n.revoked)
	}
	if got, err := loadConfig(); err != nil || got.DeviceID != 9 {
		t.Fatalf("new config not saved: %+v %v", got, err)
	}
	if warn.Len() != 0 {
		t.Errorf("unexpected warning: %s", warn)
	}
}

func TestPairReplaceKeepsOtherNASDevice(t *testing.T) {
	pairSetup(t)
	_, oldPub, _ := newKeyPair()
	_, newPub, _ := newKeyPair()
	oldPairing(t, oldPub)
	n := newPairNAS(t, newPub)
	if err := cmdPair([]string{n.srv.URL, "-user", "alice", "-replace"}, nil); err != nil {
		t.Fatal(err)
	}
	if len(n.revoked) != 0 {
		t.Fatalf("revoked a device id from a different NAS: %v", n.revoked)
	}
	if got, _ := loadConfig(); got.DeviceID != 9 {
		t.Errorf("new pairing not saved")
	}
}

func TestPairReplaceOldRevokeFailureWarns(t *testing.T) {
	warn := pairSetup(t)
	_, nasPub, _ := newKeyPair()
	oldPairing(t, nasPub)
	n := newPairNAS(t, nasPub)
	n.revokeSt = http.StatusInternalServerError
	if err := cmdPair([]string{n.srv.URL, "-user", "alice", "-replace"}, nil); err != nil {
		t.Fatalf("a failed revoke of the old device failed the command: %v", err)
	}
	w := warn.String()
	if !strings.Contains(w, "3") || !strings.Contains(w, "device list") {
		t.Errorf("warning must name the old id and the device list: %q", w)
	}
	if strings.Contains(w, "SECRETPW") || strings.Contains(w, "OLDTOKEN") || strings.Contains(w, "ACCESS") {
		t.Errorf("warning leaks a secret: %q", w)
	}
	if got, _ := loadConfig(); got.DeviceID != 9 {
		t.Errorf("new pairing not saved")
	}
}

func TestPairReplaceSaveFailureKeepsOld(t *testing.T) {
	pairSetup(t)
	_, nasPub, _ := newKeyPair()
	old := oldPairing(t, nasPub)
	n := newPairNAS(t, nasPub)
	n.clientAddr = "x" // the new pairing cannot be validated, so it cannot be saved
	err := cmdPair([]string{n.srv.URL, "-user", "alice", "-replace"}, nil)
	if err == nil {
		t.Fatal("expected failure")
	}
	if len(n.revoked) != 1 || n.revoked[0] != "9:ACCESS" {
		t.Fatalf("revoked %v, want only the NEW device 9", n.revoked)
	}
	if got, err := loadConfig(); err != nil || got.DeviceID != old.DeviceID || got.DeviceToken != "OLDTOKEN" {
		t.Fatalf("old config disturbed: %+v %v", got, err)
	}
}

func TestPairRefusesWhileUp(t *testing.T) {
	pairSetup(t)
	tunnelRunning = func() bool { return true }
	_, nasPub, _ := newKeyPair()
	oldPairing(t, nasPub)
	n := newPairNAS(t, nasPub)
	for _, args := range [][]string{{n.srv.URL, "-user", "alice"}, {n.srv.URL, "-user", "alice", "-replace"}} {
		err := cmdPair(args, nil)
		if err == nil || !strings.Contains(err.Error(), "nimolink down") {
			t.Errorf("%v: %v", args, err)
		}
	}
	if n.count() != 0 {
		t.Errorf("the NAS was contacted: %v", n.requests)
	}
}

func TestPairIgnoresUnusableConfig(t *testing.T) {
	for name, content := range map[string]string{"damaged": "{not json", "invalid": `{"device_id":3}`} {
		t.Run(name, func(t *testing.T) {
			pairSetup(t)
			dir, _ := configDirE()
			_ = os.WriteFile(dir+"/config.json", []byte(content), 0o600)
			_, nasPub, _ := newKeyPair()
			n := newPairNAS(t, nasPub)
			if err := cmdPair([]string{n.srv.URL, "-user", "alice"}, nil); err != nil {
				t.Fatal(err)
			}
			if len(n.revoked) != 0 {
				t.Errorf("revoked %v", n.revoked)
			}
			if got, err := loadConfig(); err != nil || got.DeviceID != 9 {
				t.Errorf("not paired: %+v %v", got, err)
			}
		})
	}
}

func TestPairUntrustedConfigDirStillRefuses(t *testing.T) {
	pairSetup(t)
	dir, _ := configDirE()
	_ = os.Chmod(dir, 0o755)
	_, nasPub, _ := newKeyPair()
	n := newPairNAS(t, nasPub)
	if err := cmdPair([]string{n.srv.URL, "-user", "alice", "-replace"}, nil); err == nil || n.count() != 0 {
		t.Fatalf("err=%v requests=%v", err, n.requests)
	}
}
