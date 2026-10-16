package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cfg")
	t.Setenv("NIMOLINK_CONFIG", dir)
	if _, err := loadConfig(); err == nil {
		t.Fatal("a config was loaded although none exists")
	}
	c := Config{NAS: "http://192.168.1.118", Username: "alice", DeviceID: 7, DeviceToken: "TOKEN", PrivateKey: "PRIV",
		NASPublicKey: "PUB", NASAddress: "100.64.7.1", ClientAddress: "100.64.7.5", Subnet: "100.64.7.0/24",
		Port: 51900, Endpoints: []string{"192.168.1.118:51900"}, RemoteURL: "https://x.example.test", Keepalive: 25, MTU: 1280}
	if err := c.save(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, "config.json"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("config file: %v %v", fi, err)
	}
	if di, _ := os.Stat(dir); di.Mode().Perm() != 0o700 {
		t.Fatalf("config directory mode %v", di.Mode().Perm())
	}
	got, err := loadConfig()
	if err != nil || got.DeviceToken != "TOKEN" || got.Endpoints[0] != "192.168.1.118:51900" || got.MTU != 1280 {
		t.Fatalf("loaded %+v, %v", got, err)
	}
	// a file somebody damaged is an error, not an empty config
	_ = os.WriteFile(filepath.Join(dir, "config.json"), []byte("{"), 0o600)
	if _, err := loadConfig(); err == nil {
		t.Fatal("a damaged config was accepted")
	}
}

func TestSaveDoesNotTouchAnExistingDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cfg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(dir, 0o755)
	t.Setenv("NIMOLINK_CONFIG", dir)
	if err := (Config{}).save(); err == nil {
		t.Fatal("saved into a world-accessible directory")
	}
	if di, _ := os.Stat(dir); di.Mode().Perm() != 0o755 {
		t.Fatalf("the existing directory was changed to %v", di.Mode().Perm())
	}
	// a private directory that already exists is fine and keeps its mode
	dir2 := filepath.Join(t.TempDir(), "cfg2")
	_ = os.Mkdir(dir2, 0o700)
	t.Setenv("NIMOLINK_CONFIG", dir2)
	if err := (Config{}).save(); err != nil {
		t.Fatal(err)
	}
}

func TestNotPairedNamesThePath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nothing-here")
	t.Setenv("NIMOLINK_CONFIG", dir)
	_, err := loadConfig()
	if err == nil || !strings.Contains(err.Error(), dir) {
		t.Fatalf("error %v does not name %s", err, dir)
	}
}

func TestConfigDirNeedsAHome(t *testing.T) {
	t.Setenv("NIMOLINK_CONFIG", "")
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	if _, err := configDirE(); err == nil {
		t.Fatal("no home and no NIMOLINK_CONFIG, yet a directory was chosen")
	}
}

func TestSaveDoesNotFollowATempSymlink(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cfg")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NIMOLINK_CONFIG", dir)
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	// the old predictable temporary name, planted as a link
	if err := os.Symlink(victim, filepath.Join(dir, "config.json.tmp")); err != nil {
		t.Fatal(err)
	}
	if err := (Config{DeviceToken: "T"}).save(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "precious" {
		t.Fatalf("the link target was overwritten: %q", b)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") && e.Name() != "config.json.tmp" {
			t.Errorf("temporary file %s left behind", e.Name())
		}
	}
}

func TestConfigDirMustBeARealDirectory(t *testing.T) {
	real := filepath.Join(t.TempDir(), "real")
	_ = os.Mkdir(real, 0o700)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NIMOLINK_CONFIG", link)
	if err := (Config{}).save(); err == nil {
		t.Fatal("saved through a symlinked config directory")
	}
	if _, err := loadConfig(); err == nil || strings.Contains(err.Error(), "not paired") {
		t.Fatalf("loaded through a symlinked config directory: %v", err)
	}
}

func TestConfigDirProblem(t *testing.T) {
	dir := os.ModeDir | 0o700
	if err := configDirProblem(dir, 1000, 1000); err != nil {
		t.Errorf("own private dir: %v", err)
	}
	if err := configDirProblem(dir, 1001, 0); err == nil {
		t.Error("a directory owned by another user was trusted by root")
	}
	if err := configDirProblem(os.ModeDir|0o750, 0, 0); err == nil {
		t.Error("group-accessible dir accepted")
	}
	if err := configDirProblem(os.ModeSymlink|0o777, 0, 0); err == nil {
		t.Error("symlink accepted")
	}
	if err := configDirProblem(0o600, 0, 0); err == nil {
		t.Error("regular file accepted")
	}
}

func TestPreflightConfigDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cfg")
	t.Setenv("NIMOLINK_CONFIG", dir)
	if err := preflightConfigDir(); err != nil {
		t.Fatal(err)
	}
	if es, _ := os.ReadDir(dir); len(es) != 0 {
		t.Fatalf("preflight left files: %v", es)
	}
	_ = os.Chmod(dir, 0o755)
	if err := preflightConfigDir(); err == nil {
		t.Fatal("preflight accepted an open directory")
	}
}

func TestWritePidFile(t *testing.T) {
	d := t.TempDir()
	victim := filepath.Join(d, "victim")
	_ = os.WriteFile(victim, []byte("precious"), 0o600)
	pf := filepath.Join(d, "nimolink.pid")
	if err := os.Symlink(victim, pf); err != nil {
		t.Fatal(err)
	}
	if err := writePidFile(pf, 4242); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "precious" {
		t.Fatalf("link target overwritten: %q", b)
	}
	if b, _ := os.ReadFile(pf); string(b) != "4242" {
		t.Fatalf("pid file: %q", b)
	}
	if fi, _ := os.Lstat(pf); fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("pid file is still a symlink")
	}
	if err := writePidFile(filepath.Join(d, "missing", "x.pid"), 1); err == nil {
		t.Fatal("a write failure was not reported")
	}
}
func TestSTUNServerFor(t *testing.T) {
	for _, c := range []struct {
		cfg  Config
		want string
	}{
		{Config{STUNServer: "stun.example:3479", RemoteURL: "https://abc.relay-test.nimotech.ai"}, "stun.example:3479"},
		{Config{RemoteURL: "https://abc.relay-test.nimotech.ai"}, "abc.relay-test.nimotech.ai:3478"},
		{Config{}, ""},
	} {
		if got := stunServerFor(c.cfg); got != c.want {
			t.Errorf("%+v: %q want %q", c.cfg, got, c.want)
		}
	}
}
