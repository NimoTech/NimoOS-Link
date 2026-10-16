// Command nimolink is the reference client for NimoLink direct connections:
// pair with a NAS at home, then reach it over a WireGuard tunnel.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
)

// Config is everything pairing produced. It holds the client's private key
// and its device credential: the file is 0600.
type Config struct {
	NAS           string   `json:"nas"` // the address pairing was done with
	Username      string   `json:"username"`
	DeviceID      int      `json:"device_id"`
	DeviceToken   string   `json:"device_token"`
	PrivateKey    string   `json:"private_key"`
	NASPublicKey  string   `json:"nas_public_key"`
	NASAddress    string   `json:"nas_address"`
	ClientAddress string   `json:"client_address"`
	Subnet        string   `json:"subnet"`
	Port          int      `json:"port"`
	Endpoints     []string `json:"endpoints"`
	RemoteURL     string   `json:"remote_url"`
	Keepalive     int      `json:"keepalive"`
	MTU           int      `json:"mtu"`
	STUNServer    string   `json:"stun_server,omitempty"`
}

// configDirE is where the configuration lives: NIMOLINK_CONFIG, else the
// user's config directory (under sudo that is root's, not the caller's).
func configDirE() (string, error) {
	if d := os.Getenv("NIMOLINK_CONFIG"); d != "" {
		return d, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", errors.New("cannot tell where to keep the configuration (no home directory): set NIMOLINK_CONFIG to a directory")
	}
	return filepath.Join(base, "nimolink"), nil
}

// noUsableConfig marks a loadConfig failure that means "there is no usable
// pairing here" (nothing saved, or a file that cannot be read as one), as
// opposed to a directory that cannot be trusted or a file that cannot be read.
type noUsableConfig struct{ msg string }

func (e *noUsableConfig) Error() string { return e.msg }

func notPaired(path string) error {
	return &noUsableConfig{"not paired yet (no configuration at " + path + "): run `nimolink pair <NAS address>` on the home network"}
}

// configDirProblem says why a config directory with this mode (as from
// Lstat, so a symlink shows as one) and owner cannot be trusted by a process
// running as euid: it must be a real directory, owned by that user, with no
// group or world access. A root process must not read or write a directory
// somebody else controls.
func configDirProblem(mode os.FileMode, uid, euid uint32) error {
	switch {
	case mode&os.ModeSymlink != 0:
		return errors.New("is a symbolic link, not a real directory")
	case !mode.IsDir():
		return errors.New("is not a directory")
	case uid != euid:
		return fmt.Errorf("is owned by user %d, not by the user running this command (%d)", uid, euid)
	case mode.Perm()&0o077 != 0:
		return fmt.Errorf("is accessible to other users (mode %o): make it private (chmod 700)", mode.Perm())
	}
	return nil
}

// checkConfigDir inspects dir without following a link. exists is false when
// there is nothing there yet.
func checkConfigDir(dir string) (exists bool, err error) {
	fi, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var uid uint32
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		uid = st.Uid
	} else {
		return true, errors.New("cannot tell who owns " + dir)
	}
	if p := configDirProblem(fi.Mode(), uid, uint32(os.Geteuid())); p != nil {
		return true, fmt.Errorf("the configuration directory %s %v; choose another with NIMOLINK_CONFIG", dir, p)
	}
	return true, nil
}

// prepareConfigDir returns the config directory, created 0700 if missing and
// otherwise checked (never changed).
func prepareConfigDir() (string, error) {
	dir, err := configDirE()
	if err != nil {
		return "", err
	}
	exists, err := checkConfigDir(dir)
	if err != nil {
		return "", err
	}
	if !exists {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
		if _, err := checkConfigDir(dir); err != nil {
			return "", err
		}
	}
	return dir, nil
}

// preflightConfigDir proves, before the user is asked for anything and before
// a device is registered, that the configuration can be saved.
func preflightConfigDir() error {
	dir, err := prepareConfigDir()
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "preflight-*.tmp")
	if err != nil {
		return fmt.Errorf("cannot write in the configuration directory: %v", err)
	}
	name := f.Name()
	_ = f.Close()
	return os.Remove(name)
}

func loadConfig() (Config, error) {
	var c Config
	dir, err := configDirE()
	if err != nil {
		return c, err
	}
	path := filepath.Join(dir, "config.json")
	exists, err := checkConfigDir(dir)
	if err != nil {
		return c, err
	}
	if !exists {
		return c, notPaired(path)
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, notPaired(path)
	}
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, &noUsableConfig{"the config file " + path + " is damaged: " + err.Error()}
	}
	if err := validatePairing(c); err != nil {
		return c, &noUsableConfig{"the config file " + path + " is unusable (" + err.Error() + "): pair again"}
	}
	return c, nil
}

// save writes the config through a fresh, exclusively created temporary file
// (never a name somebody could have planted a link at) and renames it into
// place.
func (c Config) save() (err error) {
	dir, err := prepareConfigDir()
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	f, err := os.CreateTemp(dir, "config-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if _, err = f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, "config.json"))
}

// stunServerFor: what pairing said, else the remote address's host on 3478
// (the relay's wildcard name points at the relay host). Pairings from step 1
// have no stun_server and need no new pairing.
func stunServerFor(c Config) string {
	if c.STUNServer != "" {
		return c.STUNServer
	}
	u, err := url.Parse(c.RemoteURL)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	return net.JoinHostPort(u.Hostname(), "3478")
}
