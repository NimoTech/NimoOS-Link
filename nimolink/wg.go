package main

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const ifName = "nimolink0"

// validatePairing checks a pairing answer before anything is saved or
// installed: the network must be a /24 inside 100.64.0.0/10, the NAS its .1,
// this device a host 2-254 of it, and the numbers sane. A NAS (or something
// pretending to be one) must not be able to make the client route 0.0.0.0/0
// or a home network into the tunnel.
func validatePairing(c Config) error {
	bad := func(format string, a ...interface{}) error {
		return fmt.Errorf("the NAS sent an unusable network setting: "+format, a...)
	}
	ip, ipnet, err := net.ParseCIDR(c.Subnet)
	if err != nil || ip.To4() == nil {
		return bad("network %q is not an IPv4 network", c.Subnet)
	}
	if ones, bits := ipnet.Mask.Size(); ones != 24 || bits != 32 {
		return bad("network %s is not a /24", c.Subnet)
	}
	if !ip.Equal(ipnet.IP) {
		return bad("network %s has host bits set", c.Subnet)
	}
	if _, cgnat, _ := net.ParseCIDR("100.64.0.0/10"); !cgnat.Contains(ipnet.IP) {
		return bad("network %s is outside 100.64.0.0/10", c.Subnet)
	}
	base := ipnet.IP.To4()
	nas := net.ParseIP(c.NASAddress).To4()
	if nas == nil || !nas.Equal(net.IPv4(base[0], base[1], base[2], 1)) {
		return bad("the NAS address %q is not %d.%d.%d.1", c.NASAddress, base[0], base[1], base[2])
	}
	cl := net.ParseIP(c.ClientAddress).To4()
	if cl == nil || !ipnet.Contains(cl) || cl[3] < 2 || cl[3] > 254 {
		return bad("this device's address %q is not a host 2-254 of %s", c.ClientAddress, c.Subnet)
	}
	if c.Port < 1 || c.Port > 65535 {
		return bad("port %d", c.Port)
	}
	// 0 means "use the default" (1280 / 25).
	if c.MTU != 0 && (c.MTU < 576 || c.MTU > 1500) {
		return bad("MTU %d", c.MTU)
	}
	if c.Keepalive < 0 || c.Keepalive > 600 {
		return bad("keepalive %d", c.Keepalive)
	}
	return nil
}

// downOutcome is what `down` may do with the pid file.
type downOutcome int

const (
	downStale   downOutcome = iota // no such process / garbage: the file is stale
	downSignal                     // the process is this program: stop it
	downForeign                    // a live process, but not this program
)

// decideDown decides what `down` may do with the pid file. It signals only a
// process whose executable is this very program: the pid file goes stale when
// `up` is killed without cleaning up, and the number may belong to anything
// by now. exe is what /proc/<pid>/exe resolved to (symlinks evaluated), exeErr
// the failure to resolve it, own this program's path (also resolved). The pid
// is returned whenever a process holds the number.
func decideDown(pidText, exe string, exeErr error, own string) (int, downOutcome) {
	pid, err := strconv.Atoi(strings.TrimSpace(pidText))
	if err != nil || pid <= 1 {
		return 0, downStale
	}
	if errors.Is(exeErr, os.ErrNotExist) || errors.Is(exeErr, syscall.ESRCH) {
		return 0, downStale
	}
	if exeErr != nil || exe == "" || own == "" || strings.HasSuffix(exe, " (deleted)") || exe != own {
		return pid, downForeign
	}
	return pid, downSignal
}

// uapiConfig is the wireguard-go configuration for the tunnel to the NAS.
// extraAllowed adds networks to route into the tunnel; only tests use it (to
// show that the NAS forwards nothing).
func uapiConfig(c Config, endpoint string, extraAllowed []string) (string, error) {
	priv, err := hexKey(c.PrivateKey)
	if err != nil {
		return "", errors.New("the stored private key is unusable: pair again")
	}
	pub, err := hexKey(c.NASPublicKey)
	if err != nil {
		return "", errors.New("the stored NAS key is unusable: pair again")
	}
	if _, _, err := net.ParseCIDR(c.Subnet); err != nil {
		return "", errors.New("the stored network is unusable: pair again")
	}
	// wireguard-go takes an address, not a name: resolve it here.
	addr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return "", fmt.Errorf("%q is not an endpoint (host:port)", endpoint)
	}
	endpoint = addr.String()
	if err := validatePairing(c); err != nil {
		return "", err
	}
	keepalive := c.Keepalive
	if keepalive <= 0 {
		keepalive = 25
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\nreplace_peers=true\npublic_key=%s\nendpoint=%s\npersistent_keepalive_interval=%d\nreplace_allowed_ips=true\nallowed_ip=%s\n",
		priv, pub, endpoint, keepalive, c.Subnet)
	for _, extra := range extraAllowed {
		if _, _, err := net.ParseCIDR(extra); err != nil {
			return "", fmt.Errorf("%q is not a network", extra)
		}
		fmt.Fprintf(&b, "allowed_ip=%s\n", extra)
	}
	return b.String(), nil
}

// chooseEndpoint picks where to send WireGuard packets: what the user said,
// else the address pairing was done with (it is reachable — pairing just
// used it), else the first address the NAS listed.
func chooseEndpoint(c Config, override string) (string, error) {
	if override != "" {
		return override, nil
	}
	if u, err := url.Parse(c.NAS); err == nil && u.Hostname() != "" {
		return net.JoinHostPort(u.Hostname(), strconv.Itoa(c.Port)), nil
	}
	if len(c.Endpoints) > 0 {
		return c.Endpoints[0], nil
	}
	return "", errors.New("no address to connect to: give one with --endpoint host:port")
}

// TunnelStatus is what `status` shows.
type TunnelStatus struct {
	Endpoint      string
	LastHandshake time.Time // zero: none yet
	Rx, Tx        int64
}

// parseStatus reads wireguard-go's answer to "get=1".
func parseStatus(get string) TunnelStatus {
	var st TunnelStatus
	for _, line := range strings.Split(get, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "endpoint":
			st.Endpoint = v
		case "last_handshake_time_sec":
			if n, _ := strconv.ParseInt(v, 10, 64); n > 0 {
				st.LastHandshake = time.Unix(n, 0)
			}
		case "rx_bytes":
			st.Rx, _ = strconv.ParseInt(v, 10, 64)
		case "tx_bytes":
			st.Tx, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	return st
}

// staleAfter: WireGuard shakes hands again at least every two minutes while
// traffic (or the keepalive) flows; three minutes without one is a dead tunnel.
const staleAfter = 3 * time.Minute

func statusLine(st TunnelStatus, now time.Time) string {
	switch {
	case st.LastHandshake.IsZero():
		return fmt.Sprintf("no handshake yet with %s — the NAS did not answer (wrong address, port blocked, or this device was removed)", st.Endpoint)
	case now.Sub(st.LastHandshake) > staleAfter:
		return fmt.Sprintf("stale: last handshake %s ago with %s — the NAS stopped answering", now.Sub(st.LastHandshake).Round(time.Second), st.Endpoint)
	}
	return fmt.Sprintf("direct to %s, handshake %s ago, received %d bytes, sent %d bytes",
		st.Endpoint, now.Sub(st.LastHandshake).Round(time.Second), st.Rx, st.Tx)
}

var (
	errTunnelDown = errors.New("the tunnel is not up (start it with `nimolink up`)")
	errNeedRoot   = errors.New("permission denied: the tunnel belongs to root, run this command with sudo")
)

// classifyControlErr turns a failure to reach the running tunnel (dialling its
// control socket, or signalling its process) into a message: "not up" only
// when nothing is there, "run as root" on a permission error, and any other
// error as itself.
func classifyControlErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, os.ErrNotExist), errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, syscall.ESRCH):
		return errTunnelDown
	case errors.Is(err, os.ErrPermission), errors.Is(err, syscall.EPERM), errors.Is(err, syscall.EACCES):
		return errNeedRoot
	}
	return err
}

// writePidFile writes the pid through a fresh temporary file renamed over
// path, so a link planted at path is replaced, never followed.
func writePidFile(path string, pid int) (err error) {
	f, err := os.CreateTemp(filepath.Dir(path), ".nimolink-pid-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if _, err = f.WriteString(strconv.Itoa(pid)); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Chmod(0o644); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
