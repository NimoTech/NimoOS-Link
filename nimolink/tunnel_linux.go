//go:build linux

package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/NimoTech/NimoOS-Link/nimolink/direct"
)

const pidFile = "/run/nimolink.pid"

// pathFile says how the running tunnel reaches the NAS ("<type> <endpoint>").
// A variable for tests.
var pathFile = "/run/nimolink.path"

func ipCmd(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return nil
}

// runUp brings the tunnel up and stays in the foreground until a signal.
func runUp(c Config, endpoint string, forced bool, extraAllowed []string, trace io.Writer) error {
	if os.Geteuid() != 0 {
		return errors.New("`nimolink up` creates a network interface: run it as root")
	}
	conf, err := uapiConfig(c, endpoint, extraAllowed)
	if err != nil {
		return err
	}
	mtu := c.MTU
	if mtu <= 0 {
		mtu = 1280
	}
	tdev, err := tun.CreateTUN(ifName, mtu)
	if err != nil {
		return fmt.Errorf("cannot create %s: %v", ifName, err)
	}
	level := device.LogLevelError
	if trace != nil {
		level = device.LogLevelVerbose
	}
	// One UDP port for WireGuard and STUN: the NAT maps both alike.
	bind := direct.NewBind(conn.NewDefaultBind())
	agent := direct.NewAgent(bind)
	dev := device.NewDevice(tdev, bind, device.NewLogger(level, "wireguard: "))
	defer dev.Close()
	if err := dev.IpcSet(conf); err != nil {
		return fmt.Errorf("cannot configure the tunnel: %v", err)
	}
	if err := dev.Up(); err != nil {
		return err
	}
	_, subnet, _ := net.ParseCIDR(c.Subnet)
	ones, _ := subnet.Mask.Size()
	if err := ipCmd("address", "replace", c.ClientAddress+"/"+strconv.Itoa(ones), "dev", ifName); err != nil {
		return err
	}
	if err := ipCmd("link", "set", "dev", ifName, "up"); err != nil {
		return err
	}
	for _, extra := range extraAllowed {
		if err := ipCmd("route", "replace", extra, "dev", ifName); err != nil {
			return err
		}
	}

	// `status` and `down` find the running tunnel through these.
	uapiFile, err := ipc.UAPIOpen(ifName)
	if err != nil {
		return err
	}
	listener, err := ipc.UAPIListen(ifName, uapiFile)
	if err != nil {
		return err
	}
	defer listener.Close()
	go func() {
		for {
			cn, err := listener.Accept()
			if err != nil {
				return
			}
			go dev.IpcHandle(cn)
		}
	}()
	// Without its pid file `down` cannot find this process: refuse to run
	// (the deferred closes above take the interface and device down again).
	if err := writePidFile(pidFile, os.Getpid()); err != nil {
		return fmt.Errorf("cannot write %s: %v", pidFile, err)
	}
	defer os.Remove(pidFile)
	clearPath() // one left by a killed `up` is not ours
	defer os.Remove(pathFile)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	via := endpoint
	if endpoint != "" {
		setPath(Path{"endpoint", endpoint})
	} else {
		via = "a path still to be found"
	}
	if !forced && c.RemoteURL != "" {
		go connectLoop(ctx, c, dev, agent, trace)
	}

	fmt.Printf("tunnel up: this device is %s, the NAS is %s (via %s)\n", c.ClientAddress, c.NASAddress, via)
	go func() {
		// Say plainly whether the NAS answered; do not leave the user guessing.
		wait := 10 * time.Second
		if endpoint == "" {
			wait = 25 * time.Second // connect has to find the path first
		}
		deadline := time.Now().Add(wait)
		for time.Now().Before(deadline) {
			if get, err := dev.IpcGet(); err == nil && !parseStatus(get).LastHandshake.IsZero() {
				fmt.Printf("connected: open http://%s/\n", c.NASAddress)
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
		get, _ := dev.IpcGet()
		fmt.Println(statusLine(parseStatus(get), time.Now()))
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	select {
	case <-sig:
	case <-dev.Wait():
	}
	fmt.Println("tunnel down")
	return nil
}

func runStatus() error {
	cn, err := net.DialTimeout("unix", "/var/run/wireguard/"+ifName+".sock", 2*time.Second)
	if err != nil {
		return classifyControlErr(err)
	}
	defer cn.Close()
	_ = cn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(cn, "get=1\n\n"); err != nil {
		return err
	}
	var b strings.Builder
	r := bufio.NewReader(cn)
	for {
		line, err := r.ReadString('\n')
		b.WriteString(line)
		if err != nil || line == "\n" {
			break
		}
	}
	fmt.Println(statusLine(parseStatus(b.String()), time.Now()))
	if p, err := os.ReadFile(pathFile); err == nil && len(strings.TrimSpace(string(p))) > 0 {
		fmt.Printf("path: %s\n", strings.TrimSpace(string(p)))
	}
	return nil
}

// inspectPid reads the pid file and decides what it points at.
func inspectPid() (string, int, downOutcome, error) {
	b, err := os.ReadFile(pidFile)
	if err != nil {
		return "", 0, downStale, err
	}
	own, err := os.Executable()
	if err != nil {
		return "", 0, downStale, err
	}
	if r, err := filepath.EvalSymlinks(own); err == nil {
		own = r
	}
	// Only signal a process that is this program: the pid file can be stale.
	exe, exeErr := "", error(nil)
	if pid, perr := strconv.Atoi(strings.TrimSpace(string(b))); perr == nil && pid > 1 {
		if link, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe"); err != nil {
			exeErr = err
		} else if strings.HasSuffix(link, " (deleted)") {
			exe = link
		} else if r, err := filepath.EvalSymlinks(link); err != nil {
			exe = link
		} else {
			exe = r
		}
	}
	if errors.Is(exeErr, os.ErrPermission) {
		return "", 0, downStale, errNeedRoot
	}
	pid, outcome := decideDown(string(b), exe, exeErr, own)
	return string(b), pid, outcome, nil
}

func init() {
	// The tunnel is up when the pid file names a live nimolink process. When
	// that cannot be told (no permission), pairing is not blocked.
	tunnelRunning = func() bool {
		_, _, outcome, err := inspectPid()
		return err == nil && outcome == downSignal
	}
}

func runDown() error {
	_, pid, outcome, err := inspectPid()
	if err != nil {
		return classifyControlErr(err)
	}
	switch outcome {
	case downStale:
		_ = os.Remove(pidFile)
		return errTunnelDown
	case downForeign:
		return fmt.Errorf("process %d holds %s but was started from a different or replaced binary: stop it with `kill %d` if it is the tunnel", pid, pidFile, pid)
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			_ = os.Remove(pidFile)
		}
		return classifyControlErr(err)
	}
	return nil
}

var (
	pathMu  sync.Mutex
	curPath Path
)

func currentPath() Path {
	pathMu.Lock()
	defer pathMu.Unlock()
	return curPath
}

// clearPath forgets any path, in this process and on disk.
func clearPath() {
	pathMu.Lock()
	curPath = Path{}
	pathMu.Unlock()
	_ = os.Remove(pathFile)
}

// setPath records the path for this process and for `status`.
func setPath(p Path) {
	pathMu.Lock()
	curPath = p
	pathMu.Unlock()
	_ = os.WriteFile(pathFile, []byte(p.Type+" "+p.Endpoint+"\n"), 0o644)
}

// connectLoop finds the best path and keeps it: at once, then every five
// minutes, when this machine's addresses change (checked every 5 s), and when
// the current path stops answering (no handshake within pathStaleAfter).
func connectLoop(ctx context.Context, c Config, dev *device.Device, agent *direct.Agent, trace io.Writer) {
	api := connectAPI(c, trace)
	var skip netip.Prefix
	if _, subnet, err := net.ParseCIDR(c.Subnet); err == nil {
		skip, _ = netip.ParsePrefix(subnet.String())
	}
	backoff := 10 * time.Second
	next := time.Now()
	lastAddrs := addrSnapshot()
	wasAlive := false
	for {
		alive := handshakeFresh(dev, pathStaleAfter(c.Keepalive))
		died := wasAlive && !alive
		wasAlive = alive
		addrs := addrSnapshot()
		changed := addrs != lastAddrs
		if attemptDue(time.Now(), next, died, changed) {
			lastAddrs = addrs
			cur := currentPath()
			found, curAnswered, err := findPath(ctx, c, api, agent, listenPort(dev), skip, cur, changed, trace)
			switch {
			case ctx.Err() != nil:
				return
			case errors.Is(err, ErrDeviceRemoved):
				fmt.Println(err)
				dev.Close() // `up` ends: there is nothing to retry
				return
			case errors.Is(err, ErrNoConnect):
				fmt.Println(err)
				next = time.Now().Add(time.Hour) // an older NAS: stay on pairing's endpoint
			case err != nil:
				fmt.Printf("no direct path yet (%v); trying again in %s\n", err, backoff)
				next = time.Now().Add(backoff)
				if backoff *= 2; backoff > 5*time.Minute {
					backoff = 5 * time.Minute
				}
			default:
				backoff = 10 * time.Second
				next = time.Now().Add(5 * time.Minute)
				if shouldSwitch(cur, aliveForSwitch(alive, changed, curAnswered), found) {
					if err := dev.IpcSet(endpointConfig(c, found.Endpoint)); err == nil {
						setPath(found)
						fmt.Printf("path: %s %s\n", found.Type, found.Endpoint)
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

// findPath runs connect and the checks. With recheck it also asks whether
// cur still answers in this session (after a network change).
func findPath(ctx context.Context, c Config, api *API, agent *direct.Agent, port uint16, skip netip.Prefix, cur Path, recheck bool, trace io.Writer) (Path, bool, error) {
	cands := direct.SystemCandidates(port, skip)
	if srv := stunServerFor(c); srv != "" {
		if ap, err := resolveUDP4(srv); err == nil {
			rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			if refl, err := agent.Reflexive(rctx, ap); err == nil {
				cands = append(cands, direct.Candidate{Type: "stun", Addr: refl.String()})
			}
			cancel()
		}
	}
	res, err := api.Connect(c.DeviceToken, cands)
	if err != nil {
		return Path{}, false, err
	}
	key, err := base64.RawURLEncoding.DecodeString(res.CheckKey)
	if err != nil || len(key) == 0 {
		return Path{}, false, errors.New("connect: unusable check key")
	}
	agent.SetSession(res.Session, key)
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	won, err := agent.Check(cctx, res.Candidates, res.Session, key)
	if trace != nil {
		fmt.Fprintf(trace, "checks: offered %v, NAS %v -> %+v %v\n", cands, res.Candidates, won, err)
	}
	if err != nil {
		return Path{}, false, err
	}
	answered := false
	if recheck && cur.Endpoint != "" {
		if cur.Endpoint == won.Addr {
			answered = true
		} else {
			rctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
			_, err := agent.Check(rctx, []direct.Candidate{{Type: cur.Type, Addr: cur.Endpoint}}, res.Session, key)
			cancel()
			answered = err == nil
		}
	}
	return Path{won.Type, won.Addr}, answered, nil
}

func listenPort(dev *device.Device) uint16 {
	get, err := dev.IpcGet()
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(get, "\n") {
		if v, ok := strings.CutPrefix(line, "listen_port="); ok {
			p, _ := strconv.Atoi(v)
			return uint16(p)
		}
	}
	return 0
}

func handshakeFresh(dev *device.Device, d time.Duration) bool {
	get, err := dev.IpcGet()
	if err != nil {
		return false
	}
	hs := parseStatus(get).LastHandshake
	return !hs.IsZero() && time.Since(hs) < d
}

func addrSnapshot() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	var out []string
	for _, a := range addrs {
		out = append(out, a.String())
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func resolveUDP4(hostport string) (netip.AddrPort, error) {
	a, err := net.ResolveUDPAddr("udp4", hostport)
	if err != nil {
		return netip.AddrPort{}, err
	}
	ap := a.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
}
