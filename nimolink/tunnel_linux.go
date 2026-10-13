//go:build linux

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

const pidFile = "/run/nimolink.pid"

func ipCmd(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return nil
}

// runUp brings the tunnel up and stays in the foreground until a signal.
func runUp(c Config, endpoint string, extraAllowed []string, trace io.Writer) error {
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
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(level, "wireguard: "))
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

	fmt.Printf("tunnel up: this device is %s, the NAS is %s (via %s)\n", c.ClientAddress, c.NASAddress, endpoint)
	go func() {
		// Say plainly whether the NAS answered; do not leave the user guessing.
		deadline := time.Now().Add(10 * time.Second)
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
