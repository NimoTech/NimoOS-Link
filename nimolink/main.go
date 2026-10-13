package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"golang.org/x/term"
)

const usage = `nimolink — reference client for NimoLink direct connections

  nimolink pair <NAS address> [-user NAME] [-name DEVICE NAME]   pair with a NAS (on the home network)
  nimolink pair <NAS address> -replace                            pair again and remove the old device from the NAS
  nimolink up [-endpoint HOST:PORT]                               connect (needs root; stays in the foreground)
  nimolink down                                                   disconnect
  nimolink status                                                 show the state of the tunnel

  --trace before the command prints every request and answer (secrets hidden).
  The password is asked for, or read from NIMOLINK_PASSWORD.
`

// stderrW is where warnings go (replaced in tests).
var stderrW io.Writer = os.Stderr

// stdoutW is where the result goes (replaced in tests).
var stdoutW io.Writer = os.Stdout

// tunnelRunning says whether a nimolink tunnel is up on this machine
// (replaced in tests).
var tunnelRunning = func() bool { return false }

func fail(err error) {
	fmt.Fprintln(os.Stderr, "nimolink:", err)
	os.Exit(1)
}

func readPassword() (string, error) {
	if p := os.Getenv("NIMOLINK_PASSWORD"); p != "" {
		return p, nil
	}
	fmt.Fprint(os.Stderr, "Password: ")
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return string(b), err
}

func cmdPair(args []string, trace io.Writer) error {
	fs := flag.NewFlagSet("pair", flag.ExitOnError)
	user := fs.String("user", "", "account name on the NAS")
	name := fs.String("name", "", "what to call this device in the NAS's device list")
	replace := fs.Bool("replace", false, "pair again although this device is already paired, and remove the old device from the NAS")
	if len(args) == 0 {
		return fmt.Errorf("which NAS? usage: nimolink pair <NAS address>")
	}
	base, err := normalizeBase(args[0])
	if err != nil {
		return err
	}
	_ = fs.Parse(args[1:])
	// Before asking for anything or registering a device: can the result be kept?
	if err := preflightConfigDir(); err != nil {
		return err
	}
	// An existing pairing must not be silently stranded on the NAS.
	var old *Config
	switch prev, err := loadConfig(); {
	case err == nil:
		if tunnelRunning() {
			return fmt.Errorf("the tunnel is up: run `nimolink down` first, then pair again")
		}
		if !*replace {
			return fmt.Errorf("this device is already paired with %s as device id %d: `nimolink pair <NAS address> -replace` pairs again (and removes the old device from the NAS)", prev.NAS, prev.DeviceID)
		}
		old = &prev
	default:
		// Nothing saved, or a file that is not a usable pairing: there is no
		// old device id worth protecting. Anything else (an untrusted
		// directory, an unreadable file) still stops here.
		var soft *noUsableConfig
		if !errors.As(err, &soft) {
			return err
		}
		if tunnelRunning() {
			return fmt.Errorf("the tunnel is up: run `nimolink down` first, then pair again")
		}
	}
	if *user == "" {
		fmt.Fprint(os.Stderr, "User name: ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		*user = strings.TrimSpace(line)
	}
	if *name == "" {
		if h, err := os.Hostname(); err == nil {
			*name = h
		}
	}
	pass, err := readPassword()
	if err != nil {
		return err
	}
	api := &API{Base: base, HTTP: newHTTPClient(), Trace: trace}
	token, err := api.Login(*user, pass)
	if err != nil {
		return err
	}
	priv, pub, err := newKeyPair()
	if err != nil {
		return err
	}
	res, err := api.Pair(token, pub, *name, runtime.GOOS)
	if err != nil {
		return err
	}
	c := Config{NAS: base, Username: *user, DeviceID: res.DeviceID, DeviceToken: res.DeviceToken, PrivateKey: priv,
		NASPublicKey: res.NASPublicKey, NASAddress: res.NASAddress, ClientAddress: res.ClientAddress, Subnet: res.Subnet,
		Port: res.Port, Endpoints: res.Endpoints, RemoteURL: res.RemoteURL, Keepalive: res.Keepalive, MTU: res.MTU}
	if err := savePairing(api, token, c); err != nil {
		return err
	}
	fmt.Fprintf(stdoutW, "paired: this device is %s on the NAS's network %s. Run `nimolink up` to connect.\n", c.ClientAddress, c.Subnet)
	// The new pairing is saved; only now give up the old device. A device id
	// from a different NAS means nothing on this one.
	if old != nil && old.NASPublicKey == c.NASPublicKey && old.DeviceID != c.DeviceID {
		if err := api.RevokeDevice(token, old.DeviceID); err != nil {
			fmt.Fprintf(stderrW, "warning: the new pairing works, but the old device (id %d) could not be removed from the NAS (%v): remove it in the panel's device list\n", old.DeviceID, err)
		}
	}
	return nil
}

// savePairing validates and saves a pairing the NAS has already registered.
// If that fails the device would sit unusable in the NAS's limited client
// list (the private key is lost), so it is removed again with the access token
// still in hand.
func savePairing(api *API, token string, c Config) error {
	err := validatePairing(c)
	if err == nil {
		err = c.save()
	}
	if err == nil {
		return nil
	}
	if rerr := api.RevokeDevice(token, c.DeviceID); rerr != nil {
		return fmt.Errorf("%v; the NAS registered this device (id %d) but it could not be removed again (%v): remove it in the panel's device list", err, c.DeviceID, rerr)
	}
	return fmt.Errorf("%v; the device the NAS registered (id %d) was removed again", err, c.DeviceID)
}

func cmdUp(args []string, trace io.Writer) error {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	endpoint := fs.String("endpoint", "", "HOST:PORT to reach the NAS's tunnel on")
	extra := fs.String("test-allowed-ips", "", "testing only: extra networks to send into the tunnel, comma-separated")
	_ = fs.Parse(args)
	c, err := loadConfig()
	if err != nil {
		return err
	}
	ep, err := chooseEndpoint(c, *endpoint)
	if err != nil {
		return err
	}
	var extras []string
	if *extra != "" {
		extras = strings.Split(*extra, ",")
	}
	return runUp(c, ep, extras, trace)
}

func main() {
	args := os.Args[1:]
	var trace io.Writer
	if len(args) > 0 && args[0] == "--trace" {
		trace, args = os.Stderr, args[1:]
	}
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch args[0] {
	case "pair":
		err = cmdPair(args[1:], trace)
	case "up":
		err = cmdUp(args[1:], trace)
	case "down":
		err = runDown()
	case "status":
		err = runStatus()
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fail(err)
	}
}
