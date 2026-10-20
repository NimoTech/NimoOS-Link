//go:build linux

package main

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// wgPair is a client and a "NAS" wireguard-go device on loopback. The client
// starts pointed at a port where nothing answers, so its first handshake
// goes nowhere, as when the pairing endpoint is out of reach.
func wgPair(t *testing.T) (client *device.Device, c Config, nasAddr string) {
	t.Helper()
	cPriv, cPub, _ := newKeyPair()
	nPriv, nPub, _ := newKeyPair()
	hex := func(k string) string { h, _ := hexKey(k); return h }
	quiet := device.NewLogger(device.LogLevelSilent, "")
	up := func(conf string) *device.Device {
		d := device.NewDevice(tuntest.NewChannelTUN().TUN(), conn.NewDefaultBind(), quiet)
		t.Cleanup(d.Close)
		if err := d.IpcSet(conf); err != nil {
			t.Fatal(err)
		}
		if err := d.Up(); err != nil {
			t.Fatal(err)
		}
		return d
	}
	nas := up(fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nallowed_ip=100.64.7.5/32\n", hex(nPriv), hex(cPub)))
	nasAddr = fmt.Sprintf("127.0.0.1:%d", listenPort(nas))

	dead, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dead.Close() })

	c = testConfig(t)
	c.PrivateKey, c.NASPublicKey = cPriv, nPub
	client = up(fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nendpoint=%s\npersistent_keepalive_interval=25\nallowed_ip=%s\nallowed_ip=192.0.2.9/32\n",
		hex(cPriv), hex(nPub), dead.LocalAddr(), c.Subnet))
	time.Sleep(300 * time.Millisecond) // the first initiation has gone to the dead port
	return client, c, nasAddr
}

func handshakeWithin(d *device.Device, wait time.Duration) bool {
	for end := time.Now().Add(wait); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if handshakeFresh(d, time.Minute) {
			return true
		}
	}
	return false
}

// Why: pointing the peer elsewhere does not bring a handshake before
// WireGuard's 5 s retry.
func TestEndpointChangeWaitsForRetry(t *testing.T) {
	client, c, nasAddr := wgPair(t)
	if err := client.IpcSet(endpointConfig(c, nasAddr)); err != nil {
		t.Fatal(err)
	}
	if handshakeWithin(client, 1500*time.Millisecond) {
		t.Skip("wireguard-go shook hands at once after an endpoint change: freshPeerConfig is no longer needed")
	}
}

// The fix: a fresh peer shakes hands at once, and keeps its allowed IPs.
func TestFreshPeerShakesHandsAtOnce(t *testing.T) {
	client, c, nasAddr := wgPair(t)
	get, _ := client.IpcGet()
	before := allowedIPs(get)
	start := time.Now()
	if err := client.IpcSet(freshPeerConfig(c, nasAddr, before)); err != nil {
		t.Fatal(err)
	}
	if !handshakeWithin(client, time.Second) {
		t.Fatal("no handshake within 1 s of the switch")
	}
	t.Logf("handshake %v after the switch", time.Since(start).Round(time.Millisecond))
	get, _ = client.IpcGet()
	after := allowedIPs(get)
	if strings.Join(after, ",") != strings.Join(before, ",") || len(after) != 2 {
		t.Fatalf("allowed IPs %v, were %v", after, before)
	}
	if !strings.Contains(get, "persistent_keepalive_interval=25") {
		t.Fatalf("keepalive lost:\n%s", get)
	}
}
