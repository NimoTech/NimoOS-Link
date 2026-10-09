package protocol

import (
	"net"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
)

func TestYamuxConfig(t *testing.T) {
	c := YamuxConfig()
	if err := yamux.VerifyConfig(c); err != nil {
		t.Fatal(err)
	}
	if !c.EnableKeepAlive || c.KeepAliveInterval != 30*time.Second || c.ConnectionWriteTimeout != 60*time.Second {
		t.Errorf("config = %+v", c)
	}
}

func TestRelayYamuxConfig(t *testing.T) {
	c := RelayYamuxConfig()
	if err := yamux.VerifyConfig(c); err != nil {
		t.Fatal(err)
	}
	if c.StreamCloseTimeout != 10*time.Second {
		t.Errorf("relay config: close timeout %v", c.StreamCloseTimeout)
	}
	// yamux sizes the semaphore of un-ACKed outbound streams with AcceptBacklog,
	// so it must cover the relay's concurrent streams per device (256); see
	// TestRelayOpensStreamsWithoutWaitingForAccept.
	if c.AcceptBacklog != 256 {
		t.Errorf("relay config: backlog %d, want 256", c.AcceptBacklog)
	}
	if !c.EnableKeepAlive || c.KeepAliveInterval != 30*time.Second || c.ConnectionWriteTimeout != 60*time.Second {
		t.Errorf("relay config lost the shared settings: %+v", c)
	}
	// The device side keeps yamux's defaults for these two.
	if d := YamuxConfig(); d.AcceptBacklog != 256 || d.StreamCloseTimeout != 5*time.Minute {
		t.Errorf("device config changed: backlog %d, close timeout %v", d.AcceptBacklog, d.StreamCloseTimeout)
	}
}

// The relay must be able to open a device's full allowance of streams even
// while the device has accepted none of them: Open must not wait for the peer.
func TestRelayOpensStreamsWithoutWaitingForAccept(t *testing.T) {
	a, b := net.Pipe()
	relay, err := yamux.Client(a, RelayYamuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	nas, err := yamux.Server(b, YamuxConfig()) // never calls Accept
	if err != nil {
		t.Fatal(err)
	}
	defer nas.Close()
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 256; i++ {
			if _, err := relay.Open(); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Open blocked waiting for the device to accept earlier streams")
	}
}
