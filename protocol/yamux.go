package protocol

import (
	"io"
	"time"

	"github.com/hashicorp/yamux"
)

// YamuxConfig is the session configuration of both tunnel ends. A ping goes
// out every 30 s; a ping unanswered for 60 s tears the session down, so a dead
// peer is noticed at most 90 s after it last answered.
func YamuxConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	c.KeepAliveInterval = 30 * time.Second
	c.ConnectionWriteTimeout = 60 * time.Second
	c.LogOutput = io.Discard
	return c
}

// RelayYamuxConfig is the relay's end of a tunnel. A stream the relay closed
// is forgotten after 10 s even if the device never acknowledges the close,
// instead of yamux's 5 minutes, which bounds the buffered state a device can pin.
//
// AcceptBacklog deliberately stays at yamux's default (256). The relay never
// accepts streams (a device that opens one has its tunnel closed), but yamux
// sizes its semaphore of outbound streams awaiting the peer's ACK with the
// same value: a backlog of 1 would make every Session.Open wait until the
// device has accepted the previous stream, serialising visitors on the
// device's round-trip time and letting a device that accepts nothing park
// every visitor goroutine inside Open.
func RelayYamuxConfig() *yamux.Config {
	c := YamuxConfig()
	c.StreamCloseTimeout = 10 * time.Second
	return c
}
