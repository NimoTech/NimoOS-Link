// Package protocol is the wire contract between the NimoLink relay and NimoOS
// devices: device IDs, signed control requests, the PROXY v2 header written in
// front of every relayed visitor stream, and the shared yamux settings.
//
// NimoOS-Gateway imports this package, so it must keep building with go 1.21.
package protocol

import "time"

const (
	// TunnelUpgrade is the Upgrade token of GET /v1/tunnel.
	TunnelUpgrade = "nimolink-tunnel/1"
	// AuthScheme is the Authorization scheme of signed device requests.
	AuthScheme = "NimoLink"
	// MaxClockSkew bounds |now - ts| of a signed request; it is also how long
	// the relay remembers a signature to reject replays.
	MaxClockSkew = 300 * time.Second

	signPrefix = "nimolink-v1\n"
)
