# NimoOS-Link

The device side of NimoLink, the remote-access tunnel of [NimoOS](https://github.com/NimoTech).

A NimoOS device opens one outbound TLS connection to a relay. Visitors reach
the device at `https://<device-id>.<relay domain>`; the relay forwards the raw
TLS stream by SNI and never holds the device's certificate key, so traffic is
encrypted end to end between the visitor's browser and the device.

This module is what the device needs to talk to a relay:

- `protocol/` — device IDs, request signing (Ed25519), the PROXY v2 header that
  carries the visitor's address, and the yamux settings both ends agree on.
- `client/` — register a device, open the tunnel and accept visitor
  connections from it as a `net.Listener`, order a certificate for the
  device's host name.

It is consumed by NimoOS-Gateway (`link` package).

## Use

```go
c := &client.Client{RelayURL: "https://link.example.net", Key: deviceKey}
id, err := c.Register(ctx, deviceKey.Public().(ed25519.PublicKey))
c.ID = id
sess, err := c.DialTunnel(ctx)
ln := client.NewListener(sess, 5*time.Second)
// serve TLS on ln; every connection's RemoteAddr is the visitor's address
```

## Develop

```bash
go test -race ./...
```

Go 1.21. The only dependency is `github.com/hashicorp/yamux`.

## License

Apache-2.0, see `LICENSE`.
