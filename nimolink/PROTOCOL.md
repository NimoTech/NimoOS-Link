# NimoLink direct connections: the client's side of the protocol

This is what `nimolink` does to reach a NimoOS NAS over WireGuard without a
relay in the data path, and (§6) through the relay when no direct path
answers. It is written for people building another client.
Pairing (`POST /v1/gateway/link/direct/pair`) is described in the Gateway's
OpenAPI spec; this file starts after it, with a saved pairing: the device
token, the NAS's public key, the tunnel network, the WireGuard port (51900 by
default), the endpoints pairing listed, the remote address (`remote_url`) and
the relay's STUN service (`stun_server`, `host:3478`).

## 1. One UDP port for everything

The client's WireGuard socket also carries STUN. A received packet is STUN
when its first two bits are `00`, bytes 4–7 are the magic cookie
`0x2112A442` and the length in bytes 2–3 is a multiple of 4 that matches the
packet (`protocol/stun.IsMessage`); everything else goes to WireGuard. (A
WireGuard packet has its random sender index in bytes 4–7, so it looks like
STUN only by a 1-in-2³² accident whose length must also match.) STUN
therefore leaves from the same port, and through the same NAT mapping, that
WireGuard then uses.

The NAS does the same on its kernel WireGuard port: a raw socket with a BPF
filter sees only STUN addressed to the port. It answers only checks signed
with the key of a live session (§3) and is not a public STUN server.

## 2. `POST /v1/gateway/direct/connect`

Reach it through the remote address (`remote_url`) or over the tunnel itself.
At home, pairing's endpoints serve and connect answers `403
REMOTE_OR_VPN_ONLY`.

Request headers: `X-NimoLink-Device: <device token>` (not `Authorization`),
`Content-Type: application/json`. Do not follow redirects: the token must not
travel to another host. Each successful call renews the token for 400 days.

Request body (at most 4 KiB):

```json
{"candidates": [{"type": "lan", "addr": "192.168.43.5:40000"},
                {"type": "stun", "addr": "52.15.161.48:49241"}]}
```

- `type` is `lan` (an IPv4 address of this machine), `ipv6` (a global or
  unique-local IPv6 address) or `stun` (what the STUN service saw, §4).
- `addr` is `host:port`, no zone. For `lan` and `ipv6` the port is the
  client's WireGuard port; for `stun` it is the address and port exactly as
  the STUN answer's `XOR-MAPPED-ADDRESS` gave them (a NAT may change the
  port).
- At most 8. Leave out loopback, link-local, the tunnel's own network, and
  container / VM bridges (`docker*`, `br-*`, `veth*`, `virbr*`, `cni*`,
  `flannel*`): the NAS has the same `172.17.0.1` and would answer itself.

Answer `200`:

```json
{"success": 200, "message": "ok", "data": {
  "session": "3H57G0mQao0NCUTcJrEo9w",
  "check_key": "<base64url, 32 bytes>",
  "expires_in": 60,
  "nas_public_key": "19HFkGHISHGYszxevfABq7d8R5v66VLu3OcJTG1q5Hs=",
  "candidates": [{"type": "lan", "addr": "192.168.1.118:51900"},
                 {"type": "stun", "addr": "203.0.113.7:48222"}]}}
```

The NAS asks the relay's STUN service again before it answers (up to 1.5 s),
so the `stun` candidate is its mapping of now. Check that `nas_public_key` is
the key pairing saved, and drop the whole answer if it is not: it came from
another machine. `check_key` is a secret: never log it.

Errors (body `{"success": <HTTP status>, "message": "<CODE>"}`):

| Status | Code | Meaning | Client does |
|---|---|---|---|
| 400 | `BAD_REQUEST`, `BAD_CANDIDATES` | body or candidates malformed | fix the request |
| 401 | `CLIENT_INVALID` (through the remote entry), `TOKEN_INVALID`, `TOKEN_REQUIRED` | the device was removed, or the password changed | stop: pair again |
| 403 | `REMOTE_AUTH_REQUIRED` | an older NAS without connect | keep the pairing endpoint |
| 403 | `REMOTE_OR_VPN_ONLY` | called from home | use pairing's endpoints |
| 403 | `NOT_THIS_DEVICE` | over the tunnel, from another device's address | — |
| 404 | `DIRECT_OFF` (or a plain 404 from an older NAS) | remote access off / tunnel not running | retry later |
| 409 | `DIRECT_UNAVAILABLE` | no raw sockets on the NAS: no STUN there | home connections only |
| 429 | `RATE_LIMITED` | over 12 calls per device, 48 per visitor address, or 48 device-token checks per visitor address a minute | back off |
| 503 | `BUSY`, `AUTH_UNAVAILABLE` | NAS busy / user service down | retry later |

## 3. Signed connectivity checks

A check is a STUN Binding Request (RFC 8489) with:

- `USERNAME` = `session`;
- `MESSAGE-INTEGRITY` (HMAC-SHA1) keyed with the 32 bytes that
  `check_key` decodes to (base64url, no padding);
- `FINGERPRINT`, required.

A valid answer is a Binding Success Response from the very address the check
went to, with `XOR-MAPPED-ADDRESS`, `MESSAGE-INTEGRITY` with the same key and
`FINGERPRINT`. Anything else is ignored. The NAS answers at most 20 checks
per second per source address, and only for 60 s after connect.

The NAS sends the same kind of signed requests towards the client (the
punch); the client answers them the same way, which also opens its own NAT.

## 4. Timing

1. Gather: this machine's addresses (`lan`, `ipv6`), then one STUN Binding
   Request (unsigned) from the WireGuard port to `stun_server`, resent every
   400 ms for up to 2 s; its `XOR-MAPPED-ADDRESS` is the `stun` candidate.
2. `connect` with the candidates (timeout 10 s).
3. The NAS punches towards every usable offered address, and through the
   remote entry towards the visitor's own IP with each offered port, every
   200 ms for 10 s.
4. The client checks every NAS candidate at once, staggered by type (`lan`
   at 0 ms, `ipv6` at 100 ms, `stun` at 200 ms), each resent every 200 ms,
   for up to 10 s. The first valid answer wins; the others stop.
5. Point WireGuard's peer endpoint at the winner. WireGuard's own handshake
   follows from the same port.
6. Nothing answered in 10 s: retry after 10 s, doubling up to 5 minutes.

Afterwards the client runs steps 1–5 again every 5 minutes, when this
machine's addresses change (checked every 5 s), and when the current path
looks dead: no handshake for 120 s + keepalive + 15 s (160 s with the default
25 s keepalive). It moves to a new path only when the current one stopped
answering, or when the new one is better (home before internet). After an
address change the current path counts as alive only if it answered in that
round. These later rounds may call connect over the tunnel itself.

A home NAT may forget an idle UDP mapping within seconds (the test NAS's:
15–20 s), and may count only packets sent from inside as use. Keep the steps
above back to back. Once the tunnel is up, the NAS sends a WireGuard
keepalive every 10 s to a peer reached over the internet (while its
handshakes are fresh), and the client's own keepalive (25 s by default) keeps
the client's side open; lower it if the client's NAT is as quick.

## 5. A real run (`nimolink --trace up`)

From the acceptance test on 2026-10-15: client on an AWS host
(`52.15.161.48`), NAS at home behind two NATs (`203.0.113.7`), every NAT
mapping idle for 40 s beforehand; the path was found 1.4 s after start.
The pairing endpoint is not reachable from there, so the client starts on it and finds
the path in the background. The check key is hidden by `--trace`; the NAS's public address is replaced
with a documentation address.

```
tunnel up: this device is 100.91.200.2, the NAS is 100.91.200.1 (via 10.199.0.1:51900)
> POST /v1/gateway/direct/connect
> {"candidates":[{"addr":"172.31.44.8:51600","type":"lan"},{"addr":"52.15.161.48:51600","type":"stun"}]}
< 200
< {"data":{"candidates":[{"addr":"192.168.1.118:51900","type":"lan"},{"addr":"203.0.113.7:36127","type":"stun"}],"check_key":"\u003chidden\u003e","expires_in":60,"nas_public_key":"19HFkGHISHGYszxevfABq7d8R5v66VLu3OcJTG1q5Hs=","session":"_0LRJR_nQgq7jNYSjHAxRw"},"message":"ok","success":200}
checks: offered [{lan 172.31.44.8:51600} {stun 52.15.161.48:51600}], NAS [{lan 192.168.1.118:51900} {stun 203.0.113.7:36127}] -> {Type:stun Addr:203.0.113.7:36127} <nil>
path: stun 203.0.113.7:36127
connected: open http://100.91.200.1/
```

## 6. The relay fallback

When no direct path answers, WireGuard travels over TLS to the NAS's remote
address, through the relay. The relay forwards it by SNI like any visitor and
holds it to its own rate (5 Mbps each way per NAS by default); the NAS ends
the TLS.

1. TLS 1.2 or later to the remote address's host on port 443, SNI that host,
   the NAS's certificate verified as usual, and **only** `nimolink-wg/1` in
   the ALPN list. A NAS that does not know the protocol fails the handshake
   (`no_application_protocol`) or negotiates something else: it has no
   fallback.
2. Everything after the handshake is frames: a `uint16` big-endian length,
   1–65535, then that many bytes. A frame of length 0 is invalid and ends
   the connection. Constants and the codec are in `protocol`
   (`FallbackALPN`, `WriteFrame`, `ReadFrame`).
3. The client's first frame is the device token, within 10 s.
4. The NAS answers one frame of one byte, and closes after anything but 0:
   - `0`: from now on every frame, either way, is one WireGuard packet;
   - `1`: the token is no good: the device was removed (as connect's `401
     CLIENT_INVALID`);
   - `2`: not now (the NAS's user service or its WireGuard is down): retry
     later.
5. There is no keepalive of its own: WireGuard's keepalive is the traffic.
   The NAS closes a connection that carried nothing for 3 minutes, an older
   one when the same token opens a new one, and every one within 10 s of the
   device being removed.

How `nimolink` uses it. The fallback connection is a made-up endpoint inside
the WireGuard Bind (`direct.RelayEndpoint`, `127.77.0.1:9`, never on the
network): WireGuard sends to it, the Bind writes frames; frames read are
handed to WireGuard as packets from it. So any wireguard-go host can carry
the fallback without a local proxy.

- When the current path does not answer (no path yet, no handshake for the
  time in §4, or, after an address change, no answer in that round), the
  client opens a fallback connection and points WireGuard at the relay
  endpoint first (usable within about a second), and looks for a direct path
  as in §4. When starting from pairing's endpoint it first gives that
  endpoint 5 s to complete a handshake: at home it does, and no fallback
  connection is made.
- The relay ranks after every direct path: one that answers replaces it.
  From then on packets that still arrive over the fallback connection are
  dropped (they would make WireGuard roam back), and the connection is closed
  30 s later; if the direct path dies before that, the client goes back to
  it.
- A lost fallback connection while on the relay is reopened after 1 s,
  doubling up to 30 s. Status `1` ends `up` like connect's 401. A NAS without
  the fallback is not asked again for an hour.
- `nimolink status` shows `path: relay <host>`. `nimolink --trace up`
  prints the fallback's dial, status and close. `up -path=relay` uses only
  the relay, `up -path=direct` never; both are for testing.
