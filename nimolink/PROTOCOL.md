# NimoLink direct connections: the client's side of the protocol

This is what `nimolink` does to reach a NimoOS NAS over WireGuard: directly
when it can, and through the relay (§8) when no direct path answers. It is
written for people building another client (the iOS app first), and the
command-line client in this directory behaves as it says. Where the two
disagree, that is a bug in one of them.

## 1. Overview

1. **Pair, at home** (§2): sign in with the account's password, send a fresh
   WireGuard public key, get back the tunnel settings and a device token.
   Pairing only works from the NAS's home network.
2. **Bring the tunnel up** (§3): one WireGuard peer, the NAS, carrying only
   the tunnel's /24. Start on pairing's endpoint.
3. **Find the best path** (§4–§7): from anywhere, call `connect` through the
   NAS's remote address with this machine's candidate addresses, check the
   NAS's candidates with signed STUN, point WireGuard at the first that
   answers. Repeat when the network changes or the path dies.
4. **Fall back to the relay** (§8) while no direct path answers: WireGuard
   in frames over TLS to the remote address.

Through the tunnel the client reaches the NAS itself (`nas_address`, every
port) and nothing else: the NAS forwards nothing to the home network or to
containers. There is no DNS: use the address, e.g. `http://100.91.200.1/`.

## 2. Pairing

Over plain HTTP(S) to the NAS's address on the home network (what the user
types: an IP address, or `http://host`). Do not follow redirects: tokens must
not travel to another host.

1. `POST /v1/users/login`, body `{"username": "...", "password": "..."}`.
   Answer `200` with `data.token.access_token`. At home the NAS never asks
   for a second factor; if the answer has `data.mfa_required: true`, the
   client is not at home: say so. `429` means too many attempts: wait.
2. Make a WireGuard key pair (X25519; the private key is 32 random bytes,
   clamped; both base64, standard alphabet with padding). The private key
   never leaves the device.
3. `POST /v1/gateway/direct/pair` with `Authorization: <access token>` (bare
   or `Bearer `; never in the URL), body
   `{"public_key": "<base64>", "name": "<shown in the device list>", "platform": "ios"}`
   (at most 4 KiB). Answer `200` (`Cache-Control: no-store`):

```json
{"success": 200, "message": "ok", "data": {
  "device_id": 30,
  "device_token": "<shown once>",
  "nas_public_key": "19HFkGHISHGYszxevfABq7d8R5v66VLu3OcJTG1q5Hs=",
  "nas_address": "100.91.200.1",
  "client_address": "100.91.200.2",
  "subnet": "100.91.200.0/24",
  "port": 51900,
  "endpoints": ["192.168.1.118:51900"],
  "remote_url": "https://k7f3x2ab2m.relay-test.nimotech.ai",
  "keepalive": 25,
  "mtu": 1280,
  "stun_server": "link.relay-test.nimotech.ai:3478"}}
```

4. Check the answer before using it. `device_id` must be a positive
   integer; an answer without one registered nothing and is simply refused.
   Then refuse it, and remove that device again (step 6), if any of these
   fails: `subnet` is an IPv4 /24 inside
   `100.64.0.0/10` without host bits; `nas_address` is its `.1`;
   `client_address` is a host 2–254 in it; `port` is 1–65535; `mtu` is 0 or
   576–1500 (0: 1280); `keepalive` is 0–600 (0: 25); `nas_public_key`
   decodes (standard base64, with padding) to exactly 32 bytes;
   `device_token` is not empty.
5. Save everything, with the private key and the device token, where only
   this user can read it. `remote_url` may be empty (remote access not yet
   registered): then only home connections work. Without `stun_server`, use
   the remote address's host on port 3478.
6. The access token is only needed for pairing and for removing a device:
   `DELETE /v1/users/remote/devices/<device_id>` with `Authorization`
   (what the panel's device list does). Pairing again on the same device
   should remove the old device after the new pairing is saved.

Errors (body `{"success": <HTTP status>, "message": "<CODE>"}`):

| Status | Code | Meaning |
|---|---|---|
| 400 | `BAD_REQUEST`, `KEY_INVALID` | body malformed; not a WireGuard public key |
| 401 | `TOKEN_REQUIRED`, `TOKEN_INVALID` | no or no live access token: sign in again |
| 403 | `LAN_ONLY` | not on the home network |
| 404 | `DIRECT_OFF` | remote access is off on the NAS (Settings → Remote access) |
| 409 | `DIRECT_UNSUPPORTED` | the NAS's system has no WireGuard |
| 409 | `KEY_EXISTS` | this public key is already paired |
| 409 | `NO_ADDRESS` | 253 clients already: remove one |
| 503 | `AUTH_UNAVAILABLE` | the NAS cannot check accounts right now: retry |

The device token is valid for 400 days and every successful `connect`
renews it. It stops working when the device is removed and when the
account's password changes: then the user pairs again, at home.

## 3. The tunnel

| WireGuard setting | Value |
|---|---|
| Interface address | `client_address`/24 |
| MTU | `mtu` (1280) |
| Listen port | any; keep it for the session (§4) |
| Peer | one: `nas_public_key` |
| Allowed IPs | `subnet` only. Do not route anything else (no default route) |
| Persistent keepalive | `keepalive` (25 s) |
| Endpoint at start | the address pairing used, on `port`; else the first of `endpoints` |
| Preshared key, DNS | none |

The NAS sends keepalives every 10 s to a client it reaches over the internet.
When a path counts as dead, and what the client does then, is in §7 and §9.
(`nimolink status` calls a tunnel stale after 3 minutes without a handshake;
that is only a label for people, not the client's timeout.)

## 4. One UDP port for everything

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
with the key of a live session (§6) and is not a public STUN server.

## 5. `POST /v1/gateway/direct/connect`

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
  unique-local IPv6 address) or `stun` (what the STUN service saw, §7).
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
| 404 | `DIRECT_OFF` | remote access off / tunnel not running | retry later |
| 404 | any other (an older NAS without connect) | no connect here | keep the pairing endpoint; try again in an hour |
| 409 | `DIRECT_UNAVAILABLE` | no raw sockets on the NAS: no STUN there | home connections only |
| 429 | `RATE_LIMITED` | over 12 calls per device, 48 per visitor address, or 48 device-token checks per visitor address a minute | back off |
| 503 | `BUSY`, `AUTH_UNAVAILABLE` | NAS busy / user service down | retry later |

## 6. Signed connectivity checks

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

## 7. Timing

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

## 8. The relay fallback

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
  time in §7, or, after an address change, no answer in that round), the
  client opens a fallback connection and points WireGuard at the relay
  endpoint first (usable within about a second), and looks for a direct path
  as in §7. When starting from pairing's endpoint it first gives that
  endpoint 5 s to complete a handshake: at home it does, and the relay is
  not used. Without a handshake after 1 s it already dials the fallback
  connection meanwhile, so that away from home the relay is ready when the
  5 s are up; a connection dialed when the endpoint then answers after all
  is closed unused.
- WireGuard starts a handshake at most every 5 s per peer, and the last one
  has usually just gone to the dead path; merely changing the endpoint then
  waits for the next retry (in the run in §10, 4 s). So when moving onto the
  relay the client removes the NAS peer and adds it again in one
  configuration call (`remove=true`, then the same `public_key` with the
  relay endpoint, keepalive and allowed IPs): a new peer has no handshake
  history and, its keepalive switched on, shakes hands at once. The old
  session is lost, which costs nothing since its path is dead.
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

## 9. Errors and states at a glance

| Where | Answer | Client does |
|---|---|---|
| login | `mfa_required` | not at home: pair at home |
| pair | see §2 | |
| connect | `401` (`CLIENT_INVALID` …) | the device was removed or the password changed: stop, pair again |
| connect | `403 REMOTE_AUTH_REQUIRED`, or `404` other than `DIRECT_OFF` | older NAS: stay on pairing's endpoint, try again in an hour |
| connect | `403 REMOTE_OR_VPN_ONLY` | at home: pairing's endpoints serve |
| connect | `404 DIRECT_OFF`, `503`, `429`, network error | retry: 10 s, doubling to 5 min |
| checks | nothing answered in 10 s | use the relay (§8), retry as above |
| relay | handshake refused with `no_application_protocol`, or another protocol negotiated | older NAS: no relay for an hour |
| relay | status `1` | as connect's `401` |
| relay | status `2`, any other dial or handshake failure (timeout, reset, certificate), connection lost | reopen: 1 s, doubling to 30 s |
| tunnel | at start: no handshake on pairing's endpoint within 5 s (the fallback is dialed from 1 s on) | use the relay (§8) while looking (§7) |
| tunnel | later: no handshake for 120 s + keepalive + 15 s (160 s by default) | the path is dead: relay, and look again (§7) |

## 10. Real runs (`nimolink --trace up`)

### Direct, through two NATs

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

### Pairing, then the relay (2026-10-19)

From the end-to-end test on the NAS host (`e2e/netns.sh` with `RELAY=1`,
`KEEP_TRACE=1`): the client sits in a network namespace on a test home network
(`10.199.0.0/24`), pairs there, and is then cut off from all UDP; only the
relay is reachable. Secrets are hidden by `--trace`; the login answer is cut
to the token, the NAS's public address is replaced with a documentation
address and its remote address's name with an example one. Lines without `>`/`<` are the client's own output, in order.

Pairing:

```
> POST /v1/users/login
> {"password":"<hidden>","username":"nimoos"}
< 200
< {"data":{"token":{"access_token":"<hidden>","expires_at":1792478224,"refresh_token":"<hidden>"},"user":{…}},"message":"ok","success":200}
> POST /v1/gateway/direct/pair
> {"name":"e2e-netns","platform":"linux","public_key":"h3+JGyGxEMf7n79w60b/d/KpOjBLMwYBDDWmjpbt1Ug="}
< 200
< {"data":{"client_address":"100.91.200.2","device_id":31,"device_token":"<hidden>","endpoints":["192.168.1.118:51900","10.199.0.1:51900"],"keepalive":25,"mtu":1280,"nas_address":"100.91.200.1","nas_public_key":"19HFkGHISHGYszxevfABq7d8R5v66VLu3OcJTG1q5Hs=","port":51900,"remote_url":"https://k7f3x2ab2m.relay-test.nimotech.ai","stun_server":"link.relay-test.nimotech.ai:3478","subnet":"100.91.200.0/24"},"message":"ok","success":200}
paired: this device is 100.91.200.2 on the NAS's network 100.91.200.0/24. Run `nimolink up` to connect.
```

`up` with no UDP: the pairing endpoint gets its 5 s, then the relay carries
the tunnel (0:07), and the first handshake completes at WireGuard's next
retry (0:11). Connect still runs every round, through the remote address;
its checks cannot answer without UDP:

```
tunnel up: this device is 100.91.200.2, the NAS is 100.91.200.1 (via 10.199.0.1:51900)
fallback: dialing k7f3x2ab2m.relay-test.nimotech.ai:443
fallback: status 0
path: relay k7f3x2ab2m.relay-test.nimotech.ai
connected: open http://100.91.200.1/
> POST /v1/gateway/direct/connect
> {"candidates":[{"addr":"10.199.0.2:51226","type":"lan"}]}
< 200
< {"data":{"candidates":[{"addr":"192.168.1.118:51900","type":"lan"},{"addr":"10.199.0.1:51900","type":"lan"},{"addr":"203.0.113.7:33071","type":"stun"}],"check_key":"<hidden>","expires_in":60,"nas_public_key":"19HFkGHISHGYszxevfABq7d8R5v66VLu3OcJTG1q5Hs=","session":"iCy8Emke81TVQlg11WNzvQ"},"message":"ok","success":200}
checks: offered [{lan 10.199.0.2:51226}], NAS [{lan 192.168.1.118:51900} {lan 10.199.0.1:51900} {stun 203.0.113.7:33071}] -> {Type: Addr:} no address of the NAS answered
no direct path yet (no address answered: no address of the NAS answered); trying again in 10s
```

UDP let through again and an address added: the next round finds the home
address and leaves the relay (the connection stays open for 30 s):

```
> {"candidates":[{"addr":"10.199.0.2:51226","type":"lan"},{"addr":"10.199.0.3:51226","type":"lan"}]}
< 200
checks: offered [{lan 10.199.0.2:51226} {lan 10.199.0.3:51226}], NAS [{lan 192.168.1.118:51900} {lan 10.199.0.1:51900} {stun 203.0.113.7:33071}] -> {Type:lan Addr:10.199.0.1:51900} <nil>
path: lan 10.199.0.1:51900
```

UDP blocked again and the address removed: that round's checks fail and the
old path does not answer, so the tunnel goes back to the relay connection
still open from before (no new dial):

```
checks: offered [{lan 10.199.0.2:51226}], NAS […] -> {Type: Addr:} no address of the NAS answered
no direct path yet (no address answered: no address of the NAS answered); trying again in 10s
path: relay k7f3x2ab2m.relay-test.nimotech.ai
```

The device removed (as from the panel's device list): the NAS closes the relay connection, the
next connect answers `401`, and `up` ends:

```
fallback: connection closed (read tcp 10.199.0.2:46688->52.15.161.48:443: read: connection reset by peer)
> POST /v1/gateway/direct/connect
< 401
< {"code":"CLIENT_INVALID","message":"CLIENT_INVALID","success":401}
this device was removed from the NAS: pair it again at home
tunnel down
```
