#!/usr/bin/env bash
# End-to-end check on one machine: a client in its own network namespace on
# the NAS pairs over a private "home network" link, connects, reaches the
# panel through the tunnel, is refused what a VPN client may not do, cannot
# get past the NAS, and is cut off when its device is removed.
#
#   sudo NAS_USER=<account> BIN=/path/to/nimolink bash netns.sh
#
# The account's password is asked for on the terminal (it never goes on a
# command line). Optional, for Docker apps on the NAS:
#   DOCKER_PORT=<port a bridge-network app publishes on all addresses>  must answer
#   DOCKER_LOOPBACK_PORT=<port an app publishes on 127.0.0.1 only>      must not
#   DOCKER_CONTAINER_IP=<a container's address on its bridge>           must not be routed to
# RELAY=1 runs everything over the relay fallback instead: the namespace may
# reach only the relay (its IPv4 address, through this machine's uplink) and
# sends no UDP, so the pairing endpoint cannot answer. On top it checks the
# relay's rate on a 20 MB download, the move to a direct path once UDP is let
# through again (and back), and that removing the device ends `up`. Needs the
# NAS's remote access on (a remote_url in the pairing) and iptables.
# NAT=easy or NAT=strict puts the client behind a home router of its own (a
# second namespace that translates its addresses) and has the NAS let in only
# answers on its WireGuard port, like a NAS behind a router without port
# mappings: a direct path then needs both sides to punch. A STUN service on
# this machine tells the client its address outside its router. easy maps one
# port for every destination (Linux's usual NAT): the client must move from
# the relay to a direct path. strict maps a new port for each destination
# (symmetric NAT): punching cannot work and the client must stay on the relay.
# Needs what RELAY=1 needs; the two do not go together.
# KEEP_TRACE=1 keeps the run's `nimolink --trace` output (pair.trace, up.log,
# up.trace; passwords, tokens and check keys are hidden) in a new directory
# the script makes under /tmp, private to root; it prints where.
# Do not run it with `bash -x`: that would trace the password and the token.
set -euo pipefail
: "${NAS_USER:?}" "${BIN:?path to the nimolink binary}"
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

NS=nlc HOST_IF=nlc-host HOST_IP=10.199.0.1 NS_IP=10.199.0.2
WORK="" DEVICE_ID="" TOKEN="" REVOKED=0 MADE_NS=0 MADE_LINK=0 CLIENT_STARTED=0 MADE_HOME=0
RELAY=${RELAY:-0} MADE_ETC=0 NAT_RULE=() HTTP_PID=""
NAT=${NAT:-} RNS=nlr LAN_IP=10.199.1.1 CLIENT_IP=10.199.1.2 STUN_IP=10.199.0.9 MADE_RNS=0 STUN_PID="" WG_RULE=()
GW_INI=/etc/nimoos/gateway.ini
fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "ok: $*"; }
inns() { ip netns exec "$NS" "$@"; }

for tool in python3 curl ip ss; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is required but not installed"
done
KEEP_TRACE=${KEEP_TRACE:-0}
if [ "$KEEP_TRACE" = 1 ]; then
  # Not a path the caller names: a new directory of root's, mode 0700, in
  # sticky /tmp, so nobody else can plant a link in it or swap it out.
  [ -k /tmp ] || fail "/tmp is not sticky"
  TRACE_DIR=$(mktemp -d /tmp/nimolink-e2e-trace.XXXXXX) || fail "cannot create a trace directory"
fi
case "$NAT" in
  "" | easy | strict) ;;
  *) fail "NAT must be easy or strict, not $NAT" ;;
esac
[ -z "$NAT" ] || [ "$RELAY" != 1 ] || fail "RELAY=1 and NAT do not go together"
# both reach the relay from the namespace
VIA_RELAY=0
if [ "$RELAY" = 1 ] || [ -n "$NAT" ]; then VIA_RELAY=1; fi
if [ "$VIA_RELAY" = 1 ]; then
  command -v iptables >/dev/null 2>&1 || fail "RELAY=1 and NAT need iptables"
  [ ! -e "/etc/netns/$NS" ] || fail "/etc/netns/$NS already exists"
fi

# Refuse to touch anything that already exists on this host.
netns_list=$(ip netns list 2>/dev/null || true)
links=$(ip -o link show 2>/dev/null || true)
addrs=$(ip -o -4 addr show 2>/dev/null || true)
routes=$(ip -4 route show 2>/dev/null || true)
[[ $netns_list =~ (^|$'\n')$NS([[:space:]]|$) ]] && fail "a network namespace named $NS already exists"
[[ $links =~ :[[:space:]]($HOST_IF|nlc-ns)[@:[:space:]] ]] && fail "a link named $HOST_IF or nlc-ns already exists"
[[ $addrs =~ 10\.199\.0\. || $routes =~ 10\.199\.0\. ]] && fail "10.199.0.0/24 is already in use on this host"
if [ -n "$NAT" ]; then # what only the client's router adds
  [[ $netns_list =~ (^|$'\n')$RNS([[:space:]]|$) ]] && fail "a network namespace named $RNS already exists"
  [[ $links =~ :[[:space:]](nlr-wan|nlr-lan)[@:[:space:]] ]] && fail "a link named nlr-wan or nlr-lan already exists"
  [[ $addrs =~ 10\.199\.1\. || $routes =~ 10\.199\.1\. ]] && fail "10.199.1.0/24 is already in use on this host"
fi
# `ip netns exec` does not isolate /run: a real tunnel would collide with ours.
for f in /run/nimolink.pid /var/run/wireguard/nimolink0.sock; do
  [ ! -e "$f" ] || fail "$f exists: a nimolink tunnel is running on this host; stop it first"
done

if [ -z "${NIMOLINK_PASSWORD:-}" ]; then
  [ -t 0 ] || fail "no terminal to ask the password on: run this from a terminal"
  read -rs -p "Password for $NAS_USER: " NIMOLINK_PASSWORD; echo
  [ -n "$NIMOLINK_PASSWORD" ] || fail "empty password"
fi
export NAS_USER NIMOLINK_PASSWORD


WORK=$(mktemp -d)           # mode 0700
export NIMOLINK_CONFIG="$WORK"
AUTH="$WORK/auth"           # curl header file; the token never goes on a command line

REVOKE_CODE=""
revoke() { # host side, over the private link; succeeds only on HTTP 200
  [ -n "$DEVICE_ID" ] && [ -n "$TOKEN" ] || return 1
  REVOKE_CODE=$(curl -s -m 5 -o /dev/null -w '%{http_code}' -X DELETE -H @"$AUTH" "http://$HOST_IP/v1/users/remote/devices/$DEVICE_ID") || true
  [ "$REVOKE_CODE" = 200 ]
}

cleanup() {
  trap - EXIT
  if [ -n "$DEVICE_ID" ] && [ "$REVOKED" = 0 ]; then
    if revoke; then
      echo "removed the test device $DEVICE_ID"
    else
      echo "NOTE: test device $DEVICE_ID was NOT removed (HTTP ${REVOKE_CODE:-none}, or no access token): remove it in the panel's device list" >&2
    fi
  fi
  # Only what this run created is touched. No `nimolink down` here: it acts
  # on the host-wide pid file and could stop a real tunnel.
  [ -z "$HTTP_PID" ] || kill "$HTTP_PID" 2>/dev/null || true
  [ -z "$STUN_PID" ] || kill "$STUN_PID" 2>/dev/null || true
  [ "${#NAT_RULE[@]}" = 0 ] || iptables -t nat -D POSTROUTING "${NAT_RULE[@]}" 2>/dev/null || true
  [ "${#WG_RULE[@]}" = 0 ] || iptables -D INPUT "${WG_RULE[@]}" 2>/dev/null || true
  [ "$MADE_ETC" = 0 ] || rm -rf "/etc/netns/$NS"
  if [ "$MADE_NS" = 1 ]; then
    ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
    for _ in $(seq 1 25); do
      [ -n "$(ip netns pids "$NS" 2>/dev/null)" ] || break
      sleep 0.2
    done
    ip netns pids "$NS" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    sleep 0.3
    ip netns del "$NS" 2>/dev/null || true
  fi
  # its links go with it, the host's end of the pair too
  [ "$MADE_RNS" = 0 ] || ip netns del "$RNS" 2>/dev/null || true
  [ "$MADE_LINK" = 0 ] || ip link del "$HOST_IF" 2>/dev/null || true
  if [ "$CLIENT_STARTED" = 1 ]; then
    for f in /run/nimolink.pid /var/run/wireguard/nimolink0.sock; do
      if [ -e "$f" ]; then rm -f "$f"; echo "removed leftover $f"; fi
    done
  fi
  if [ "$MADE_HOME" = 1 ] && [ -f "$WORK/gateway.ini.orig" ]; then
    if cp -p "$WORK/gateway.ini.orig" "$GW_INI" && systemctl restart nimoos-gateway; then
      echo "restored $GW_INI and restarted the Gateway"
    else
      echo "NOTE: restore $GW_INI from $WORK/gateway.ini.orig and restart nimoos-gateway" >&2
    fi
  fi
  if [ "$KEEP_TRACE" = 1 ] && [ -n "$WORK" ]; then
    for f in pair.trace up.log; do [ ! -f "$WORK/$f" ] || cp "$WORK/$f" "$TRACE_DIR/$f"; done
    [ ! -f "$WORK/trace.log" ] || cp "$WORK/trace.log" "$TRACE_DIR/up.trace"
    echo "traces kept in $TRACE_DIR (readable by root only)"
  fi
  if [ -n "$WORK" ]; then
    if [ "$MADE_HOME" = 1 ] && ! cmp -s "$WORK/gateway.ini.orig" "$GW_INI"; then
      echo "kept $WORK (it holds the original gateway.ini)" >&2
    else
      rm -rf "$WORK"
    fi
  fi
}
trap cleanup EXIT

ip netns add "$NS"; MADE_NS=1
if [ -z "$NAT" ]; then
  ip link add "$HOST_IF" type veth peer name nlc-ns; MADE_LINK=1
  ip link set nlc-ns netns "$NS"
  ip addr add "$HOST_IP/24" dev "$HOST_IF" && ip link set "$HOST_IF" up
  inns ip addr add "$NS_IP/24" dev nlc-ns
  inns ip link set nlc-ns up && inns ip link set lo up
else
  # client (nlc-ns, CLIENT_IP) -- its router (nlr-lan | nlr-wan, NS_IP) --
  # this machine (HOST_IF, HOST_IP). The NAS sees only the router's address.
  inr() { ip netns exec "$RNS" "$@"; }
  ip netns add "$RNS"; MADE_RNS=1
  ip link add "$HOST_IF" type veth peer name nlr-wan; MADE_LINK=1
  ip link set nlr-wan netns "$RNS"
  ip link add nlr-lan type veth peer name nlc-ns
  ip link set nlr-lan netns "$RNS"
  ip link set nlc-ns netns "$NS"
  ip addr add "$HOST_IP/24" dev "$HOST_IF" && ip link set "$HOST_IF" up
  inr ip addr add "$NS_IP/24" dev nlr-wan
  inr ip addr add "$LAN_IP/24" dev nlr-lan
  inr ip link set nlr-wan up && inr ip link set nlr-lan up && inr ip link set lo up
  inns ip addr add "$CLIENT_IP/24" dev nlc-ns
  inns ip link set nlc-ns up && inns ip link set lo up
  inns ip route add 10.199.0.0/24 via "$LAN_IP"
  inr sysctl -qw net.ipv4.ip_forward=1
  # From outside only answers get in, as with a home router.
  inr iptables -A FORWARD -i nlr-wan -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  inr iptables -A FORWARD -i nlr-wan -j DROP
  if [ "$NAT" = easy ]; then
    inr iptables -t nat -A POSTROUTING -o nlr-wan -j MASQUERADE
  else
    inr iptables -t nat -A POSTROUTING -o nlr-wan -j MASQUERADE --random-fully
  fi
fi

# The test's home network is a veth pair, which the Gateway does not count as
# a home interface. For the run it is added to home_interfaces: to the list
# already configured, or else to what the Gateway detects on its own (NICs,
# bridges with a NIC port, bonds and VLANs on NICs). The file is restored and
# the Gateway restarted on exit.
[ -f "$GW_INI" ] || fail "$GW_INI not found"
cp -p "$GW_INI" "$WORK/gateway.ini.orig"; MADE_HOME=1
homes=$(python3 - "$GW_INI" "$HOST_IF" <<'PY'
import os, re, sys
path, test_if = sys.argv[1], sys.argv[2]
text = open(path).read()

def section(name):
    m = re.search(r'(?ms)^\[' + name + r'\]\s*$(.*?)(?=^\[|\Z)', text)
    return m.group(1) if m else ''

def hardware(name, depth=0):  # as the Gateway's pkg/source hardware()
    d = '/sys/class/net/' + name
    if depth > 4 or not os.path.isdir(d):
        return False
    if os.path.exists(d + '/device'):
        return True
    for e in os.listdir(d):
        if e.startswith('lower_') and hardware(e[len('lower_'):], depth + 1):
            return True
    brif = d + '/brif'
    return os.path.isdir(brif) and any(hardware(p, depth + 1) for p in os.listdir(brif))

m = re.search(r'(?m)^\s*home_interfaces\s*=\s*(.*)$', section('gateway'))
configured = [n.strip() for n in (m.group(1) if m else '').split(',') if n.strip()]
names = configured or sorted(n for n in os.listdir('/sys/class/net') if hardware(n))
homes = ','.join([test_if] + [n for n in names if n != test_if])

text = re.sub(r'(?m)^\s*home_interfaces\s*=.*\n?', '', text)
if re.search(r'(?m)^\[gateway\]\s*$', text):
    text = re.sub(r'(?m)^\[gateway\]\s*$', '[gateway]\nhome_interfaces=' + homes, text, count=1)
else:
    text += '\n[gateway]\nhome_interfaces=' + homes + '\n'
open(path, 'w').write(text)
print(homes)
PY
) || fail "could not set home_interfaces in $GW_INI"
systemctl restart nimoos-gateway
for i in $(seq 1 40); do curl -s -m 2 -o /dev/null "http://$HOST_IP/v1/gateway/device-info" && break; sleep 0.5; done
sleep 3 # the tunnel comes up on the first sweep
ok "home_interfaces for the run: $homes"

# 1. pair over the "home network" link
PAIR_TRACE=()
[ "$KEEP_TRACE" = 1 ] && PAIR_TRACE=(--trace)
inns "$BIN" "${PAIR_TRACE[@]}" pair "$HOST_IP" -user "$NAS_USER" -name "e2e-netns" 2> >(tee "$WORK/pair.trace" >&2) || fail "pairing (if the NAS did accept it, a device named e2e-netns may be on the account: remove it in the panel)"
read -r NAS_VIP DEVICE_ID CLIENT_VIP < <(python3 -c "
import json,os
c=json.load(open(os.environ['NIMOLINK_CONFIG']+'/config.json'))
print(c['nas_address'], c['device_id'], c['client_address'])") || true
[[ $DEVICE_ID =~ ^[0-9]+$ && -n $NAS_VIP && -n $CLIENT_VIP ]] || fail "pairing may have succeeded but the config could not be read back: a device named e2e-netns may have been left on the account, remove it in the panel's device list"
ok "paired as device $DEVICE_ID; the NAS is $NAS_VIP"

# 1b. RELAY=1: the namespace reaches the relay and nothing else out there,
#     and sends no UDP at all. NAT: the same, through its router, with UDP.
if [ "$VIA_RELAY" = 1 ]; then
  RELAY_HOST=$(python3 -c "
import json,os,urllib.parse
print(urllib.parse.urlparse(json.load(open(os.environ['NIMOLINK_CONFIG']+'/config.json')).get('remote_url') or '').hostname or '')")
  [ -n "$RELAY_HOST" ] || fail "the pairing has no remote address: turn on remote access on the NAS"
  RELAY_IP=$(python3 -c "import socket,sys;print(socket.gethostbyname(sys.argv[1]))" "$RELAY_HOST") || fail "cannot resolve $RELAY_HOST"
  mkdir -p "/etc/netns/$NS"; MADE_ETC=1
  printf '127.0.0.1 localhost\n%s %s\n' "$RELAY_IP" "$RELAY_HOST" >"/etc/netns/$NS/hosts"
  if [ -n "$NAT" ]; then
    inns ip route add "$RELAY_IP/32" via "$LAN_IP"
    inr ip route add "$RELAY_IP/32" via "$HOST_IP"
  else
    inns ip route add "$RELAY_IP/32" via "$HOST_IP"
  fi
  NAT_RULE=(-s "$NS_IP/32" -d "$RELAY_IP/32" -j MASQUERADE)
  iptables -t nat -I POSTROUTING "${NAT_RULE[@]}"
  if [ "$RELAY" = 1 ]; then inns iptables -I OUTPUT -p udp -j DROP; fi
  # This host's uplink drops some new connections: a few tries.
  reached=no
  for i in 1 2 3 4 5; do
    if err=$(inns curl -sS -m 10 -o /dev/null "https://$RELAY_HOST/" 2>&1); then reached=yes; break; fi
    echo "info: try $i to reach the relay: $err"
    sleep 2
  done
  [ "$reached" = yes ] || fail "the namespace cannot reach the relay at $RELAY_HOST ($RELAY_IP)"
  if [ "$RELAY" = 1 ]; then
    ok "namespace: only the relay $RELAY_HOST ($RELAY_IP) is reachable, no UDP leaves"
  else
    ok "namespace: behind a $NAT NAT, the relay $RELAY_HOST ($RELAY_IP) is reachable"
  fi
fi

# 1c. NAT: the NAS lets in only answers on its WireGuard port, and a STUN
#     service on this machine shows the client its router's outside address.
if [ -n "$NAT" ]; then
  WG_PORT=$(python3 -c "import json,os;print(int(json.load(open(os.environ['NIMOLINK_CONFIG']+'/config.json'))['port']))") || fail "no port in the pairing"
  WG_RULE=(-i "$HOST_IF" -p udp --dport "$WG_PORT" -m conntrack --ctstate NEW -j DROP)
  iptables -I INPUT "${WG_RULE[@]}"
  ip addr add "$STUN_IP/24" dev "$HOST_IF"
  cat >"$WORK/stun.py" <<'STUN'
# answers a binding request with XOR-MAPPED-ADDRESS and FINGERPRINT
import socket, struct, sys, zlib
COOKIE = b'\x21\x12\xa4\x42'
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], 3478))
while True:
    b, (ip, port) = s.recvfrom(2048)
    if len(b) < 20 or b[:2] != b'\x00\x01' or b[4:8] != COOKIE:
        continue
    xaddr = struct.pack('!BBH', 0, 1, port ^ 0x2112) + bytes(x ^ y for x, y in zip(socket.inet_aton(ip), COOKIE))
    body = struct.pack('!HH', 0x0020, len(xaddr)) + xaddr
    msg = struct.pack('!HH', 0x0101, len(body) + 8) + COOKIE + b[8:20] + body
    fp = (zlib.crc32(msg) ^ 0x5354554e) & 0xffffffff
    s.sendto(msg + struct.pack('!HHI', 0x8028, 4, fp), (ip, port))
STUN
  python3 -I "$WORK/stun.py" "$STUN_IP" &
  STUN_PID=$!
  # the client asks this STUN service instead of the relay's
  python3 - "$NIMOLINK_CONFIG/config.json" "$STUN_IP:3478" <<'PY2' || fail "could not point the pairing at the test's STUN service"
import json, sys
path, srv = sys.argv[1], sys.argv[2]
c = json.load(open(path))
c['stun_server'] = srv
with open(path, 'w') as f:  # the same file: its owner and mode stay
    json.dump(c, f, indent=2)
PY2
  ok "NAS: only answers get in on UDP $WG_PORT from the test network; STUN at $STUN_IP:3478"
fi

# 2. connect. The home router's address is sent into the tunnel as well, to
#    show in step 6 that the NAS passes nothing on.
GW=$(ip route show default | awk '{print $3; exit}')
CLIENT_STARTED=1
inns "$BIN" --trace up -test-allowed-ips "$GW/32" >"$NIMOLINK_CONFIG/up.log" 2>"$NIMOLINK_CONFIG/trace.log" &
UP_PID=$!
for i in $(seq 1 60); do grep -q "^connected" "$NIMOLINK_CONFIG/up.log" && break; sleep 0.5; done
grep -q "^connected" "$NIMOLINK_CONFIG/up.log" || { cat "$NIMOLINK_CONFIG/up.log"; fail "no handshake"; }
if [ "$RELAY" = 1 ]; then
  inns "$BIN" status | grep -q "^over the relay" || fail "status does not say relay: $(inns "$BIN" status)"
  inns "$BIN" status | grep -q "^path: relay $RELAY_HOST" || fail "status path: $(inns "$BIN" status)"
elif [ "$NAT" = easy ]; then
  # Nothing answers directly before both sides punch: the relay first, then
  # a direct path through both "routers".
  moved=no
  for i in $(seq 1 60); do
    p=$(inns "$BIN" status | sed -n 's/^path: //p')
    if [ -n "$p" ] && [[ $p != relay* ]]; then moved=yes; echo "info: direct ~${i}s after connecting: $p"; break; fi
    sleep 1
  done
  [ "$moved" = yes ] || fail "behind an easy NAT, still not direct 60 s after connecting: $(inns "$BIN" status)"
  # one of the NAS's addresses on the test network (the STUN service's too)
  inns "$BIN" status | grep -q "^direct to 10\.199\.0\.[0-9]*:$WG_PORT," || fail "status: $(inns "$BIN" status)"
  ok "easy NAT: punched through to a direct path ($p)"
elif [ "$NAT" = strict ]; then
  # A new port for each destination: what STUN saw is not where the client
  # sends from, so the NAS's punches miss. It stays on the relay.
  for i in $(seq 1 45); do
    p=$(inns "$BIN" status | sed -n 's/^path: //p')
    [[ -z $p || $p == relay* ]] || fail "behind a strict NAT the client found a direct path ($p): the test does not model what it should"
    sleep 1
  done
  inns "$BIN" status | grep -q "^path: relay $RELAY_HOST" || fail "status path: $(inns "$BIN" status)"
  ok "strict NAT: no direct path in 45 s, the relay carries the tunnel"
else
  inns "$BIN" status | grep -q "^direct to" || fail "status does not say direct"
fi
ok "tunnel up: $(inns "$BIN" status)"

# 3. the panel answers on the virtual address
code=$(inns curl -s -m 5 -o /dev/null -w '%{http_code}' "http://$NAS_VIP/v1/gateway/device-info")
[ "$code" = 200 ] || fail "panel over the tunnel: HTTP $code"
ok "panel reachable over the tunnel"

# 3b. connect over the tunnel answers with the NAS's home address; from the
#     home network it is refused (pairing's endpoints serve there). The device
#     credential goes to curl in a header file, never on a command line.
python3 -c "import json,os;print('X-NimoLink-Device: '+json.load(open(os.environ['NIMOLINK_CONFIG']+'/config.json'))['device_token'])" >"$WORK/devhdr"
chmod 600 "$WORK/devhdr"
out=$(inns curl -s -m 10 -H @"$WORK/devhdr" -H 'Content-Type: application/json' -d '{"candidates":[]}' "http://$NAS_VIP/v1/gateway/direct/connect")
echo "$out" | python3 -c "
import json,sys
d=json.load(sys.stdin)['data']
assert d['session'] and d['check_key'], d
assert any(c['type']=='lan' and c['addr']=='$HOST_IP:51900' for c in d['candidates']), d['candidates']
" || fail "connect over the tunnel: $out"
code=$(inns curl -s -m 5 -o /dev/null -w '%{http_code}' -H @"$WORK/devhdr" -H 'Content-Type: application/json' -d '{"candidates":[]}' "http://$HOST_IP/v1/gateway/direct/connect")
[ "$code" = 403 ] || fail "connect from the home network: HTTP $code, want 403"
inns "$BIN" status | grep -q "^path: " || fail "status does not show the path"
! grep -q "another key than the one paired" "$NIMOLINK_CONFIG/up.log" || fail "the client refused the NAS's connect answer: $(cat "$NIMOLINK_CONFIG/up.log")"
ok "connect: over the tunnel it answers with the home address; from the home network it is refused"

# 4. requests over the tunnel are labelled vpn: what is for the home network only is refused
# The login body is built from the environment and goes to curl on stdin.
TOKEN=$(python3 -c 'import json,os;print(json.dumps({"username":os.environ["NAS_USER"],"password":os.environ["NIMOLINK_PASSWORD"]}))' \
  | inns curl -s -m 5 -H 'Content-Type: application/json' --data @- "http://$NAS_VIP/v1/users/login" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['token']['access_token'])" 2>/dev/null) || TOKEN=""
[ -n "$TOKEN" ] || fail "sign-in over the tunnel (password only) did not work"
printf 'Authorization: %s\n' "$TOKEN" >"$AUTH"
code=$(inns curl -s -m 5 -o /dev/null -w '%{http_code}' -X POST -H @"$AUTH" "http://$NAS_VIP/v1/users/remote/enroll-code")
[ "$code" = 403 ] || fail "enroll-code over the tunnel: HTTP $code, want 403. If the NAS accepted it, an enrol code may have been issued: check the panel"
code=$(inns curl -s -m 5 -o /dev/null -w '%{http_code}' -X PUT -H @"$AUTH" -H 'Content-Type: application/json' -d '{"enabled":true}' "http://$NAS_VIP/v1/gateway/link")
[ "$code" = 403 ] || fail "PUT /v1/gateway/link over the tunnel: HTTP $code, want 403. If the NAS accepted it, the remote-access switch may have been changed: check the panel"
code=$(inns curl -s -m 5 -o /dev/null -w '%{http_code}' -X POST -H @"$AUTH" -H 'Content-Type: application/json' -d '{"public_key":"x"}' "http://$NAS_VIP/v1/gateway/direct/pair")
[ "$code" = 403 ] || fail "pairing over the tunnel: HTTP $code, want 403"
ok "vpn label: enroll-code, the remote access switch and pairing are refused over the tunnel"

# 4b. this machine itself is not the home network any more: what a tunnel
#     client on the NAS would send is refused like the internet
code=$(curl -s -m 5 -o /dev/null -w '%{http_code}' -X POST -H @"$AUTH" "http://127.0.0.1/v1/users/remote/enroll-code")
[ "$code" = 403 ] || fail "enroll-code from this machine (loopback): HTTP $code, want 403. If the NAS accepted it, an enrol code may have been issued: check the panel"
ok "local label: enroll-code from this machine is refused"

# 5. another port of the NAS (ssh), if it listens
listening=$(ss -ltn)
if [[ $listening =~ :22[[:space:]] ]]; then
  inns timeout 3 bash -c "exec 3<>/dev/tcp/$NAS_VIP/22" || fail "ssh port over the tunnel"
  ok "ssh port reachable over the tunnel"
fi

# 5b. Docker apps (optional). A port published on all addresses answers on
#     the virtual address: the NAS delivers it to Docker's proxy on this
#     machine instead of forwarding it. A port published on 127.0.0.1 only
#     does not.
if [ -n "${DOCKER_PORT:-}" ]; then
  inns timeout 3 bash -c "exec 3<>/dev/tcp/$NAS_VIP/$DOCKER_PORT" 2>/dev/null || fail "docker port $DOCKER_PORT is not reachable over the tunnel"
  ok "docker port $DOCKER_PORT reachable over the tunnel"
fi
if [ -n "${DOCKER_LOOPBACK_PORT:-}" ]; then
  [[ $listening =~ 127\.0\.0\.1:$DOCKER_LOOPBACK_PORT[[:space:]] ]] || fail "nothing listens on 127.0.0.1:$DOCKER_LOOPBACK_PORT: the check would prove nothing"
  if inns timeout 3 bash -c "exec 3<>/dev/tcp/$NAS_VIP/$DOCKER_LOOPBACK_PORT" 2>/dev/null; then
    fail "port $DOCKER_LOOPBACK_PORT, published on 127.0.0.1 only, is reachable over the tunnel"
  fi
  ok "port $DOCKER_LOOPBACK_PORT (127.0.0.1 only) is not reachable over the tunnel"
fi

# 6. the NAS forwards nothing. Asserted on the kernel's decision, not on a
#    ping (a router with no route back would stay silent either way).
refused() { # $1: a destination that is not the NAS itself
  local out rc
  out=$(ip route get "$1" from "$CLIENT_VIP" iif nimo0 2>&1) && rc=0 || rc=$?
  echo "info: ip route get $1 from $CLIENT_VIP iif nimo0 (exit $rc): $out"
  if [ "$rc" = 0 ]; then
    [[ $out == *prohibit* || $out == *unreachable* ]] || fail "the kernel would forward $CLIENT_VIP -> $1 from nimo0"
    echo "info: refused by a prohibit/unreachable route"
  elif [[ $out == *"Permission denied"* ]]; then
    echo "info: refused: Permission denied (the prohibit rule)"
  elif [[ $out == *"No route to host"* ]]; then
    echo "info: refused: No route to host (the prohibit rule seen through forwarding=0)"
  else
    fail "route lookup failed for another reason than a refusal: $out"
  fi
}
refused "$GW"
# a container's own address is behind the NAS just like the home network
[ -z "${DOCKER_CONTAINER_IP:-}" ] || refused "$DOCKER_CONTAINER_IP"

# 6b. and nothing but the NAS itself reaches the client: what a machine at
#     home or a container sends to the virtual network is not passed on.
not_passed_on() { # $1: where it comes from, $2: the interface it arrives on
  local out rc
  out=$(ip route get "$CLIENT_VIP" from "$1" iif "$2" 2>&1) && rc=0 || rc=$?
  echo "info: ip route get $CLIENT_VIP from $1 iif $2 (exit $rc): $out"
  if [ "$rc" = 0 ]; then
    [[ $out == *prohibit* || $out == *unreachable* ]] || fail "the kernel would forward $1 -> $CLIENT_VIP into the tunnel"
  elif [[ $out != *"Permission denied"* && $out != *"No route to host"* ]]; then
    fail "route lookup failed for another reason than a refusal: $out"
  fi
}
GW_IF=$(ip route show default | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}')
[ -n "$GW_IF" ] || fail "no default route interface"
not_passed_on "$GW" "$GW_IF"
if [ -n "${DOCKER_CONTAINER_IP:-}" ]; then
  BR_IF=$(ip route get "$DOCKER_CONTAINER_IP" | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}')
  [ -n "$BR_IF" ] || fail "no interface leads to $DOCKER_CONTAINER_IP"
  not_passed_on "$DOCKER_CONTAINER_IP" "$BR_IF"
fi
own=$(ip route get "$CLIENT_VIP" 2>&1) || fail "the NAS itself has no route to the client: $own"
[[ $own == *"dev nimo0"* ]] || fail "the NAS's own route to the client is not the tunnel: $own"
ping -c 2 -W 2 "$CLIENT_VIP" >/dev/null 2>&1 || fail "the NAS itself cannot reach the client through the tunnel"
rules=$(ip -4 rule show)
grep -Eq '^5201:.*to [0-9./]+ iif lo lookup 5201' <<<"$rules" && grep -Eq '^5202:.*to [0-9./]+ prohibit' <<<"$rules" || fail "the rules at priority 5201/5202 are missing:
$rules"
# the way to the clients is in the NAS's own table only: no rule of anybody
# else's can find it in the main table, whatever its priority
main_routes=$(ip -4 route show table main)
[[ $main_routes != *nimo0* ]] || fail "the main table has a route through nimo0:
$main_routes"
own_table=$(ip -4 route show table 5201 2>/dev/null || true)
[[ $own_table == *"dev nimo0"* ]] || fail "table 5201 has no route through nimo0: $own_table"
ok "only the NAS reaches the client: the home network and containers are refused, the NAS's own ping is answered"
[ "$(cat /proc/sys/net/ipv4/conf/nimo0/forwarding)" = 0 ] || fail "IPv4 forwarding is on for nimo0"
rules=$(ip -4 rule show)
grep -Eq '^5200:.*iif nimo0.*prohibit' <<<"$rules" || fail "no 'iif nimo0 prohibit' rule at priority 5200:
$rules"
ok "the NAS forwards nothing: forwarding off on nimo0, prohibit rule at priority 5200, route lookup refused"
# secondary: the home router does not answer through the tunnel either
if inns ping -c 2 -W 2 "$GW" >/dev/null 2>&1; then fail "the home router ($GW) answered through the tunnel"; fi

if [ "$RELAY" = 1 ]; then
  # 6c. the relay holds the fallback to its rate (5 Mbps by default): a 20 MB
  #     download from the NAS averages no more than 6 Mbps (750 000 B/s).
  ss -ltn | grep -q "$NAS_VIP:18080 " && fail "$NAS_VIP:18080 is in use"
  mkdir "$WORK/dl" && head -c 20000000 /dev/urandom >"$WORK/dl/blob"
  python3 -m http.server --bind "$NAS_VIP" --directory "$WORK/dl" 18080 >/dev/null 2>&1 &
  HTTP_PID=$!
  for i in $(seq 1 20); do ss -ltn | grep -q "$NAS_VIP:18080 " && break; sleep 0.25; done
  speed=$(inns curl -s -m 180 -o /dev/null -w '%{speed_download}' "http://$NAS_VIP:18080/blob") || fail "download over the relay failed"
  echo "info: 20 MB over the relay at $speed B/s"
  python3 -c "import sys; sys.exit(0 if float(sys.argv[1]) <= 750000 else 1)" "$speed" || fail "the download averaged $speed B/s, above 6 Mbps"
  kill "$HTTP_PID"; HTTP_PID=""
  ok "relay rate held: $speed B/s"

  # 6d. UDP let through again plus an address change: a direct path answers
  #     and replaces the relay.
  inns iptables -D OUTPUT -p udp -j DROP
  inns ip addr add 10.199.0.3/24 dev nlc-ns
  moved=no
  for i in $(seq 1 60); do
    p=$(inns "$BIN" status | sed -n 's/^path: //p')
    if [ -n "$p" ] && [[ $p != relay* ]]; then moved=yes; echo "info: direct after ~${i}s: $p"; break; fi
    sleep 1
  done
  [ "$moved" = yes ] || fail "still on the relay 60 s after UDP was let through: $(inns "$BIN" status)"
  inns "$BIN" status | grep -q "^direct to" || fail "status: $(inns "$BIN" status)"
  code=$(inns curl -s -m 5 -o /dev/null -w '%{http_code}' "http://$NAS_VIP/v1/gateway/device-info")
  [ "$code" = 200 ] || fail "panel after moving to the direct path: HTTP $code"
  ok "moved to the direct path: $p"

  # 6e. UDP blocked again plus another address change: back on the relay.
  inns iptables -I OUTPUT -p udp -j DROP
  inns ip addr del 10.199.0.3/24 dev nlc-ns
  back=no
  for i in $(seq 1 45); do
    if inns "$BIN" status | grep -q "^path: relay"; then back=yes; echo "info: back on the relay after ~${i}s"; break; fi
    sleep 1
  done
  [ "$back" = yes ] || fail "not back on the relay 45 s after UDP was blocked: $(inns "$BIN" status)"
  for i in $(seq 1 30); do
    code=$(inns curl -s -m 3 -o /dev/null -w '%{http_code}' "http://$NAS_VIP/v1/gateway/device-info") || code=000
    [ "$code" = 200 ] && break
    sleep 1
  done
  [ "$code" = 200 ] || fail "panel after moving back to the relay: HTTP $code"
  ok "back on the relay"
fi

# 7. removing the device cuts the tunnel within one sweep
code=$(curl -s -m 5 -o /dev/null -w '%{http_code}' -X DELETE -H @"$AUTH" "http://$HOST_IP/v1/users/remote/devices/$DEVICE_ID")
[ "$code" = 200 ] || fail "removing the device: HTTP $code"
REVOKED=1
cut=no
for i in $(seq 1 30); do
  if ! inns curl -s -m 2 -o /dev/null "http://$NAS_VIP/v1/gateway/device-info"; then cut=yes; echo "cut off after ~${i}s"; break; fi
  sleep 1
done
[ "$cut" = yes ] || fail "still connected 30 s after the device was removed"
ok "removed device is cut off"
if [ "$RELAY" = 1 ]; then
  # the NAS closes the fallback connection; the client's next one is told
  # the device is gone, and `up` ends
  for i in $(seq 1 30); do kill -0 "$UP_PID" 2>/dev/null || break; sleep 1; done
  ! kill -0 "$UP_PID" 2>/dev/null || fail "up still runs 30 s after the device was removed: $(cat "$NIMOLINK_CONFIG/up.log")"
  grep -q "removed from the NAS" "$NIMOLINK_CONFIG/up.log" || fail "up ended without saying the device was removed: $(cat "$NIMOLINK_CONFIG/up.log")"
  ok "up ended: the device was removed"
fi
echo "ALL OK"
