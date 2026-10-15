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
# Do not run it with `bash -x`: that would trace the password and the token.
set -euo pipefail
: "${NAS_USER:?}" "${BIN:?path to the nimolink binary}"
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

NS=nlc HOST_IF=nlc-host HOST_IP=10.199.0.1 NS_IP=10.199.0.2
WORK="" DEVICE_ID="" TOKEN="" REVOKED=0 MADE_NS=0 MADE_LINK=0 CLIENT_STARTED=0 MADE_HOME=0
GW_INI=/etc/nimoos/gateway.ini
fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "ok: $*"; }
inns() { ip netns exec "$NS" "$@"; }

for tool in python3 curl ip ss; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is required but not installed"
done

# Refuse to touch anything that already exists on this host.
netns_list=$(ip netns list 2>/dev/null || true)
links=$(ip -o link show 2>/dev/null || true)
addrs=$(ip -o -4 addr show 2>/dev/null || true)
routes=$(ip -4 route show 2>/dev/null || true)
[[ $netns_list =~ (^|$'\n')$NS([[:space:]]|$) ]] && fail "a network namespace named $NS already exists"
[[ $links =~ :[[:space:]]($HOST_IF|nlc-ns)[@:[:space:]] ]] && fail "a link named $HOST_IF or nlc-ns already exists"
[[ $addrs =~ 10\.199\.0\. || $routes =~ 10\.199\.0\. ]] && fail "10.199.0.0/24 is already in use on this host"
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
ip link add "$HOST_IF" type veth peer name nlc-ns; MADE_LINK=1
ip link set nlc-ns netns "$NS"
ip addr add "$HOST_IP/24" dev "$HOST_IF" && ip link set "$HOST_IF" up
inns ip addr add "$NS_IP/24" dev nlc-ns
inns ip link set nlc-ns up && inns ip link set lo up

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
inns "$BIN" pair "$HOST_IP" -user "$NAS_USER" -name "e2e-netns" || fail "pairing (if the NAS did accept it, a device named e2e-netns may be on the account: remove it in the panel)"
read -r NAS_VIP DEVICE_ID CLIENT_VIP < <(python3 -c "
import json,os
c=json.load(open(os.environ['NIMOLINK_CONFIG']+'/config.json'))
print(c['nas_address'], c['device_id'], c['client_address'])") || true
[[ $DEVICE_ID =~ ^[0-9]+$ && -n $NAS_VIP && -n $CLIENT_VIP ]] || fail "pairing may have succeeded but the config could not be read back: a device named e2e-netns may have been left on the account, remove it in the panel's device list"
ok "paired as device $DEVICE_ID; the NAS is $NAS_VIP"

# 2. connect. The home router's address is sent into the tunnel as well, to
#    show in step 6 that the NAS passes nothing on.
GW=$(ip route show default | awk '{print $3; exit}')
CLIENT_STARTED=1
inns "$BIN" up -test-allowed-ips "$GW/32" >"$NIMOLINK_CONFIG/up.log" 2>&1 &
for i in $(seq 1 20); do grep -q "^connected" "$NIMOLINK_CONFIG/up.log" && break; sleep 0.5; done
grep -q "^connected" "$NIMOLINK_CONFIG/up.log" || { cat "$NIMOLINK_CONFIG/up.log"; fail "no handshake"; }
inns "$BIN" status | grep -q "^direct to" || fail "status does not say direct"
ok "tunnel up: $(inns "$BIN" status)"

# 3. the panel answers on the virtual address
code=$(inns curl -s -m 5 -o /dev/null -w '%{http_code}' "http://$NAS_VIP/v1/gateway/device-info")
[ "$code" = 200 ] || fail "panel over the tunnel: HTTP $code"
ok "panel reachable over the tunnel"

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
echo "ALL OK"
