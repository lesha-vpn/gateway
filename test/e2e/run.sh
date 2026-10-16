#!/usr/bin/env bash
# End-to-end test of the image against a mock coordinator and two AWG 3.1 servers (the same LOCAL
# identity on two hosts). Needs Docker and /dev/net/tun. IMAGE defaults to lesha-vpn-gw:dev.
#
#   wan 172.30.0.0/24: gw .2, server-a .10, server-b .11, coordinator .20
#   lan 172.31.0.0/24: gw .2, client .10
#   "internet": 198.51.100.10 on server-a, .11 on server-b; the gateway's default route goes to
#   server-a, so traffic that skips the tunnel reaches .10 from 172.30.0.2
#
# Checks: login via CLI, config issued, SOCKS5 and HTTP CONNECT go through the tunnel, the
# kill-switch never lets traffic out directly, a new Endpoint is picked up without a restart,
# revocation closes traffic.
set -euo pipefail

IMAGE=${IMAGE:-lesha-vpn-gw:dev}
HERE=$(cd "$(dirname "$0")" && pwd)
P=lvgw-e2e
WORK=$(mktemp -d)
FAILED=0

cleanup() {
  if [[ $FAILED == 1 ]]; then
    echo "----- gateway log -----"; docker logs $P-gw 2>&1 | tail -80 || true
    echo "----- coordinator log -----"; docker logs $P-coord 2>&1 | tail -30 || true
  fi
  teardown
  rm -rf "$WORK"
}
teardown() {
  docker rm -f $P-gw $P-a $P-b $P-coord $P-client >/dev/null 2>&1 || true
  docker network rm $P-wan $P-lan >/dev/null 2>&1 || true
}
trap cleanup EXIT
[[ -n ${E2E_KEEP:-} ]] && trap - EXIT
fail() { echo "FAIL: $*"; FAILED=1; exit 1; }
ok() { echo "ok: $*"; }

teardown
docker network create --subnet 172.30.0.0/24 $P-wan >/dev/null
docker network create --subnet 172.31.0.0/24 $P-lan >/dev/null

# Keys and AWG 3.1 params like the coordinator's awg3 profile
key() { docker run --rm --entrypoint awg "$IMAGE" "$@"; }
SRV_PRIV=$(key genkey); SRV_PUB=$(echo "$SRV_PRIV" | docker run --rm -i --entrypoint awg "$IMAGE" pubkey)
CLI_PRIV=$(key genkey); CLI_PUB=$(echo "$CLI_PRIV" | docker run --rm -i --entrypoint awg "$IMAGE" pubkey)
PSK=$(key genpsk); HPK=$(key genpsk)
SHARED="S1 = 12
S2 = 12
S3 = 12
S4 = 12
H1 = 1
H2 = 2
H3 = 3
H4 = 4
HeaderProtectionKey = $HPK
RekeyAfterTime = 100-120
RekeyTimeout = 3-7
RejectAfterTime = 150-180
KeepaliveTimeout = 5-15
MaxHandshakeAttempts = 15-20
RandomTrailers = on
DisableCookies = on"
cat > "$WORK/server.conf" <<EOF
[Interface]
PrivateKey = $SRV_PRIV
ListenPort = 51820
$SHARED

[Peer]
PublicKey = $CLI_PUB
PresharedKey = $PSK
AllowedIPs = 10.66.0.7/32
EOF
cat > "$WORK/client.conf.tmpl" <<EOF
[Interface]
Address = 10.66.0.7/32
DNS = 1.1.1.1, 8.8.8.8
PrivateKey = $CLI_PRIV
MTU = 1280
Jc = 5
Jmin = 10
Jmax = 50
$SHARED
I1 = <r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>

[Peer]
PublicKey = $SRV_PUB
PresharedKey = $PSK
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = @ENDPOINT@
PersistentKeepalive = 25
EOF
cp "$HERE"/server.sh "$HERE"/mock-coordinator.js "$HERE"/probe.js "$WORK"/
chmod -R a+r "$WORK"

AWG_RUN=(--cap-add NET_ADMIN --device /dev/net/tun -v "$WORK:/e2e:ro")
for s in a:10 b:11; do
  docker run -d --name $P-${s%%:*} --network $P-wan --ip 172.30.0.${s##*:} -e INTERNET_IP=198.51.100.${s##*:} \
    "${AWG_RUN[@]}" --entrypoint /e2e/server.sh "$IMAGE" >/dev/null
done
docker run -d --name $P-coord --network $P-wan --ip 172.30.0.20 -v "$WORK:/e2e:ro" \
  -e CONF_TEMPLATE=/e2e/client.conf.tmpl -e ENDPOINT=172.30.0.10:51820 \
  --entrypoint node "$IMAGE" /e2e/mock-coordinator.js >/dev/null
docker run -d --name $P-client --network $P-lan --ip 172.31.0.10 -v "$WORK:/e2e:ro" --entrypoint sleep "$IMAGE" infinity >/dev/null

# Kernels without IPv6 have no such sysctl
V6=(); [[ -e /proc/sys/net/ipv6 ]] && V6=(--sysctl net.ipv6.conf.all.disable_ipv6=1)
docker create --name $P-gw --network $P-wan --ip 172.30.0.2 "${AWG_RUN[@]}" \
  --sysctl net.ipv4.conf.all.src_valid_mark=1 "${V6[@]}" \
  -e COORDINATOR_URL=http://172.30.0.20:8080 -e DEVICE_NAME=e2e -e LAN_CIDRS=172.31.0.0/24 \
  -e POLL_INTERVAL=3s -e HANDSHAKE_TIMEOUT=20s -e AWG_IMPL="${AWG_IMPL:-auto}" \
  "$IMAGE" >/dev/null
# Second network after create, so the default route stays on wan
docker network connect --ip 172.31.0.2 $P-lan $P-gw
docker start $P-gw >/dev/null
docker exec $P-gw ip -4 route replace default via 172.30.0.10

coord() { docker exec $P-coord node -e "
  const r=require('http').request({host:'127.0.0.1',port:8080,path:'/control',method:'POST',headers:{'Content-Type':'application/json'}},s=>s.pipe(process.stdout));r.end(process.argv[1])" "$1" >/dev/null; }
phase() { docker exec $P-gw node -e "try{console.log(require('/run/lesha-vpn-gw/status.json').phase)}catch{console.log('none')}"; }
wait_phase() {
  for _ in $(seq 1 60); do [[ $(phase) == "$1" ]] && return 0; sleep 1; done
  fail "phase $(phase), expected $1"
}
probe() { docker exec $P-client node /e2e/probe.js "$1" 172.31.0.2 "$2" "$3" 8000; }
expect_tunnel() {
  local out
  for _ in $(seq 1 30); do
    out=$(probe "$1" "$2" "$3")
    [[ $out == 10.66.0.7 ]] && return 0
    [[ $out == FAIL* ]] || fail "$1 to $3 seen as $out (not via tunnel)"
    sleep 1
  done
  fail "$1 to $3: $out"
}
# Over $1 seconds nothing may reach a server from the gateway's own address (a leak)
LEAK_TARGETS=198.51.100.10
never_leaks() {
  local end=$((SECONDS + $1)) out
  while (( SECONDS < end )); do
    for t in $LEAK_TARGETS; do
      out=$(probe socks 1080 $t)
      [[ $out == 10.66.0.7 || $out == FAIL* ]] || fail "leak: $t saw $out"
    done
  done
}

wait_phase need_login
ok "starts without a token in need_login"
expect_closed() { local out; out=$(probe socks 1080 198.51.100.10); [[ $out == FAIL* ]] || fail "traffic passes without a tunnel: $out"; }
expect_closed
ok "no tunnel, no traffic"

docker exec $P-gw lesha-vpn-gw login 000000 >/dev/null 2>&1 && fail "wrong code accepted"
docker exec $P-gw lesha-vpn-gw login 123456 | grep -q 'Вход выполнен' || fail "login"
wait_phase up
ok "login, config issued, tunnel up"
docker exec $P-coord node -e "require('http').get('http://127.0.0.1:8080/control',r=>r.pipe(process.stdout))" | grep -q '"deviceLabel":"gateway-e2e"' || fail "device label"
docker exec $P-coord node -e "require('http').get('http://127.0.0.1:8080/control',r=>r.pipe(process.stdout))" | grep -q '"name":"gw-e2e"' || fail "config name"

expect_tunnel socks 1080 198.51.100.10
expect_tunnel http 8080 198.51.100.10
ok "SOCKS5 and HTTP CONNECT go through the tunnel"
docker exec $P-gw cat /etc/resolv.conf | grep -q 'nameserver 1.1.1.1' || fail "resolv.conf does not follow the tunnel DNS"
ok "container DNS is the tunnel DNS"

docker exec $P-gw lesha-vpn-gw status | grep -q 'gw-e2e' || fail "status"
docker exec $P-gw lesha-vpn-gw health || fail "health"
ok "status and health"

docker exec $P-gw ip link del awg0
never_leaks 15
expect_tunnel socks 1080 198.51.100.10
ok "interface lost: no leak, recovered"

# LOCAL moves to a new host: the old one dies, the leak path now goes to server-b
coord '{"endpoint":"172.30.0.11:51820"}'
docker stop -t 1 $P-a >/dev/null
docker exec $P-gw ip -4 route replace default via 172.30.0.11
LEAK_TARGETS=198.51.100.11
expect_tunnel socks 1080 198.51.100.11
docker logs $P-gw 2>&1 | grep -q 'без разрыва' || fail "endpoint change was not applied live"
ok "new Endpoint picked up live"

docker restart -t 2 $P-gw >/dev/null
docker exec $P-gw ip -4 route replace default via 172.30.0.11
wait_phase up
expect_tunnel socks 1080 198.51.100.11
ok "restart: back up from the stored token and config"

coord '{"state":"suspended"}'
wait_phase suspended
never_leaks 8
expect_closed() { local out; out=$(probe socks 1080 198.51.100.11); [[ $out == FAIL* ]] || fail "traffic passes while suspended: $out"; }
expect_closed
coord '{"state":"active"}'
wait_phase up
expect_tunnel socks 1080 198.51.100.11
ok "suspended closes traffic, active brings it back"

coord '{"state":"revoked"}'
wait_phase revoked
expect_closed
ok "revoked closes traffic"

out=$(docker exec $P-gw lesha-vpn-gw logout 2>&1)
[[ $out == *'Выход выполнен'* && $out != *'недоступен'* ]] || fail "logout: $out"
wait_phase need_login
ok "logout"

echo "e2e passed"
