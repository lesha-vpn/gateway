#!/bin/sh
# Stand-in for LOCAL: an AWG 3.1 server on amneziawg-go with one peer, plus an HTTP echo on :8000
# that answers with the client address it sees (10.66.0.7 = came through the tunnel).
# INTERNET_IP is a "public" address on this host that the gateway also reaches directly (its
# default route points here), so a leak shows up as the gateway's own address.
set -e
ip -4 address add "$INTERNET_IP/32" dev lo
amneziawg-go awg0
awg setconf awg0 /e2e/server.conf
ip -4 address add 10.66.0.1/16 dev awg0
ip link set dev awg0 mtu 1280 up
exec node -e "require('http').createServer((q,s)=>s.end(q.socket.remoteAddress.replace('::ffff:','')+'\n')).listen(8000)"
