#!/bin/bash
# AmneziaWG server container. The agent mounts the generated awg0.conf read-only.
# With route.json present, clients leave only through the sing-box router (exit and exceptions).
set -eu
DIR=/etc/amnezia/amneziawg
CONF=$DIR/awg0.conf
ROUTE=$DIR/route.json
TUN=egress0
TABLE=200
[ -f "$CONF" ] || { echo "awg0.conf is missing" >&2; exit 1; }
SUBNET=$(awk -F' = ' '$1 == "Address" { print $2; exit }' "$CONF")

awg-quick up awg0

# VPN clients reach the Internet only: no other clients, host panels or private networks.
iptables -A FORWARD -i awg0 -o awg0 -j DROP
for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10 127.0.0.0/8; do
    iptables -A FORWARD -i awg0 -d "$net" -j REJECT
done
iptables -A FORWARD -o awg0 -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -P FORWARD DROP

if [ -f "$ROUTE" ]; then
    # The router connects from this namespace: never to the host's own public address.
    while read -r address; do
        [ -n "$address" ] && iptables -A OUTPUT -d "$address" -j REJECT
    done < "$DIR/blocked"
    # Fail closed: no eth0 path for clients. Without the TUN their packets are dropped.
    iptables -A FORWARD -i awg0 -o "$TUN" -j ACCEPT
    ip rule add iif awg0 lookup "$TABLE" priority 100
    sing-box check -c "$ROUTE"
    (
        while true; do
            sing-box run -c "$ROUTE" &
            box=$!
            # The TUN and its route disappear with each sing-box process.
            for _ in $(seq 50); do
                ip link show "$TUN" >/dev/null 2>&1 && break
                sleep 0.2
            done
            ip route replace default dev "$TUN" table "$TABLE" || true
            wait "$box" || true
            sleep 2
        done
    ) &
else
    iptables -A FORWARD -i awg0 -o eth0 -j ACCEPT
    iptables -t nat -A POSTROUTING -s "$SUBNET" -o eth0 -j MASQUERADE
fi

trap 'awg-quick down awg0; exit 0' TERM INT
sleep infinity &
wait $!
