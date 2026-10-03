#!/bin/bash
# AmneziaWG server container. The agent mounts the generated awg0.conf read-only.
set -eu
CONF=/etc/amnezia/amneziawg/awg0.conf
[ -f "$CONF" ] || { echo "awg0.conf is missing" >&2; exit 1; }
SUBNET=$(awk -F' = ' '$1 == "Address" { print $2; exit }' "$CONF")

awg-quick up awg0

# VPN clients reach the Internet only: no other clients, host panels or private networks.
iptables -A FORWARD -i awg0 -o awg0 -j DROP
for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10 127.0.0.0/8; do
    iptables -A FORWARD -i awg0 -d "$net" -j REJECT
done
iptables -A FORWARD -i awg0 -o eth0 -j ACCEPT
iptables -A FORWARD -o awg0 -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -P FORWARD DROP
iptables -t nat -A POSTROUTING -s "$SUBNET" -o eth0 -j MASQUERADE

trap 'awg-quick down awg0; exit 0' TERM INT
sleep infinity &
wait $!
