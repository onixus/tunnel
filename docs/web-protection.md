# Telegram and HTTPS authentication protection

Deployed on onixus-rf on 2026-10-01. `/panel` and the compatible `/panels`
command now open the unified console. `/bans` shows both `sshd` and `vpn-web`.
Owner ID, private-chat checks and one-time mutation confirmations remain required.
No credentials are included in the button URL.

## Web jail

`vpn-web` counts **POST /admin/login** and **POST /login** responses with status
401. Five failures within ten minutes ban the source address from TCP 443 for one
hour. GETs, successful logins, and 403 responses for unapproved accounts do not
count. This protects the public HTTPS portal; legacy private HTTP panels do not
feed this jail.

Nginx writes only timestamp and its socket peer address to
`/var/log/vpn-portal/auth.log`. Request bodies, passwords, query strings and
forwarded headers are not part of that log. The upstream forwarded address is
overwritten by nginx. Do not add a CDN without separately configuring trusted
proxy address handling.

Fail2ban uses a separate `inet vpn_web_bans` nftables table, prerouting priority
-110 (before Docker destination NAT), explicit **TCP 443**, and separate IPv4
and IPv6 sets. It does not modify the SSH/UFW jail or drop UDP Hysteria traffic.
A shared public address may affect multiple users for the duration of a ban.
The nginx bind mount survives container recreation; logrotate keeps 14 rotated
logs and sends USR1 to reopen the active file.

## Deployment and rollback

Run from a checkout on ingress as root:

```sh
python3 deploy/install-web-protection.py
fail2ban-client status vpn-web
nft list table inet vpn_web_bans
```

The installer retains the previous nginx container and saves configuration and
bot backups under `/opt/vpn-console/backups/protection-<timestamp>`. It validates
nginx before replacement. Only the HTTPS proxy and Telegram bot restart.
When recreating nginx manually, retain the auth-log mount and logging directives.

Emergency unban:

```sh
fail2ban-client set vpn-web unbanip 192.0.2.123
```

For a full rollback, stop the `vpn-web` jail, restore the backed-up nginx config
and bot, remove the new proxy container, rename/start the retained previous
container, and restore/remove the jail/filter/logrotate files according to the
backup. Restart the bot. Do not flush the host firewall.

## Evidence and limits

Four isolated bot tests pass (links, allowlist/staleness, both jails, expired
confirmation). Live Telegram command registration and service health were
verified without sending messages. Both HTTPS login pages return 200.

An isolated nginx fixture confirmed that only the failed login POST is logged; GET, success, 403, unrelated requests and forged forwarded IPs do not produce a matching failure.

Fail2ban regex fixtures matched IPv4/IPv6 failures and rejected unrelated or
injected suffix text. Ten synthetic log entries triggered bans for two reserved
documentation addresses; the resulting nftables rules explicitly matched TCP
443. Both test bans were removed. This validates log parsing and action creation;
no real user's address or infrastructure node was deliberately banned, and an
end-to-end blocked live connection is not claimed.
