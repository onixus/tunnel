# Telegram and HTTPS authentication protection

`/panel` and the compatible `/panels` command open the configured unified console. `/bans` shows both `sshd` and `vpn-web`.
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

## Verification and limits

Use isolated nginx and Fail2ban fixtures to check failed-login matching,
IPv4/IPv6 actions and rejection of forged forwarded addresses. Then verify your
configured HTTPS origin, source-IP handling, jail counters and unban procedure.
Synthetic log matches do not prove a connection is blocked in your network.
