# Dynamic addresses and DuckDNS

Deployed 2026-09-29. This covers IPv4 VPN infrastructure; it does not update public DNS hosted outside DuckDNS.

| Role | Stable endpoint |
|---|---|
| Hysteria, TrustTunnel, SSH ingress | `onixus-rf.duckdns.org` |
| Primary exit and SMTP TCP connection | `onixus.duckdns.org` |
| Reserve exit | `onixus-reverse.duckdns.org` |

## Update flow

All three hosts run `duckdns-update.timer` every minute. `/usr/local/sbin/duckdns-update` detects the public address using HTTPS and updates DuckDNS. Root-only `/etc/duckdns-update.json` holds `domain` and `token`; never commit it. The existing reserve credential is in `/etc/lego/duckdns.env`. The ingress additionally sets `update_local_panels: true`. Its service timeout is 150 seconds to allow the panel hook to finish.

All three run `wg-dns-refresh.timer` every minute. `/etc/wg-dns-refresh.json` contains the peer hostname, interface, UDP port, firewall backend and initial address. The refresher resolves one public IPv4 address, updates source restrictions (UFW / nftables+iptables / firewalld), and applies the endpoint to the existing peer without replacing keys or AllowedIPs. Last successful addresses are in `/var/lib/wg-dns-refresh/`. DNS failures retain the previous configuration. WireGuard configuration endpoints also use hostnames so reboot starts with DNS resolution.

The ingress `/usr/local/sbin/vpn-local-address` adjusts panel firewall destinations and `trusttunnel-panel.socket` when its own address changes. State is `/var/lib/vpn-local-address.json`. It requires the detected address to be assigned locally; a transition to NAT or a floating address not assigned to the host needs manual review. The Docker bridge name and subnet remain deployment-specific.

`/etc/hysteria/exits.json` uses `expected_host` for exit checks. The internal SOCKS addresses stay on WireGuard. Linux client `192.168.68.116` resolves the Hysteria endpoint through its direct DNS resolver. TrustTunnel exports use the ingress hostname and strict public CA validation. Existing imported profiles containing numeric addresses must be reimported.

## Mail

Monitoring on ingress and primary uses `connect_host: onixus.duckdns.org` in root-only `/etc/vpn-report/smtp.json`. TrustTunnel uses `SMTP_CONNECT_HOST=onixus.duckdns.org` with image `trusttunnel-web:dns-20260929`. SMTP settings retain `mail.onixus.ru`, SSL port 465, and normal certificate validation; the override changes TCP resolution only, preserving TLS SNI and hostname verification. The current override is implemented for SMTP SSL, not STARTTLS.

Public `onixus.ru` and `mail.onixus.ru` DNS records and MX/incoming mail are outside this updater. Their DNS-provider records must also be changed if their public services move. Certificate renewal for those unrelated names may depend on those records.

## Operations and rollback

Check `systemctl status duckdns-update.timer wg-dns-refresh.timer`, their service journals, `wg show`, and `hysteria-exit-switch check`. Then test actual client traffic and panel access, not only handshakes. DNS TTL, caches and reconnect intervals add to the one-minute timers; a change is not guaranteed to be seamless. Simultaneous loss of internet access cannot be repaired by DNS updates.

Backups include WireGuard `.before-dynamic-dns`, ingress `/root/compose.before-dns.yaml`, `/root/mailer.before-dns.py`, and both hosts' `/root/vpn-report.before-dns` plus `/root/vpn-report-smtp.before-dns.json`. Restore only the affected component after inspecting its backup. Disabling a timer alone does not revert firewall rules or endpoint state.

Local Mac SSH configuration resolves the ingress hostname and uses the previously trusted host key via `HostKeyAlias`; the numeric alias is a trust-store identifier, not a connection destination. Backup: `~/.ssh/config.before-duckdns-20260929`. The private key must be unlocked in the SSH agent after login when required.

## Validation

Mocked address-change tests cover all three firewall backends, preserve the peer identity, and reject private or failed DNS responses without applying changes. Live checks cover both exit nodes, Hysteria traffic from `.116`, SMTP from both monitors and the TrustTunnel panel. TrustTunnel HTTP/2 native client checks returned HTTP 200 for both panels by hostname; its public internet egress was the ingress server. No real public-address change was performed during deployment.
