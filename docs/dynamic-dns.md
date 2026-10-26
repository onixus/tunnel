# Dynamic addresses and DuckDNS

These optional helpers update IPv4 endpoints when a host address changes.
Create your own DuckDNS names and token. Example roles: `vpn.example.com`,
`exit.example.com`, `reserve.example.com`; actual DuckDNS names must belong
to your account. DNS zones outside DuckDNS are managed separately.

## Update flow

[duckdns-update.py](../scripts/duckdns-update.py) reads root-only
`/etc/duckdns-update.json` with `domain` and `token`. Adapt the timer and paths
before installing. The optional ingress `update_local_panels` hook adjusts
address-dependent local panel access. It requires the public address to be assigned
locally; NAT and floating-address setups need their own rules.

[wg-dns-refresh.py](../scripts/wg-dns-refresh.py) reads
`/etc/wg-dns-refresh.json`: peer hostname, interface, UDP port, firewall backend
and initial address. It resolves a public IPv4, updates source restrictions
and the existing peer endpoint while retaining keys and AllowedIPs. DNS failures
retain the previous configuration. An `enabled` flag allows disabled peers
to stay out of the refresh process. State is in `/var/lib/wg-dns-refresh/`.

Exit profiles can use `expected_host`. Resolve infrastructure names directly
before FakeIP and route endpoint connections outside the VPN to avoid loops.
Reissue imported profiles when endpoint names or TLS settings change.

## Mail

Monitoring can use `connect_host` in `/etc/vpn-report/smtp.json`; the portal
supports `SMTP_CONNECT_HOST` for SMTP SSL. This changes the TCP destination,
while the configured SMTP hostname remains the TLS identity. STARTTLS does not
use this override. Keep hostname verification enabled. MX records and certificate
renewal DNS for your mail domain are separate from this updater.

## Operations and rollback

Check timer/service journals, `wg show`, exit probes, actual client traffic
and panel access. DNS caches and reconnect times can delay recovery.
Back up affected WireGuard, firewall, panel and mail configurations before enabling
updates. Disabling a timer does not restore previous endpoints or rules.
A simultaneous loss of Internet access cannot be repaired through DNS updates.
Use a dedicated SSH known-host entry or HostKeyAlias when addressing a host by
name; verify its key independently when changing connection settings.
