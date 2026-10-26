# Primary interserver transport: TrustTunnel

TrustTunnel HTTP/2 can provide the proxy transport between the ingress and
primary exit. Example endpoint: `exit.example.com:8443`, local authenticated
SOCKS listener: `127.0.0.1:10810`. This transports VPN client traffic rather than
recreating WireGuard layer-3 addresses. Prepare an independent reserve before
changing a working primary path.

## Services and credentials

The ingress uses `tt-primary.service` and `/etc/tt-primary/client.toml`.
The exit uses `tt-exit.service` with restricted configuration files under
`/etc/tt-exit/`. Generate separate interserver credentials, use a service account,
and configure the endpoint certificate for your own TLS hostname. Keep TLS
verification enabled. Configure certificate renewal and reload for your actual
certificate provider; copying a mail server's private key is not a prerequisite.

For HTTP/2, open TCP 8443 only to the intended source. UDP client traffic may
be carried inside this connection; validate it separately through SOCKS.

## Transport controller

[primary-transport.py](../scripts/primary-transport.py) coordinates the two
primary definitions, stored in root-only `/etc/hysteria/primary-wireguard.json`
and `primary-trusttunnel.json`. `/etc/hysteria/primary-transport` records the last
completed switch. Configure service names, remote SSH control and exit profiles
before installing the controller as `/usr/local/sbin/primary-transport`.

Use a dedicated SSH key restricted to
[wg-primary-control](../scripts/wg-primary-control), with only `enable`/`disable`,
no forwarding or arbitrary shell. Pin the remote host key independently.
Check script arguments and configured paths before invoking a switch.

The WireGuard DNS refresher can disable individual peers. Update monitoring
service lists when choosing a different primary transport. Preserve the old
configs and keys for recovery; stopping a service does not remove its data.

## Container access to the local SOCKS listener

Keep the native client listener on loopback and require authentication.
The [bridge socket](../examples/systemd/tt-primary-bridge.socket) and
[service](../examples/systemd/tt-primary-bridge.service) can forward from an
explicit Docker gateway address to loopback. Adapt the gateway, subnet and
interface to your Docker network, then allow only that source in the firewall.
Pass the same SOCKS credentials to the exit profile and relay configuration.
Do not expose this listener publicly.

## Verification and limits

Check service health, authenticated TCP and UDP through SOCKS, both exit probes
and a full Hysteria client request. Test restoration to WireGuard in a maintenance
window with independent SSH access. Syntax validation alone does not prove
rollback connectivity. Ensure H UI startup dependencies do not unintentionally
start a transport you have disabled.
