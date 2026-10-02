# Primary interserver transport: TrustTunnel

Deployed 2026-10-02. Hysteria ingress connects to `onixus.duckdns.org:8443` over TrustTunnel HTTP/2 (TCP). Its local SOCKS listener is `127.0.0.1:10810`; the primary Hysteria outbound named `onixus` uses this listener. Public egress was verified as `212.237.219.42`. Existing RU/RF/CIS bypass rules and the forced `hostkey.ru` exception remain in place.

The old primary WireGuard interface `wg-private` is disabled and stopped on both hosts; the old primary SOCKS service `hysteria-exit` is also disabled. Configurations and keys are preserved. The reserve WireGuard transport and reserve exit remain active. TrustTunnel supplies the proxy transport for client traffic; it does not recreate WireGuard's private layer-3 addresses.

## Services and credentials

Ingress: `tt-primary.service`, `/etc/tt-primary/client.toml` (root:tt-primary, 0640), official CLI 1.1.7. Main exit: `tt-exit.service`, static endpoint binary, `/etc/tt-exit/{vpn,hosts,credentials,rules}.toml`, dedicated `tt-exit` service user. The independently generated interserver password is stored only in those restricted configs. The loopback SOCKS listener requires its own username and password since 2026-10-02 (see below). The exit accepts authenticated TCP connections on 8443; UDP 8443 is not opened because the transport uses HTTP/2. UDP client traffic is still carried inside TrustTunnel and was tested with a SOCKS UDP DNS exchange.

TCP connects through the DuckDNS hostname. TLS verifies `mail.onixus.ru` using the system CA store and the existing Let's Encrypt certificate; verification is never skipped. `tt-exit-cert-sync.timer` runs every five minutes, copies the renewed Maddy certificate/key with restricted permissions, and reloads the endpoint when changed. Caddy and `maddy-cert-sync` remain responsible for obtaining and syncing this certificate. Availability of public DNS for the certificate name remains necessary for renewal.

## Switch scripts

On the ingress server as root:

```sh
/root/enable-wireguard.sh
/root/enable-trusttunnel.sh
```

The first enables the primary WG and old SOCKS service on the exit, enables WG locally, refreshes peer DNS, then selects that primary route. The second selects the verified TrustTunnel primary route before disabling primary WG on both hosts. Both scripts intentionally select the primary exit. On failure the controller attempts to move Hysteria traffic to the independent reserve.

The implementation is `/usr/local/sbin/primary-transport`. Root-only `/etc/hysteria/primary-wireguard.json` and `primary-trusttunnel.json` preserve the two primary outbound definitions. `/etc/hysteria/primary-transport` records the last completed switch. The exit also has `/root/enable-wireguard.sh`, which enables only its local side.

Ingress `/root/.ssh/primary-wg-control` is a dedicated key. Its authorization on the exit is restricted to `/usr/local/sbin/wg-primary-control` with `enable` or `disable`; forwarding and arbitrary shell execution are disallowed. The host key is pinned in `/etc/hysteria/primary-control-known-hosts`; the SSH destination remains a DNS hostname.

WG DNS refresh supports an `enabled` flag per peer, preventing disabled primary WG from causing updater failures. Monitoring uses explicit `services` lists in the existing root-only SMTP settings and monitors the TrustTunnel services instead of stopped WG. Backups use `.before-trust-transport` beside the affected files; the old route switcher is `/root/hysteria-exit-switch.before-transport`.

## Verification and limits

Verified: full Hysteria-to-primary internet path, direct TrustTunnel SOCKS TCP egress, SOCKS UDP DNS exchange, both exit probes, active service state, disabled/inactive primary WG on both hosts, successful DNS updater runs and monitor collection without extra emails. Script syntax was checked.

The requested switch to TrustTunnel completed successfully. A separate live test enabling WG and switching back was blocked by automatic approval review because it could interrupt VPN traffic. Therefore the WG restoration script has not been validated with a complete live round trip. Do not interpret syntax validation as proof of rollback connectivity.

## Исправления 2 октября 2026

После PR #13 листенер `tt-primary` вручную перевели на `0.0.0.0:10810`, чтобы до
него дотягивался контейнер TrustTunnel. Клиент 1.1.7 без логина не слушает
не-loopback адрес: служба уходила в цикл перезапусков (1485 за сутки), primary
был недоступен, и консоль откатила TrustTunnel на `direct`.

Текущая схема:

- `tt-primary` слушает **только** `127.0.0.1:10810` и требует логин `tt-local`
  со случайным паролем. Те же учётные данные лежат в `/etc/hysteria/exits.json`,
  `primary-trusttunnel.json` и outbound `onixus` в конфигурации H UI.
- Контейнер обращается к `172.18.0.1:10810` через
  [tt-primary-bridge.socket](../examples/systemd/tt-primary-bridge.socket) и
  [service](../examples/systemd/tt-primary-bridge.service): `systemd-socket-proxyd`
  пересылает на loopback. `FreeBind=yes` позволяет стартовать до создания моста.
  UFW пропускает 10810 только с `172.18.0.0/16` на интерфейсе моста.
- `relay_config` передаёт учётные данные и для этого выхода; без них генерация
  отказывает.

**Не вешайте клиент на мост или `0.0.0.0`.** На не-loopback сокетах он отдаёт в
4–5 раз меньше: прямое подключение из контейнера давало 5–7 МБ/с, через
loopback-пересылку — 60–70 МБ/с (потолок канала onixus около 73 МБ/с). Сам мост
даёт 1.2 ГБ/с; UFW, ретрансмиты и версии curl исключены замерами.

Также `h-ui.service` больше не тянет `wg-quick@wg-private` через `Wants=`:
отключённый primary WG снова поднимался при каждом перезапуске H UI.
`primary-transport wireguard` по-прежнему включает его явно.
