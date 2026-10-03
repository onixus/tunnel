# Unified VPN Console

Live entry: `https://onixus-rf.duckdns.org/console/`. Uses the existing TrustTunnel
administrator login. The HTTPS `/admin/dashboard` entry redirects to this console;
legacy settings and client/profile APIs remain available.

## Components

- `console_app.py`: non-root FastAPI sidecar, port 8000 on the existing private Docker
  network and host loopback 18090. Reuses the portal's explicit `SECRET_KEY` and
  administrator table. Persistent jobs, contacts, campaigns and audit are in a
  separate SQLite database at `/opt/vpn-console/data/console.db`.
- `agent.py`: root-owned systemd service with a Unix socket, no network listener.
  Socket is accessible only to root and GID 10001 (the portal/console service UID).
  It exposes a fixed operation set; request parameters cannot choose shell commands,
  service names, filesystem paths or network destinations. Do not assign this GID
  to unrelated containers or users. Possession of the socket gives VPN administrative
  capabilities; this is a service trust boundary, not independent administrator auth.
- Hysteria reads its existing SQLite database and mutates through H UI's local API
  using a short-lived service JWT. The existing user IDs, credentials and bot remain.
- TrustTunnel user operations call the existing internal admin routes. Credential
  rotation/revocation writes the existing database and asks the running endpoint
  manager to reconcile. These operations can briefly reconnect TrustTunnel clients.
  If reconciliation fails, desired state remains saved and the job is failed;
  inspect the endpoint and reapply user status before considering access revoked.
- R-TrustTunnel device registrations are shown alongside VPN credentials. Revoking
  a device also revokes its associated managed keys. Previously downloaded external
  profiles cannot be remotely erased; rotate their source credentials separately.

## Routing

The existing deployment has **Hysteria application-level egress** through primary
and reserve SOCKS exits. TrustTunnel and host traffic use the host's direct route.
The console does not claim switching Hysteria switches every service's egress.

The editor supports ordered suffix/CIDR/selected CIS GeoIP rules and a catch-all
primary/reserve choice. The first three protected rules (panel access, private-IP
rejection) cannot be removed. A revision check rejects stale edits. The agent shares
`/run/hysteria-exit-switch.lock` with the existing CLI/Telegram switch, validates
exits first, saves a protected backup, arms the existing 180-second systemd rollback,
restarts H UI and probes through a real Hysteria client before cancelling rollback.
An error restores the saved configuration. Arbitrary YAML and private-network
exceptions are not accepted from the UI. A changed protected prefix requires review.

## Delivery and Telegram

Existing SMTP settings are reused. The Telegram token remains in
`/etc/vpn-telegram/config.json` and is never returned to the browser. The existing
owner-only control bot continues polling; the console does not start a competing
`getUpdates` consumer. Telegram recipients must start that bot first.

Contacts are explicitly assigned to a protocol identity, with an opt-in flag.
Accounts across protocols are not automatically merged on matching display names.
A campaign snapshots selected addresses, shows a draft and requires a second explicit
send action. Consent is rechecked before dispatch. Every recipient is persisted as
`sending` before network I/O. Ambiguous delivery remains `unknown` and is never
retried automatically. `accepted` means SMTP/Telegram accepted the message, not
that the recipient read it. Campaigns send text announcements only and never attach
VPN credentials. No real messages are sent by test scripts.

Configuration delivery (`config.send`) is separate: an admin-confirmed job that sends
one user's own link, PNG QR and config files to that user's contact e-mail and/or
Telegram ID. Credentials are rendered at execution in `config_delivery.py` and are
never persisted in jobs, results or audit. See
[unified-console.md](../../docs/unified-console.md#отправка-конфигураций-на-e-mail-и-в-telegram).

## Updates

Client release entries come from existing signed manifests. Promotion verifies the
Ed25519 root in `server/console/update-root.pub`, target/schema/IPC/date/URL bounds and
actual installer SHA-256, forbids decreasing sequence, preserves the prior feed,
then atomically replaces `windows-x86_64/latest.json`. No signing key is exposed.
It does not forge or regenerate signatures. Linux Flatpak distribution stays under
the existing repository's signed publication process.

Server upgrades accept only operator-prepared root-owned recipes under
`/opt/vpn-console/packages`, never browser-uploaded binaries or arbitrary URLs.
No server upgrade packages are staged by the initial deployment. Example recipes:

```json
{"component":"hysteria","version":"operator-validated-version","sha256":"64 hex characters"}
```

For `NAME.json`, place the tested executable in `NAME.bin` with root ownership and
no group/world write. The adapter backs up the managed H UI binary, restarts the
service, verifies real Hysteria egress and restores it on caught errors.

```json
{"component":"trusttunnel","version":"operator-validated-version","image":"sha256:64 hex characters"}
```

The complete portal image must already be loaded and contain compatible profile
APIs. A root-owned executable `/opt/vpn-console/probes/trusttunnel` is mandatory;
it must exit successfully only after real client DNS/HTTPS traffic passes and must
not print secrets. No TrustTunnel upgrade is enabled without that probe. The
adapter saves compose and a SQLite backup, uses the pinned image, checks app health
and the protocol probe, and restores compose on caught errors. It never restores an
old database over newer user changes. **Server-update recovery after host/process
crash is manual** using the retained binary/compose; unlike routing there is no
watchdog for server package installation yet. Only stage packages in a maintenance
window with SSH access and retained profile encryption keys.

## Security and recovery

Mutations require a live administrator session plus a session-bound CSRF token and
same-origin check. API/HTML use no-store, CSP and no framing. Jobs store IDs and
intent, not passwords, VPN keys, bot tokens or session tokens. Password and key
export routes bypass the persistent queue, are audited without their secret data,
and are never sent via a URL. All browser-inserted values are escaped or textContent.

One worker executes durable jobs. Requests use idempotency keys. On process restart,
previously running jobs become `unknown`; they are not replayed. Queued jobs verify
that the requesting administrator still exists. Run exactly one console worker and
one agent instance. Broad RBAC, a separate identity provider, and automatic matching
of users across protocols are not implemented; existing portal admins are VPN admins.

Install from an uploaded subset using `python3 deploy/install-console.py` on the
host. The installer backs up SQLite, profile encryption key, nginx and prior console
files, builds from the exact locally installed portal image, checks imports/schema
in an isolated container, and launches the sidecar. It never replaces the running
VPN container. Earlier console containers are retained stopped as
`vpn-console-backup-TIMESTAMP`. To roll back, restore the saved nginx config, run
`nginx -t` and reload the HTTPS container. For a prior console version, restore its
agent files/unit and retained container. Keep the current console data directory;
do not overwrite it with an old snapshot without a separate recovery decision.

## Validation

The runtime inherits the existing portal image. The portal source lives in
[`server/upstream`](../upstream); the profile-exchange overlay and the Rust codec
are maintained in [Rust-trustvpn](https://github.com/onixus/Rust-trustvpn).
This repository carries the console and deployment tooling, not a duplicate Rust
workspace. Local API tests require a checkout of that companion repository
(verified baseline `573333f`) and its built codec. From this repository root:

```sh
python3 -m venv /tmp/tunnel-console-venv
/tmp/tunnel-console-venv/bin/python -m pip install -r server/test-environment/requirements.txt
# Replace this with your companion checkout's absolute path.
export RTRUST_SOURCE_DIR=/path/to/Rust-trustvpn
cargo build --manifest-path "$RTRUST_SOURCE_DIR/Cargo.toml" -p rtrust-codec --locked
node --check server/console/static/console.js
/tmp/tunnel-console-venv/bin/python server/tests/test_console.py
python3 scripts/validate-docs.py
```

The public Ed25519 update key is copied from the companion repository's
`crates/update/src/root.pub` at that baseline. It is public verification material,
not a signing secret; it must match the root compiled into distributed clients.
Do not regenerate it when installing the console.

On the deployed Linux host, `python3 deploy/test-console-isolated.py` additionally
exercises actual portal HTTP mutations in a disposable container with a tmpfs
runtime/database and no external network. It refuses to run the inner acceptance
script without its explicit isolation flag. Neither test suite sends real messages.

Tests use isolated SQLite and synthetic identities. The original profile exchange
codec tests use the real built `rtrust-codec`. See [deployment acceptance](../../docs/unified-console.md) for the
live acceptance record and unexercised operations.

## Local advertising and tracking filters

The routing view reports the private resolver health, source counts, last update/error, DNS interception service and next timer run. `adblock.refresh` schedules the fixed systemd updater; source URLs and domains are not accepted from a job payload. Routing changes retain the two protected DNS rules. See [local filtering operations](../../docs/local-adblock.md).
