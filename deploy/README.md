# Unified console deployment

Для пустого сервера x86_64 используйте [мастер Ubuntu 24.04](../docs/fresh-install.md)
или [мастер CentOS Stream 9/10](../docs/fresh-install-centos.md) из собранного `.run`.
Ниже — установка sidecar на существующем сервере.


The console is an additive sidecar for the **existing onixus-rf installation**,
not a general-purpose installer for a fresh VPN server. It uses the live portal
image, database, explicit session secret, Docker network and nginx configuration.
The exact host paths and dependencies are documented in
[console operations](../server/console/README.md).

From a repository checkout or uploaded source subset on that Linux host, run as root:

```sh
python3 deploy/install-console.py
python3 deploy/test-console-isolated.py
```

The source subset must include `server/console/`,
`server/tests/console_portal_acceptance.py`, the console deployment files in this
directory (including `amnezia/`, `trusttunnel/` and `hysteria/`), `scripts/bootstrap-hui.py`,
`examples/systemd/h-ui.service` and `server/console/update-root.pub`. Host Python needs PyYAML and cryptography;
Docker Compose, systemd and the portal container must already be installed. H UI,
the route-switch helper and VPN profiles are needed for Hysteria features only:
protocols can be installed afterwards from the console's
[Protocols page](../docs/protocols.md). The isolated acceptance script runs against the installed
console image with a temporary database and no external network or production mounts.

The installer backs up portal SQLite and encryption keys, nginx and prior console
files; tests image imports/schema; starts the agent and non-root sidecar; and adds
HTTPS `/console/` plus the `/admin/dashboard` redirect. It does not restart either
VPN endpoint. A failed deployment restores nginx and any previous console container.
Prior console containers are retained stopped for recovery.

[Deployment evidence and rollback choices](../docs/unified-console.md) distinguish
restoring the preceding console version from removing the console entry and
returning to the legacy admin dashboard. Never restore an old SQLite snapshot over
newer user changes merely to roll back application code.

## Device route groups and profile exchange

The server overlay and additive portal image builder now belong to this repository.
Use `deploy/prepare-portal-update.py` to prepare a checked image from the exact
installed image, preserving the existing Rust codec and endpoint. It does not
replace containers. See [device routing](../docs/device-routing.md) for ownership,
API compatibility, administrative precedence, migration, validation and rollback.
