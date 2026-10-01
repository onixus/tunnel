# Unified console deployment


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
directory, and `server/console/update-root.pub`. Host Python needs PyYAML and cryptography;
Docker Compose, systemd, H UI, the existing route-switch helper and VPN profiles
must already be installed. The isolated acceptance script runs against the installed
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
