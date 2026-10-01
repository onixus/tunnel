# Unified VPN administration

`console/` is the additive management UI for the existing Hysteria/H UI,
TrustTunnel portal and R-TrustTunnel clients on onixus-rf. It reuses portal admin
identity, existing VPN accounts and the private Telegram bot.

- [Architecture, trust boundaries and tests](console/README.md)
- [Deployment entry point](../deploy/README.md)
- [Live acceptance, scope and rollback](../docs/unified-console.md)

The portal runtime and Rust codec come from the existing installed portal image
and [Rust-trustvpn](https://github.com/onixus/Rust-trustvpn). This repository does
not contain private databases, account credentials, bot tokens or signing keys.
