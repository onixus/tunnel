# Unified VPN administration

`console/` is the additive management UI for the existing Hysteria/H UI,
TrustTunnel portal and R-TrustTunnel clients on onixus-rf. It reuses portal admin
identity, existing VPN accounts and the private Telegram bot.

- [Architecture, trust boundaries and tests](console/README.md)
- [Deployment entry point](../deploy/README.md)
- [Live acceptance, scope and rollback](../docs/unified-console.md)

`upstream/` is the TrustTunnel portal source that the console and the
[patches](../patches) apply to; it was moved here from Rust-trustvpn so the portal
has one owner. The profile-exchange overlay and the Rust codec stay in
[Rust-trustvpn](https://github.com/onixus/Rust-trustvpn), and the runtime still
inherits the installed portal image. This repository does not contain private
databases, account credentials, bot tokens or signing keys.
