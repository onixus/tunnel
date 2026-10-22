# Unified VPN administration

`console/` is the additive management UI for the existing Hysteria/H UI,
TrustTunnel portal and R-TrustTunnel clients on onixus-rf. It reuses portal admin
identity, existing VPN accounts and the private Telegram bot.

- [APEX design system and visual review](../docs/design-system/README.md)
- [Architecture, trust boundaries and tests](console/README.md)
- [Deployment entry point](../deploy/README.md)
- [Live acceptance, scope and rollback](../docs/unified-console.md)

`upstream/` is the TrustTunnel portal source that the console and the
[patches](../patches) apply to; it was moved here from Rust-trustvpn so the portal
has one owner. The profile-exchange overlay, device route groups and administrative policy API
also live here in `overlay/`, together with their packaging and server tests.
The Rust codec and native client remain in
[Rust-trustvpn](https://github.com/onixus/Rust-trustvpn).
[Device routing ownership and validation](../docs/device-routing.md) describe the
client API, administrative precedence, migration and rollout.
[Device credentials and endpoint revocation](../docs/device-credentials.md) describe
the opt-in lifecycle, restart policy, API and real protocol acceptance.
This repository does not contain private
databases, account credentials, bot tokens or signing keys.
