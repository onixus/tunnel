# APEX console migration — issue #35

The network console, TrustTunnel admin/client portal and standalone profile/route
screens now share the APEX palette, local Inter/JetBrains Mono, a 56px header,
240px desktop sidebar, semantic statuses and keyboard focus styling. Each page
has at most one primary action. Read-only views can have none.

The theme selector is in each header, including login pages: Dark / Light /
System. `apex.theme` is shared across same-origin consoles. System mode follows
OS changes; other tabs synchronize preference changes. Print uses light tokens;
QR images retain white paper in both themes.

[Canonical source and packaging instructions](../../server/design-system/README.md).

## Review screenshots

All users, passwords and configurations are synthetic. Before is commit
`cf61422bfb139860d4733710e4f67bbc3b2ff89e`. The old network console had **no light
theme**, so its two before captures show the same dark UI. Before portal font
CDN requests were blocked for isolated, reproducible capture; the new UI loads
its fonts locally. Full screen captures, including every tested section, are
uploaded by the APEX Design System workflow.

| Screen | Before dark | Before light | After dark | After light |
| --- | --- | --- | --- | --- |
| Network | [image](screenshots/before-console-overview-dark.png) | [unavailable](screenshots/before-console-overview-light.png) | [image](screenshots/console-overview-dark.png) | [image](screenshots/console-overview-light.png) |
| Portal admin | [image](screenshots/before-portal-admin_dashboard-dark.png) | [image](screenshots/before-portal-admin_dashboard-light.png) | [image](screenshots/portal-admin_dashboard-dark.png) | [image](screenshots/portal-admin_dashboard-light.png) |
| Portal client | [image](screenshots/before-portal-dashboard-dark.png) | [image](screenshots/before-portal-dashboard-light.png) | [image](screenshots/portal-dashboard-dark.png) | [image](screenshots/portal-dashboard-light.png) |

Mobile: [network dark](screenshots/console-mobile-dark.png),
[network light](screenshots/console-mobile-light.png),
[portal dark](screenshots/portal-mobile-dark.png),
[portal light](screenshots/portal-mobile-light.png).

## Validation boundary

`server/tests/test_design_system.py` checks token distribution, font hashes,
absence of component color literals/CDNs/sub-11px type, all 9 network sections,
15 portal templates and 2 overlay pages in both themes, mobile overflow,
visible text contrast (4.5:1), input-boundary contrast (3:1), theme persistence,
OS changes, storage events/denial, focus and light print output. Disabled controls
are excluded from text contrast assertions. Fixtures are deliberately isolated;
they do not validate real credentials, VPN connectivity or production state.

Keep `warning` text off light `bg-sunken`: the approved pair is 4.47:1. Warning
badges use a 5% warning mix with `surface-1`; this preserves the approved base
color while meeting text contrast on the actual status backgrounds.

Existing routing, protocol, QR/browser and image-publication tests also run.
Preparing or installing an image and live browser acceptance are separate gates;
no live container is changed by these tests.
