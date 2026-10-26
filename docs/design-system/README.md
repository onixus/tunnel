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

Portal review captures use synthetic users, passwords and profiles. Before is commit
`cf61422bfb139860d4733710e4f67bbc3b2ff89e`. Before portal font
CDN requests were blocked for isolated, reproducible capture; the new UI loads
its fonts locally. Full screen captures, including every tested section, are
uploaded by the APEX Design System workflow.

| Screen | Before dark | Before light | After dark | After light |
| --- | --- | --- | --- | --- |
| Portal admin | [image](screenshots/before-portal-admin_dashboard-dark.png) | [image](screenshots/before-portal-admin_dashboard-light.png) | [image](screenshots/portal-admin_dashboard-dark.png) | [image](screenshots/portal-admin_dashboard-light.png) |
| Portal client | [image](screenshots/before-portal-dashboard-dark.png) | [image](screenshots/before-portal-dashboard-light.png) | [image](screenshots/portal-dashboard-dark.png) | [image](screenshots/portal-dashboard-light.png) |

Mobile portal: [dark](screenshots/portal-mobile-dark.png),
[light](screenshots/portal-mobile-light.png).

Generate network review screenshots with neutral infrastructure fixtures before
publishing them. Hostnames, node labels and topology must be synthetic as well
as user accounts. CI capture artifacts are not deployment documentation.

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

The network console uses the full workspace width on desktop. Protocol cards use
four columns on wide screens, two on smaller desktops and one on phones. Container
names, image digests and ports wrap within all seven visible desktop columns;
on narrow screens the labelled table region supports keyboard scrolling. Table
and protocol metadata text use the 14px body scale. Install/update actions share
the secondary style; checking releases is the page's explicit primary action.
Browser regressions cover 1280/1920/2560px widths, both palettes, button text and
boundary contrast, hover/focus, reordered cards, confirmation dialogs and busy states.
