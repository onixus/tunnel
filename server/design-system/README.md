# APEX for the VPN consoles

Canonical tokens, typefaces, status icon masks, accessibility rules and the theme
bootstrap for issue #35. Values follow the issue's approved table while
`@onixus/apex-tokens` (unified-platform#117) is unpublished. `tokens.css` is the only
place for literal UI colors; product styles use semantic variables. Legacy
variable names are aliases, not a second palette.

Run `python scripts/sync-design-system.py` after editing this directory. It
vendors identical assets into the console, upstream portal and profile overlay
static roots. These are independent Docker build contexts, so symlinks or runtime
imports across the roots would break packaging. CI uses `--check` to reject drift.

`theme.js` is a blocking external head script placed before CSS. It reads
`apex.theme` (`dark`, `light`, `system`), sets `data-theme`, `.dark`, and
`color-scheme`, follows system changes, synchronizes other tabs and tolerates
blocked storage. ThemeSwitch is a native labelled select usable with a keyboard.
Print media overrides tokens with the light palette. QR paper stays white in
both themes to preserve decoding.

Fonts are full variable TrueType files (including Cyrillic) served locally:

- Inter: `https://raw.githubusercontent.com/google/fonts/main/ofl/inter/Inter%5Bopsz,wght%5D.ttf`
- JetBrains Mono: `https://raw.githubusercontent.com/google/fonts/main/ofl/jetbrainsmono/JetBrainsMono%5Bwght%5D.ttf`

Retrieved 2026-10-22. `fonts/*-OFL.txt` retain their SIL Open Font Licenses;
`SHA256SUMS` pins the committed bytes and is checked in tests. No font CDN is
contacted at runtime. Status masks use Lucide check, triangle-alert, x and info
geometry (ISC license, see `Lucide-LICENSE`).

For additive images, `deploy/apply-design-system.py` installs UI assets while
preserving profile and admin-route navigation. It does not replace Python API
modules, databases, credentials or endpoint binaries. The console Dockerfile and
portal candidate builder both include this step. Live installation requires a
separate rollout; browser fixtures do not establish deployment acceptance.
