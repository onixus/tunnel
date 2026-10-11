# Device credentials: opt-in propagation contract

The portal owns credentials for `managed-N` profiles only. External imported
profiles and previously shared credentials are unmanaged. Enablement requires
`RTRUST_DEVICE_CREDENTIALS=1`, an owned, executable, non-group/world-writable
`RTRUST_ENDPOINT_CHECK`, and the generation-aware endpoint supervisor. The
checker is built from `onixus/Rust-trustvpn` as `rtrust-endpoint-check`; install
its immutable reviewed binary separately before enabling the capability.
The portal update image includes the supervisor adapter but does not enable
managed credentials or install an unreviewed checker automatically.

New grants mint owner-encrypted random credentials per device/profile. They
cannot be exported until endpoint propagation is verified. Rotation requires
an expected generation and an owner-scoped idempotency key. Device revoke
immediately revokes portal access, queues endpoint revocation, and returns the
distinct endpoint state. Repeated revoke is idempotent. Revoked devices with
unfinished propagation remain visible to the owner with include_revoked=1.

Reconciliation needs separate consent to restart the owned endpoint. This
terminates all active endpoint sessions; other devices retain credentials and
can reconnect. The supervisor waits for the old process to exit before spawning
the replacement, even if credentials files were already written. Receipts
require fresh TLS/auth responses from each declared H2/H3 listener, both new
acceptance and old rejection for rotation. Process generation, credential
generation and checker SHA-256 fence publication. A partial protocol response,
outage, timeout or superseding generation cannot yield applied. The shared lock
serializes writers; propagation states are requested/pending/applied/failed.

The verification batch has a 25-second budget after process replacement; each
child is limited to the remaining budget or 12 seconds. Replacement itself
allows 10 seconds TERM plus 5 seconds KILL wait. These are verification bounds,
not a measured end-user revocation SLA. The checker accepts only numeric
loopback endpoint addresses, uses the endpoint certificate with normal TLS
verification, and relays no visited destination. API and logs contain no
credential payloads. Rotation and revocation remain fail-closed if the feature
is subsequently disabled.

`server/tests/device_credentials_endpoint_acceptance.py` runs synthetic
enrollment/grant/rotation/revoke against the actual endpoint and private checker
inside a disposable `--network none` container. It requires ENDPOINT_BIN,
RTRUST_CODEC and RTRUST_ENDPOINT_CHECK. API/SQLite tests with mocked probes are
separate and do not prove endpoint behavior. Physical sessions, adjacent-device
continuity, legacy shared-password migration, renewal and publisher packaging
remain acceptance requirements for #22.

The isolated real-endpoint test passed on Fedora for both H2 and H3: initial
issue, old/new rotation, saved credential rejection after revoke and neighbor
device reconnect after both operations. Full client workspace tests and 86
scoped portal/routing/agent/protocol tests passed. This evidence is deliberately
separate from installed-package and active-session acceptance.
