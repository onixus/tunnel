#!/usr/bin/env bash
# Same server/browser/native acceptance scope as all four GitHub workflows.
set -euo pipefail
mkdir -p reports test-results "$TMPDIR"
python --version
cargo --version
python -m pip freeze > reports/python-environment.txt
python scripts/sync-design-system.py --check
python -m compileall -q server/console server/upstream server/overlay deploy scripts
for script in server/design-system/theme.js server/console/static/*.js server/overlay/app/static/*.js; do
    node --check "$script"
done
(
    cd .client-source
    cargo build --locked -p rtrust-codec
    cargo build --locked -p rtrust-inspect
    cargo build --locked -p rtrust-portal --examples
)
export RTRUST_CODEC="$CARGO_TARGET_DIR/debug/rtrust-codec"
# Preserve workflow process isolation: portal modules set temporary env at import.
python -m pytest -q --junitxml=reports/apex.xml server/tests/test_design_system.py
python -m pytest -q --junitxml=reports/routing.xml server/tests/test_service_routing.py server/tests/test_routing_api.py server/tests/test_routing_browser.py server/tests/test_protocols.py
python -m pytest -q --junitxml=reports/qr.xml server/tests/test_config_qr.py server/tests/test_config_qr_browser.py
python -m pytest -q --junitxml=reports/console.xml server/tests/test_console.py server/tests/test_publication.py server/tests/test_adblock.py server/tests/test_protection.py
for suite in test_exchange test_device_credentials test_device_credential_console test_agent_routes; do
    python -m pytest -q --junitxml="reports/$suite.xml" "server/tests/$suite.py"
done
python -m pytest -q --junitxml=reports/device-browser.xml server/tests/test_credential_concurrency.py server/tests/test_agent_routes_browser.py server/tests/test_device_credentials_browser.py
python server/tests/native_exchange.py
python server/tests/routing_exchange.py
mkdir -p endpoint-fixture
curl -fL --retry 3 https://github.com/TrustTunnel/TrustTunnel/releases/download/v1.1.0/trusttunnel-v1.1.0-linux-x86_64.tar.gz -o endpoint-fixture/endpoint.tar.gz
echo '91c2ea3db7416a01b5258a4c047ec22890490bc55e1b194206031aa75144f0e7  endpoint-fixture/endpoint.tar.gz' | sha256sum -c -
tar -xzf endpoint-fixture/endpoint.tar.gz -C endpoint-fixture
endpoint_binary=$(find "$PWD/endpoint-fixture" -name trusttunnel_endpoint -type f)
test -n "$endpoint_binary"
python server/tests/managed_credentials_acceptance.py "$endpoint_binary" "$CARGO_TARGET_DIR/debug/rtrust-inspect"
printf '%s\n' 'PASS all server, APEX, browser, Rust HTTPS and HTTP/2+HTTP/3 revocation gates' > reports/acceptance.txt
