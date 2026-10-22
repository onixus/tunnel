#!/usr/bin/env bash
set -euo pipefail
# Only the disposable Jenkins workspace is bind-mounted here.
trap 'chown -R "$CI_HOST_UID:$CI_HOST_GID" "$PWD"' EXIT
bash ci/test-server.sh container
