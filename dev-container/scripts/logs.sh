#!/usr/bin/env bash
# Follow FreeIPA container logs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

ensure_docker
ensure_env_file

compose logs -f --tail=200 freeipa
