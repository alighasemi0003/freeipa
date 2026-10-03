#!/usr/bin/env bash
# Interactive shell inside the FreeIPA container.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

ensure_docker
ensure_env_file

if ! docker inspect -f '{{.State.Running}}' "${CONTAINER_NAME}" 2>/dev/null | grep -q true; then
	die "Container ${CONTAINER_NAME} is not running. Start it with ./dev-container/up.sh"
fi

exec docker exec -it "${CONTAINER_NAME}" /bin/bash
