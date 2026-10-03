#!/usr/bin/env bash
# Stop/remove the FreeIPA container but keep the data volume.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

ensure_docker
ensure_env_file

log "Stopping FreeIPA development container (volume ${VOLUME_NAME} kept)"
compose down --remove-orphans
log "Done. Data preserved in Docker volume: ${VOLUME_NAME}"
