#!/usr/bin/env bash
# Rebuild RPMs + image from current source and recreate container; keep freeipa-data.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

ensure_docker
ensure_dirs
ensure_env_file
prepare_install_opts

log "Rebuild from local source (preserving volume ${VOLUME_NAME})"
"${SCRIPT_DIR}/build-rpms.sh"
"${SCRIPT_DIR}/build-image.sh"
verify_runtime_image

check_published_port_conflicts

log "Recreating container with existing data volume"
compose up -d --force-recreate --no-build freeipa

wait_for_freeipa
verify_freeipa_services
verify_local_freeipa_rpms
verify_ldap
verify_kerberos_and_ipa_cli
print_access_info

log "Rebuild complete"
