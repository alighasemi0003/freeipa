#!/usr/bin/env bash
# Full bring-up: vendor + local RPMs + runtime image + compose up + verify.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

ensure_docker
ensure_dirs
ensure_env_file
prepare_install_opts

log "FreeIPA local development bring-up"
log "  repo:     ${REPO_ROOT}"
log "  version:  ${FREEIPA_VERSION}"
log "  image:    ${RUNTIME_IMAGE}"
log "  hostname: ${IPA_HOSTNAME}"
log "  domain:   ${IPA_DOMAIN}"
log "  realm:    ${IPA_REALM}"

maybe_reset_broken_volume

"${SCRIPT_DIR}/prepare-vendor.sh"
"${SCRIPT_DIR}/build-rpms.sh"
"${SCRIPT_DIR}/build-image.sh"
verify_runtime_image

check_published_port_conflicts

log "Starting container (volume ${VOLUME_NAME} is preserved across rebuilds)"
compose up -d --force-recreate --no-build freeipa

# Hostname must be correct before/during install; check as soon as container runs.
sleep 3
verify_hostname_inside

wait_for_freeipa
verify_freeipa_services
verify_local_freeipa_rpms
verify_dogtag
verify_ldap
verify_kerberos_and_ipa_cli

log "Persistence check: recreate container reusing ${VOLUME_NAME}"
compose up -d --force-recreate --no-build freeipa
wait_for_freeipa
verify_kerberos_and_ipa_cli

print_access_info
