#!/usr/bin/env bash
# Continue bring-up using already-built local RPMs (skip makerpms).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

ensure_docker
ensure_dirs
ensure_env_file
prepare_install_opts

count="$(rpm_count)"
[[ "${count}" -ge 1 ]] || die "No RPMs in ${RPM_OUT_DIR}"

log "Continuing from existing ${count} local RPMs"
"${SCRIPT_DIR}/build-image.sh"
verify_runtime_image
maybe_reset_broken_volume
check_published_port_conflicts

log "Starting container (volume ${VOLUME_NAME} preserved)"
remove_stale_named_container
compose up -d --force-recreate --no-build freeipa
sleep 3
verify_hostname_inside
wait_for_freeipa
verify_freeipa_services
verify_local_freeipa_rpms
verify_dogtag
verify_ldap
verify_kerberos_and_ipa_cli

log "Persistence check: recreate container reusing ${VOLUME_NAME}"
remove_stale_named_container
compose up -d --force-recreate --no-build freeipa
wait_for_freeipa
verify_kerberos_and_ipa_cli
print_access_info
