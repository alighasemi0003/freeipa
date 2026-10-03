#!/usr/bin/env bash
# Build FreeIPA RPMs from the local repository source tree.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

ensure_docker
ensure_dirs
ensure_env_file

# Reuse existing local RPMs unless FORCE_RPM_REBUILD=1.
if [[ "${FORCE_RPM_REBUILD:-0}" != "1" ]] \
	&& [[ -f "${RPM_OUT_DIR}/local-rpms.manifest" ]] \
	&& [[ "$(rpm_count)" -ge 1 ]] \
	&& ls "${RPM_OUT_DIR}"/freeipa-server-*"${LOCAL_DIST_TAG}"*.rpm >/dev/null 2>&1; then
	log "Reusing existing local RPMs in ${RPM_OUT_DIR} ($(rpm_count) packages; set FORCE_RPM_REBUILD=1 to rebuild)"
	ls -lh "${RPM_OUT_DIR}"/*.rpm | sed 's/^/    /'
	exit 0
fi

log "Building builder image ${BUILDER_IMAGE}"
docker build \
	-f "${DEV_CONTAINER_DIR}/Dockerfile.builder" \
	-t "${BUILDER_IMAGE}" \
	--build-arg "FEDORA_VERSION=${FEDORA_VERSION}" \
	--build-arg "FEDORA_BASE_IMAGE=${FEDORA_BASE_IMAGE}" \
	"${DEV_CONTAINER_DIR}"

log "Cleaning partial RPM output under ${RPM_OUT_DIR}"
find "${RPM_OUT_DIR}" -maxdepth 1 -type f \
	\( -name '*.rpm' -o -name 'local-rpms.manifest*' -o -name 'local-build.env' \) \
	-delete 2>/dev/null || true

log "Building FreeIPA RPMs from ${REPO_ROOT}"
# /src = read-only source, /build = stable work root, /out = RPM output
docker run --rm \
	--name "freeipa-rpm-build-$$" \
	-w /build \
	-e "RPMBUILD_OPTS=${RPM_BUILD_OPTS}" \
	-e "LOCAL_DIST_TAG=${LOCAL_DIST_TAG}" \
	-e "SOURCE_DIR=/src" \
	-e "WORK_ROOT=/build" \
	-e "WORKSPACE=/build/freeipa" \
	-e "OUT_DIR=/out" \
	-v "${REPO_ROOT}:/src:ro" \
	-v "${RPM_OUT_DIR}:/out:rw" \
	"${BUILDER_IMAGE}"

if [[ ! -f "${RPM_OUT_DIR}/local-rpms.manifest" ]]; then
	die "Missing local RPM provenance manifest after build"
fi

count="$(rpm_count)"
if [[ "${count}" -lt 1 ]]; then
	die "RPM build finished but ${RPM_OUT_DIR} is empty"
fi

log "RPM build OK (${count} packages in ${RPM_OUT_DIR})"
ls -lh "${RPM_OUT_DIR}"/*.rpm | sed 's/^/    /'
