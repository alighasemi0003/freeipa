#!/usr/bin/env bash
# Clone/update official freeipa-container sources into vendor/ (gitignored).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

ensure_dirs
require_cmd git

if [[ -d "${VENDOR_DIR}/.git" ]]; then
	log "Updating freeipa-container in ${VENDOR_DIR}"
	git -C "${VENDOR_DIR}" fetch --depth 1 origin "${FREEIPA_CONTAINER_REF}"
	git -C "${VENDOR_DIR}" checkout -q FETCH_HEAD
else
	log "Cloning freeipa-container (${FREEIPA_CONTAINER_REF})"
	rm -rf "${VENDOR_DIR}"
	git clone --depth 1 --branch "${FREEIPA_CONTAINER_REF}" \
		"${FREEIPA_CONTAINER_REPO}" "${VENDOR_DIR}" \
		|| git clone --depth 1 "${FREEIPA_CONTAINER_REPO}" "${VENDOR_DIR}"
	if [[ "${FREEIPA_CONTAINER_REF}" != "master" && "${FREEIPA_CONTAINER_REF}" != "main" ]]; then
		git -C "${VENDOR_DIR}" fetch --depth 1 origin "${FREEIPA_CONTAINER_REF}" || true
		git -C "${VENDOR_DIR}" checkout -q "${FREEIPA_CONTAINER_REF}" || true
	fi
fi

if [[ ! -f "${VENDOR_DIR}/${FREEIPA_CONTAINER_DOCKERFILE}" ]]; then
	die "Official Dockerfile not found: ${VENDOR_DIR}/${FREEIPA_CONTAINER_DOCKERFILE}"
fi

git -C "${VENDOR_DIR}" rev-parse --short HEAD > "${VENDOR_DIR}/.dev-container-commit"
log "freeipa-container ready at $(cat "${VENDOR_DIR}/.dev-container-commit") (${FREEIPA_CONTAINER_DOCKERFILE})"
