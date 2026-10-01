#!/usr/bin/env bash
# Build local FreeIPA runtime image from official freeipa-container + local RPMs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

ensure_docker
ensure_dirs
ensure_env_file

count="$(rpm_count)"
if [[ "${count}" -lt 1 ]]; then
	die "No RPMs in ${RPM_OUT_DIR}. Run scripts/build-rpms.sh first."
fi

"${SCRIPT_DIR}/prepare-vendor.sh"

STAGE="${BUILD_STAGING_DIR}/runtime"
log "Preparing runtime build context in ${STAGE}"
rm -rf "${STAGE}"
mkdir -p "${STAGE}/rpms"

# Official container files become the build context.
# Use tar to copy while excluding .git to keep context smaller.
tar -C "${VENDOR_DIR}" \
	--exclude='.git' \
	-cf - . | tar -C "${STAGE}" -xf -

# Local FreeIPA RPMs (never from Fedora freeipa-* packages).
cp -f "${RPM_OUT_DIR}"/*.rpm "${STAGE}/rpms/"
mkdir -p "${STAGE}/provenance"
if [[ -f "${RPM_OUT_DIR}/local-rpms.manifest" ]]; then
	cp -f "${RPM_OUT_DIR}/local-rpms.manifest" "${STAGE}/provenance/"
fi
if [[ -f "${RPM_OUT_DIR}/local-build.env" ]]; then
	cp -f "${RPM_OUT_DIR}/local-build.env" "${STAGE}/provenance/"
fi

OFFICIAL_DF="${STAGE}/${FREEIPA_CONTAINER_DOCKERFILE}"
GENERATED_DF="${STAGE}/Dockerfile.local-rpms"
[[ -f "${OFFICIAL_DF}" ]] || die "Missing ${FREEIPA_CONTAINER_DOCKERFILE} in vendor tree"

LOCAL_MARKER="${LOCAL_DIST_TAG#.}" # strip leading dot for grep convenience
log "Generating Dockerfile that installs local RPMs instead of Fedora freeipa packages"
python3 - "${OFFICIAL_DF}" "${GENERATED_DF}" "${FREEIPA_VERSION}" "${FEDORA_BASE_IMAGE}" "${FEDORA_VERSION}" "${LOCAL_DIST_TAG}" <<'PY'
import pathlib
import re
import sys

src = pathlib.Path(sys.argv[1])
dst = pathlib.Path(sys.argv[2])
version = sys.argv[3]
base_image = sys.argv[4]
fedora_version = sys.argv[5]
local_dist = sys.argv[6]
text = src.read_text(encoding="utf-8")

# Prefer Docker Hub / mirror-friendly base image (registry.fedoraproject.org is often blocked).
text, from_n = re.subn(
    r"^FROM\s+registry\.fedoraproject\.org/fedora:\S+",
    f"FROM {base_image}:{fedora_version}",
    text,
    count=1,
    flags=re.MULTILINE,
)
if from_n != 1:
    text, from_n = re.subn(
        r"^FROM\s+\S+",
        f"FROM {base_image}:{fedora_version}",
        text,
        count=1,
        flags=re.MULTILINE,
    )
if from_n != 1:
    raise SystemExit("Failed to rewrite FROM line in official Dockerfile")

# BS_N is a literal backslash + n for Dockerfile shell snippets.
# IMPORTANT: re.sub/subn interprets backslash escapes in string repl.
# Always pass a callable repl (lambda) so '\n' stays backslash+n in the
# generated Dockerfile instead of becoming a real newline.
BS_N = "\\" + "n"

replacement = f'''COPY rpms/ /tmp/local-rpms/
COPY provenance/ /usr/share/freeipa-local-build/
RUN dnf -y install --setopt=install_weak_deps=False createrepo_c dnf-plugins-core \\
	&& createrepo_c /tmp/local-rpms \\
	&& printf '%s{BS_N}' \\
		'[local-freeipa]' \\
		'name=Local FreeIPA build' \\
		'baseurl=file:///tmp/local-rpms' \\
		'enabled=1' \\
		'gpgcheck=0' \\
		'priority=1' \\
		> /etc/yum.repos.d/local-freeipa.repo \\
	&& dnf upgrade -y --setopt=install_weak_deps=False \\
	&& dnf install -y --setopt=install_weak_deps=False freeipa-server freeipa-server-dns freeipa-server-trust-ad freeipa-healthcheck freeipa-client-epn freeipa-server-encrypted-dns patch \\
	&& echo "=== Verifying FreeIPA packages come from local {version} build ===" \\
	&& rpm -q freeipa-server --qf '%{{NAME}}-%{{VERSION}}-%{{RELEASE}}{BS_N}' \\
	&& rpm -q freeipa-server | grep -E '{re.escape(version)}' \\
	&& rpm -q --qf '%{{RELEASE}}{BS_N}' freeipa-server | grep -F '{local_dist}' \\
	&& test -f /usr/share/freeipa-local-build/local-rpms.manifest \\
	&& rpm -qa 'freeipa*' 'python3-ipa*' --qf '%{{NAME}}-%{{VERSION}}-%{{RELEASE}}.%{{ARCH}}{BS_N}' | sort \\
	&& rm -rf /tmp/local-rpms /etc/yum.repos.d/local-freeipa.repo \\
	&& dnf clean all
'''


# Match the official package installation RUN (may span multiple lines).
pattern = re.compile(
    r"RUN dnf upgrade -y --setopt=install_weak_deps=False \\\n"
    r"\t&& dnf install -y --setopt=install_weak_deps=False freeipa-server[^\n]* \\\n"
    r"\t&& dnf clean all\n",
    re.MULTILINE,
)
new_text, n = pattern.subn(lambda _m: replacement + "\n", text, count=1)
if n != 1:
    # Fallback: more tolerant match around freeipa-server install.
    pattern2 = re.compile(
        r"RUN dnf upgrade -y --setopt=install_weak_deps=False\s*\\\n"
        r".*?dnf clean all\n",
        re.MULTILINE | re.DOTALL,
    )
    new_text, n = pattern2.subn(lambda _m: replacement + "\n", text, count=1)
if n != 1:
    raise SystemExit(
        "Failed to patch official Dockerfile package install section; "
        "upstream freeipa-container format may have changed."
    )

banner = (
    f"# Generated from {src.name} for local FreeIPA {version} RPMs.\n"
    f"# Base image rewritten to {base_image}:{fedora_version}\n"
    f"# Local dist marker: {local_dist}\n"
    f"# Do not edit by hand — regenerated by build-image.sh\n"
)
dst.write_text(banner + new_text, encoding="utf-8")
print(f"Wrote {dst}")
PY

log "Building runtime image ${RUNTIME_IMAGE}"
docker build \
	-f "${GENERATED_DF}" \
	-t "${RUNTIME_IMAGE}" \
	--label "freeipa.dev.source=local" \
	--label "freeipa.dev.version=${FREEIPA_VERSION}" \
	--label "freeipa.dev.dist=${LOCAL_DIST_TAG}" \
	"${STAGE}"

log "Runtime image built: ${RUNTIME_IMAGE}"
docker image inspect "${RUNTIME_IMAGE}" --format '{{.Id}} {{.Config.Labels}}' | sed 's/^/    /'
