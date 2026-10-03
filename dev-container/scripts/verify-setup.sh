#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
set -a
# shellcheck disable=SC1091
source dev-container/.env
set +a
echo "RPM_BUILD_OPTS=[${RPM_BUILD_OPTS}]"
echo "FEDORA_BASE_IMAGE=${FEDORA_BASE_IMAGE}"

# Exercise Dockerfile patch generation without a full image build.
mkdir -p dev-container/output/rpms
# Placeholder so rpm_count > 0; removed after patch test.
PLACEHOLDER=dev-container/output/rpms/freeipa-server-4.13.4-0.fc43.x86_64.rpm
printf 'placeholder' > "${PLACEHOLDER}"

# Run only the prepare + generate portion by calling build-image until docker build...
# Instead, inline the python generator the same way build-image does via a dry-run helper.
STAGE=dev-container/.build/runtime-dryrun
rm -rf "${STAGE}"
mkdir -p "${STAGE}/rpms"
tar -C dev-container/vendor/freeipa-container --exclude='.git' -cf - . | tar -C "${STAGE}" -xf -
cp -f dev-container/output/rpms/*.rpm "${STAGE}/rpms/" || true
OFFICIAL_DF="${STAGE}/Dockerfile.fedora-43"
GENERATED_DF="${STAGE}/Dockerfile.local-rpms"
python3 - "${OFFICIAL_DF}" "${GENERATED_DF}" "4.13.4" "fedora" "43" <<'PY'
import pathlib, re, sys
src = pathlib.Path(sys.argv[1]); dst = pathlib.Path(sys.argv[2])
version, base_image, fedora_version = sys.argv[3], sys.argv[4], sys.argv[5]
text = src.read_text(encoding="utf-8")
text, from_n = re.subn(r"^FROM\s+registry\.fedoraproject\.org/fedora:\S+", f"FROM {base_image}:{fedora_version}", text, count=1, flags=re.MULTILINE)
assert from_n == 1, from_n
replacement = "COPY rpms/ /tmp/local-rpms/\nRUN echo local-rpms\n"
pattern = re.compile(
    r"RUN dnf upgrade -y --setopt=install_weak_deps=False \\\n"
    r"\t&& dnf install -y --setopt=install_weak_deps=False freeipa-server[^\n]* \\\n"
    r"\t&& dnf clean all\n",
    re.MULTILINE,
)
new_text, n = pattern.subn(replacement + "\n", text, count=1)
assert n == 1, n
assert "COPY rpms/" in new_text
assert "dnf install -y --setopt=install_weak_deps=False freeipa-server freeipa-server-dns" not in new_text
assert new_text.splitlines()[0].startswith("FROM fedora:43") or any(l.startswith("FROM fedora:43") for l in new_text.splitlines()[:5])
dst.write_text(new_text, encoding="utf-8")
print("PATCH_OK", dst)
print("FROM", [l for l in new_text.splitlines() if l.startswith("FROM ")][0])
PY

rm -f "${PLACEHOLDER}"
echo VERIFY_OK
