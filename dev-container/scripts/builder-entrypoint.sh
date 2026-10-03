#!/usr/bin/env bash
# Runs inside the builder container. Builds FreeIPA RPMs from /src into /out.
#
# Layout:
#   /src            read-only bind of host repository
#   /build          stable work root (never deleted; also WORKDIR)
#   /build/freeipa  writable workspace (safe to rm -rf)
#   /out            host-mounted RPM output
#
# Dependency order (critical):
#   1) bootstrap freeipa.spec from freeipa.spec.in (no configure)
#   2) dnf builddep on that spec  ← installs krb5-devel, popt-devel, …)
#   3) verify key tools (krb5-config, pkg-config popt)
#   4) autoreconf / configure / makerpms.sh
set -euo pipefail

SOURCE_DIR="${SOURCE_DIR:-${SRC_DIR:-/src}}"
WORK_ROOT="${WORK_ROOT:-/build}"
WORKSPACE="${WORKSPACE:-${WORK_ROOT}/freeipa}"
OUT_DIR="${OUT_DIR:-/out}"
RPMBUILD_OPTS="${RPMBUILD_OPTS:---without ipatests}"
# Distinct local release marker (does not modify FreeIPA source files).
LOCAL_DIST_TAG="${LOCAL_DIST_TAG:-.fc43.ipa4134dev}"

if [[ ! -f "${SOURCE_DIR}/makerpms.sh" ]]; then
	echo "error: FreeIPA source not found at ${SOURCE_DIR}" >&2
	exit 1
fi

echo "==> Syncing source into writable build workspace"
echo "SOURCE_DIR=${SOURCE_DIR}"
echo "WORKSPACE=${WORKSPACE}"

cd "${WORK_ROOT}"
pwd
test -d "${SOURCE_DIR}"
test -d "${WORK_ROOT}"

rm -rf "${WORKSPACE}"
mkdir -p "${WORKSPACE}"

rsync -a \
	--delete \
	--exclude 'dev-container/output/' \
	--exclude 'dev-container/vendor/' \
	--exclude 'dev-container/.build/' \
	--exclude 'rpmbuild/' \
	--exclude 'dist/' \
	"${SOURCE_DIR}/" "${WORKSPACE}/"

cd "${WORKSPACE}"
pwd

if [[ ! -f makerpms.sh || ! -f freeipa.spec.in || ! -f VERSION.m4 ]]; then
	echo "error: rsync incomplete (makerpms.sh / freeipa.spec.in / VERSION.m4 required)" >&2
	exit 1
fi

# Local make dist produces an unsigned tarball. Release-mode specs run
# %gpgverify on Source1 and fail without a matching upstream .asc.
# Force developer-build mode in the workspace copy only (keeps Version 4.13.4).
if grep -q '^%define NON_DEVELOPER_BUILD ' freeipa.spec.in; then
	echo "==> Forcing NON_DEVELOPER_BUILD=0 for local unsigned RPM build"
	sed -i 's/^%define NON_DEVELOPER_BUILD .*/%define NON_DEVELOPER_BUILD 0/' freeipa.spec.in
fi

git config --global --add safe.directory "${WORKSPACE}"
git config --global --add safe.directory '*'

echo "==> Initializing git submodules"
if [[ -f .gitmodules ]]; then
	git submodule update --init --recursive
	if [[ -d install/freeipa-webui ]] && [[ -z "$(ls -A install/freeipa-webui 2>/dev/null || true)" ]]; then
		echo "error: install/freeipa-webui is empty after submodule update" >&2
		exit 1
	fi
fi

bootstrap_freeipa_spec() {
	# freeipa.spec is normally produced by make after configure. We must NOT
	# run configure before builddep (configure needs the BuildRequires).
	# Bootstrap by substituting @VERSION@ / @VENDOR_SUFFIX@ from VERSION.m4.
	local major minor release version
	major="$(sed -n 's/^define(IPA_VERSION_MAJOR, *\([0-9][0-9]*\)).*/\1/p' VERSION.m4 | head -1)"
	minor="$(sed -n 's/^define(IPA_VERSION_MINOR, *\([0-9][0-9]*\)).*/\1/p' VERSION.m4 | head -1)"
	release="$(sed -n 's/^define(IPA_VERSION_RELEASE, *\([0-9][0-9]*\)).*/\1/p' VERSION.m4 | head -1)"
	if [[ -z "${major}" || -z "${minor}" || -z "${release}" ]]; then
		echo "error: failed to parse IPA version from VERSION.m4" >&2
		exit 1
	fi
	version="${major}.${minor}.${release}"
	echo "==> Bootstrapping freeipa.spec for dnf builddep (version ${version})"
	# Must end in .spec — dnf builddep ignores unknown suffixes as package names.
	sed \
		-e "s|@VERSION@|${version}|g" \
		-e "s|@VENDOR_SUFFIX@||g" \
		freeipa.spec.in > freeipa.spec
}

install_build_dependencies() {
	echo "==> Installing BuildRequires via dnf builddep (before configure)"
	# Absolute path so dnf treats the argument as a spec file, not a package name.
	local spec_path="${WORKSPACE}/freeipa.spec"
	# Match makerpms/RPMBUILD_OPTS: skip ipatests build deps by default.
	local -a builddep_defs=(--define "_without_ipatests 1")
	if ! dnf -y builddep \
		--setopt=install_weak_deps=False \
		--setopt=skip_if_unavailable=True \
		"${builddep_defs[@]}" \
		"${spec_path}"; then
		echo "==> builddep retry with updates repo disabled"
		dnf -y builddep \
			--setopt=install_weak_deps=False \
			--disablerepo='*updates*' \
			"${builddep_defs[@]}" \
			"${spec_path}"
	fi
}

verify_build_tooling() {
	echo "==> Verifying critical build tools after builddep"
	if ! command -v krb5-config >/dev/null 2>&1; then
		echo "error: krb5-config missing after builddep (krb5-devel not installed?)" >&2
		rpm -q krb5-devel || true
		exit 1
	fi
	echo "    krb5-config: $(command -v krb5-config) ($(krb5-config --version 2>/dev/null || true))"
	if ! pkg-config --exists popt; then
		echo "error: pkg-config popt missing after builddep (popt-devel not installed?)" >&2
		rpm -q popt-devel || true
		pkg-config --list-all 2>/dev/null | grep -i popt || true
		exit 1
	fi
	echo "    popt: $(pkg-config --modversion popt)"
}

write_rpm_manifest() {
	local manifest="${OUT_DIR}/local-rpms.manifest"
	echo "==> Writing local RPM provenance manifest: ${manifest}"
	{
		echo "# FreeIPA local RPM manifest"
		echo "# generated=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
		echo "# workspace=${WORKSPACE}"
		echo "# format: SHA256<TAB>NEVRA<TAB>FILENAME"
		local f nevra
		for f in "${OUT_DIR}"/*.rpm; do
			[[ -f "${f}" ]] || continue
			nevra="$(rpm -qp --qf '%{NAME}-%{EPOCH}:%{VERSION}-%{RELEASE}.%{ARCH}' "${f}" 2>/dev/null \
				| sed 's/(none)://')"
			printf '%s\t%s\t%s\n' "$(sha256sum "${f}" | awk '{print $1}')" "${nevra}" "$(basename "${f}")"
		done
	} > "${manifest}"
	cp -f "${manifest}" "${OUT_DIR}/local-rpms.manifest.txt"
	wc -l "${manifest}" | awk '{print "    entries:", $1-4}'
	# Also stamp expected version/marker for runtime checks.
	{
		echo "FREEIPA_VERSION=$(sed -n 's/^define(IPA_VERSION_MAJOR, *\([0-9]*\)).*/\1/p' VERSION.m4).$(sed -n 's/^define(IPA_VERSION_MINOR, *\([0-9]*\)).*/\1/p' VERSION.m4).$(sed -n 's/^define(IPA_VERSION_RELEASE, *\([0-9]*\)).*/\1/p' VERSION.m4)"
		echo "LOCAL_DIST_TAG=${LOCAL_DIST_TAG}"
		echo "LOCAL_BUILD_ID=$(date -u +%Y%m%d%H%M%S)"
	} > "${OUT_DIR}/local-build.env"
}

bootstrap_freeipa_spec
install_build_dependencies
verify_build_tooling

echo "==> Generating configure/Makefile (deps already installed)"
if [[ ! -x ./configure ]]; then
	autoreconf -i
fi
# Always re-run configure in a clean workspace.
./configure --enable-silent-rules

# Regenerated freeipa.spec from Makefile (authoritative for rpmbuild).
make freeipa.spec

echo "==> Building RPMs (RPMBUILD_OPTS=${RPMBUILD_OPTS} dist=${LOCAL_DIST_TAG})"
# Force a recognizable local dist tag into Release without editing source.
# rpm --define needs "name value" (whitespace). Do not use --define=dist=.tag:
# that sets the macro body to "=.tag" and yields Release: 0=.tag.
# Quote so make recipe -> shell keeps the name/value as one argv.
export RPMBUILD_OPTS="${RPMBUILD_OPTS} --define 'dist ${LOCAL_DIST_TAG}'"
./makerpms.sh

echo "==> Publishing RPMs to ${OUT_DIR}"
mkdir -p "${OUT_DIR}"
find "${OUT_DIR}" -maxdepth 1 -type f \( -name '*.rpm' -o -name 'local-rpms.manifest*' -o -name 'local-build.env' \) -delete
shopt -s nullglob
built=(dist/rpms/*.rpm)
if ((${#built[@]} == 0)); then
	echo "error: no RPMs found under dist/rpms/" >&2
	exit 1
fi

copied=0
for rpm in "${built[@]}"; do
	base="$(basename "${rpm}")"
	case "${base}" in
		*.src.rpm|*debuginfo*|*debugsource*|*ipatests*)
			echo "    skip ${base}"
			continue
			;;
	esac
	cp -f "${rpm}" "${OUT_DIR}/"
	copied=$((copied + 1))
	echo "    copy ${base}"
done

if ((copied == 0)); then
	echo "error: no runtime RPMs were copied" >&2
	exit 1
fi

# Sanity: local dist marker must appear on freeipa-server RPM.
if ! ls "${OUT_DIR}"/freeipa-server-*"${LOCAL_DIST_TAG}"*.rpm >/dev/null 2>&1; then
	echo "error: freeipa-server RPM with local dist tag ${LOCAL_DIST_TAG} not found in ${OUT_DIR}" >&2
	ls -lh "${OUT_DIR}" || true
	exit 1
fi

write_rpm_manifest

echo "==> Built ${copied} runtime RPM(s):"
ls -lh "${OUT_DIR}"/*.rpm
echo "==> RPM build complete"
