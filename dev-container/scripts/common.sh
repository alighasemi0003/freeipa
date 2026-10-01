#!/usr/bin/env bash
# Shared helpers for FreeIPA local development container tooling.
set -euo pipefail

SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEV_CONTAINER_DIR="$(cd "${SCRIPTS_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${DEV_CONTAINER_DIR}/.." && pwd)"

# shellcheck disable=SC1091
if [[ -f "${DEV_CONTAINER_DIR}/.env" ]]; then
	set -a
	# shellcheck disable=SC1091
	source "${DEV_CONTAINER_DIR}/.env"
	set +a
fi

: "${FREEIPA_VERSION:=4.13.4}"
: "${FEDORA_VERSION:=43}"
: "${BUILDER_IMAGE:=local/freeipa-builder:${FREEIPA_VERSION}-dev}"
: "${RUNTIME_IMAGE:=local/freeipa-server:${FREEIPA_VERSION}-dev}"
: "${CONTAINER_NAME:=freeipa-dev}"
: "${COMPOSE_PROJECT_NAME:=freeipa-dev}"
: "${VOLUME_NAME:=freeipa-data}"
: "${IPA_HOSTNAME:=ipa.ipa.test}"
: "${IPA_DOMAIN:=ipa.test}"
: "${IPA_REALM:=IPA.TEST}"
: "${IPA_ADMIN_PASSWORD:=Secret123}"
: "${IPA_DM_PASSWORD:=Secret123}"
: "${IPA_SERVER_IP:=no-update}"
: "${IPA_ENABLE_DNS:=false}"
: "${IPA_SERVER_INSTALL_OPTS:=}"
: "${FREEIPA_CONTAINER_REPO:=https://github.com/freeipa/freeipa-container.git}"
: "${FREEIPA_CONTAINER_REF:=master}"
: "${FREEIPA_CONTAINER_DOCKERFILE:=Dockerfile.fedora-${FEDORA_VERSION}}"
: "${FEDORA_BASE_IMAGE:=fedora}"
: "${RPM_BUILD_OPTS:=--without ipatests}"
: "${LOCAL_DIST_TAG:=.fc43.ipa4134dev}"
: "${UP_HEALTH_TIMEOUT:=900}"
: "${HTTP_PORT:=80}"
: "${HTTPS_PORT:=443}"
: "${LDAP_PORT:=389}"
: "${LDAPS_PORT:=636}"
: "${KERBEROS_PORT:=88}"
: "${KERBEROS_PORT_UDP:=88}"
: "${KPASSWD_PORT:=464}"
: "${KPASSWD_PORT_UDP:=464}"
: "${DNS_PORT:=53}"

VENDOR_DIR="${DEV_CONTAINER_DIR}/vendor/freeipa-container"
OUTPUT_DIR="${DEV_CONTAINER_DIR}/output"
RPM_OUT_DIR="${OUTPUT_DIR}/rpms"
BUILD_STAGING_DIR="${DEV_CONTAINER_DIR}/.build"
COMPOSE_FILE="${DEV_CONTAINER_DIR}/docker-compose.yml"
COMPOSE_DNS_FILE="${DEV_CONTAINER_DIR}/docker-compose.dns.yml"
ENV_FILE="${DEV_CONTAINER_DIR}/.env"
ENV_EXAMPLE="${DEV_CONTAINER_DIR}/.env.example"

export COMPOSE_PROJECT_NAME
export DOCKER_BUILDKIT=1
# Ensure compose interpolates the same values scripts use.
export RUNTIME_IMAGE CONTAINER_NAME VOLUME_NAME
export IPA_HOSTNAME IPA_DOMAIN IPA_REALM
export IPA_ADMIN_PASSWORD IPA_DM_PASSWORD IPA_SERVER_IP IPA_SERVER_INSTALL_OPTS
export HTTP_PORT HTTPS_PORT LDAP_PORT LDAPS_PORT
export KERBEROS_PORT KERBEROS_PORT_UDP KPASSWD_PORT KPASSWD_PORT_UDP DNS_PORT

log() { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

require_cmd() {
	command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

dns_enabled() {
	case "${IPA_ENABLE_DNS,,}" in
		1|true|yes|on) return 0 ;;
		*) return 1 ;;
	esac
}

ensure_docker() {
	require_cmd docker
	docker info >/dev/null 2>&1 || die "Docker daemon is not reachable from this WSL environment"
	docker compose version >/dev/null 2>&1 || die "Docker Compose plugin is not available"
}

ensure_env_file() {
	if [[ ! -f "${ENV_FILE}" ]]; then
		log "Creating ${ENV_FILE} from .env.example"
		cp "${ENV_EXAMPLE}" "${ENV_FILE}"
	fi
	# shellcheck disable=SC1091
	set -a
	source "${ENV_FILE}"
	set +a

	# Re-apply defaults after sourcing (covers older .env files).
	: "${IPA_HOSTNAME:=ipa.ipa.test}"
	: "${IPA_DOMAIN:=ipa.test}"
	: "${IPA_REALM:=IPA.TEST}"
	: "${IPA_ADMIN_PASSWORD:=Secret123}"
	: "${IPA_DM_PASSWORD:=${IPA_ADMIN_PASSWORD}}"
	: "${IPA_ENABLE_DNS:=false}"
}

compose_args() {
	local args=(
		--project-directory "${DEV_CONTAINER_DIR}"
		-f "${COMPOSE_FILE}"
		--env-file "${ENV_FILE}"
	)
	if dns_enabled; then
		[[ -f "${COMPOSE_DNS_FILE}" ]] || die "DNS enabled but missing ${COMPOSE_DNS_FILE}"
		args+=(-f "${COMPOSE_DNS_FILE}")
	fi
	printf '%s\n' "${args[@]}"
}

compose() {
	local args=()
	mapfile -t args < <(compose_args)
	docker compose "${args[@]}" "$@"
}

prepare_install_opts() {
	# When integrated DNS is requested, ensure install opts include setup-dns once.
	if dns_enabled; then
		case " ${IPA_SERVER_INSTALL_OPTS} " in
			*" --setup-dns "*|*"--setup-dns"*) ;;
			*)
				IPA_SERVER_INSTALL_OPTS="--setup-dns --auto-forwarders ${IPA_SERVER_INSTALL_OPTS:-}"
				export IPA_SERVER_INSTALL_OPTS
				;;
		esac
		log "Integrated DNS enabled (publish :${DNS_PORT}/tcp+udp, install opts include --setup-dns)"
	else
		log "Integrated DNS disabled (default); host mapping: 127.0.0.1 ${IPA_HOSTNAME}"
	fi
}

ensure_dirs() {
	mkdir -p "${RPM_OUT_DIR}" "${OUTPUT_DIR}" "${DEV_CONTAINER_DIR}/vendor" "${BUILD_STAGING_DIR}"
}

rpm_count() {
	find "${RPM_OUT_DIR}" -maxdepth 1 -type f -name '*.rpm' ! -name '*.src.rpm' 2>/dev/null | wc -l
}

# Return 0 if host TCP (and optional UDP) port appears occupied.
host_port_in_use() {
	local port="$1"
	local proto="${2:-tcp}"
	if command -v ss >/dev/null 2>&1; then
		if [[ "${proto}" == "udp" ]]; then
			ss -uln | grep -Eq ":${port}\\b"
		else
			ss -tln | grep -Eq ":${port}\\b"
		fi
		return $?
	fi
	if command -v python3 >/dev/null 2>&1 && [[ "${proto}" == "tcp" ]]; then
		python3 - "${port}" <<'PY'
import socket, sys
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(("0.0.0.0", port))
except OSError:
    sys.exit(0)
s.close()
sys.exit(1)
PY
		return $?
	fi
	return 1
}

check_published_port_conflicts() {
	local conflicts=()
	local port proto

	declare -a checks=(
		"${HTTP_PORT}:tcp:HTTP"
		"${HTTPS_PORT}:tcp:HTTPS"
		"${LDAP_PORT}:tcp:LDAP"
		"${LDAPS_PORT}:tcp:LDAPS"
		"${KERBEROS_PORT}:tcp:Kerberos"
		"${KERBEROS_PORT_UDP}:udp:Kerberos"
		"${KPASSWD_PORT}:tcp:kpasswd"
		"${KPASSWD_PORT_UDP}:udp:kpasswd"
	)
	if dns_enabled; then
		checks+=("${DNS_PORT}:tcp:DNS" "${DNS_PORT}:udp:DNS")
	fi

	for item in "${checks[@]}"; do
		IFS=':' read -r port proto label <<<"${item}"
		if host_port_in_use "${port}" "${proto}"; then
			# Ignore if our own freeipa-dev container already owns the publish.
			if docker inspect -f '{{.State.Running}}' "${CONTAINER_NAME}" 2>/dev/null | grep -q true; then
				continue
			fi
			conflicts+=("${label} host port ${port}/${proto}")
		fi
	done

	if ((${#conflicts[@]} > 0)); then
		printf 'error: published host port conflict(s) detected:\n' >&2
		for c in "${conflicts[@]}"; do
			printf '  - %s\n' "${c}" >&2
		done
		printf 'Change ports in %s or stop the conflicting process, then retry.\n' "${ENV_FILE}" >&2
		exit 1
	fi
	log "No host port conflicts for published FreeIPA ports"
}

remove_stale_named_container() {
	# Compose uses a fixed container_name; a leftover container with that name
	# (from an interrupted run or different project) blocks recreate. Remove only
	# the named container — never the FreeIPA data volume.
	if docker inspect "${CONTAINER_NAME}" >/dev/null 2>&1; then
		log "Removing stale named container ${CONTAINER_NAME} (volume ${VOLUME_NAME} preserved)"
		docker rm -f "${CONTAINER_NAME}" >/dev/null
	fi
}

verify_runtime_image() {
	docker image inspect "${RUNTIME_IMAGE}" >/dev/null 2>&1 \
		|| die "Runtime image not found: ${RUNTIME_IMAGE}. Build it first."
	local source_label
	source_label="$(docker image inspect "${RUNTIME_IMAGE}" --format '{{index .Config.Labels "freeipa.dev.source"}}' 2>/dev/null || true)"
	if [[ "${source_label}" != "local" ]]; then
		warn "Image ${RUNTIME_IMAGE} missing label freeipa.dev.source=local (got '${source_label:-none}')"
	fi
	log "Runtime image present: ${RUNTIME_IMAGE}"
}

wait_for_freeipa() {
	local deadline=$((SECONDS + UP_HEALTH_TIMEOUT))
	local ready=0

	log "Waiting for FreeIPA initialization (timeout ${UP_HEALTH_TIMEOUT}s)"
	while ((SECONDS < deadline)); do
		if ! docker inspect -f '{{.State.Running}}' "${CONTAINER_NAME}" 2>/dev/null | grep -q true; then
			warn "Container ${CONTAINER_NAME} is not running"
			compose ps || true
			compose logs --tail=100 freeipa || true
			die "Container exited during startup — see logs above"
		fi

		# Avoid nested single-quotes inside bash -c; they break the readiness probe.
		if docker exec "${CONTAINER_NAME}" bash -c "
			set -e
			test -f /data/etc/ipa/default.conf || test -f /etc/ipa/default.conf
			ipactl status >/tmp/ipactl-status.out 2>&1 || true
			grep -qiE 'Directory Service:[[:space:]]*RUNNING' /tmp/ipactl-status.out
			grep -qiE 'krb5kdc.*RUNNING|KDC:[[:space:]]*RUNNING' /tmp/ipactl-status.out
			grep -qiE 'pki-tomcatd.*RUNNING|CA.*RUNNING' /tmp/ipactl-status.out
			systemctl is-active --quiet httpd || systemctl is-active --quiet httpd.service
			curl -kfsS https://127.0.0.1/ipa/ui/ >/dev/null 2>&1 || curl -kfsS https://127.0.0.1/ >/dev/null 2>&1
		" 2>/dev/null; then
			ready=1
			break
		fi
		printf '.'
		sleep 10
	done
	echo

	[[ "${ready}" -eq 1 ]] || {
		compose logs --tail=150 freeipa || true
		die "FreeIPA did not become ready within ${UP_HEALTH_TIMEOUT}s"
	}
	log "FreeIPA reports ready"
}

verify_freeipa_services() {
	log "Compose status"
	compose ps

	log "ipactl status"
	docker exec "${CONTAINER_NAME}" ipactl status || warn "ipactl status returned non-zero"

	log "systemctl --failed (should be empty or only unrelated units)"
	docker exec "${CONTAINER_NAME}" systemctl --failed --no-pager || true

	log "HTTPS check (insecure, development CA)"
	if docker exec "${CONTAINER_NAME}" curl -kfsS "https://127.0.0.1/ipa/ui/" >/dev/null 2>&1 \
		|| curl -kfsS "https://127.0.0.1:${HTTPS_PORT}/ipa/ui/" >/dev/null 2>&1; then
		log "HTTPS endpoint reachable"
	else
		die "HTTPS endpoint https://${IPA_HOSTNAME}/ipa/ui/ is not reachable yet"
	fi
}

verify_local_freeipa_rpms() {
	log "Verifying FreeIPA packages are from the local ${FREEIPA_VERSION} build"
	local pkg_list
	pkg_list="$(docker exec "${CONTAINER_NAME}" rpm -qa \
		--qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' \
		'freeipa*' 'python3-ipa*' 2>/dev/null | sort || true)"

	if [[ -z "${pkg_list}" ]]; then
		die "No freeipa/python3-ipa RPMs found inside ${CONTAINER_NAME}"
	fi

	printf '%s\n' "${pkg_list}" | sed 's/^/    /'

	if ! docker exec "${CONTAINER_NAME}" rpm -q freeipa-server >/dev/null 2>&1; then
		die "freeipa-server is not installed in the container"
	fi

	local ver rel
	ver="$(docker exec "${CONTAINER_NAME}" rpm -q --qf '%{VERSION}' freeipa-server)"
	rel="$(docker exec "${CONTAINER_NAME}" rpm -q --qf '%{RELEASE}' freeipa-server)"
	[[ "${ver}" == "${FREEIPA_VERSION}" ]] \
		|| die "freeipa-server version is '${ver}', expected '${FREEIPA_VERSION}' (local build)"
	[[ "${rel}" == *"${LOCAL_DIST_TAG}"* ]] \
		|| die "freeipa-server Release='${rel}' missing local marker '${LOCAL_DIST_TAG}'"

	# Provenance: installed freeipa NEVRAs must appear in the build manifest baked into the image.
	if ! docker exec "${CONTAINER_NAME}" test -f /usr/share/freeipa-local-build/local-rpms.manifest; then
		die "Missing /usr/share/freeipa-local-build/local-rpms.manifest inside runtime image"
	fi

	docker exec -e "LOCAL_DIST_TAG=${LOCAL_DIST_TAG}" "${CONTAINER_NAME}" bash -c '
		set -euo pipefail
		manifest=/usr/share/freeipa-local-build/local-rpms.manifest
		# Only packages from our makerpms build must match the manifest.
		# freeipa-healthcheck* come from Fedora and are intentionally allowed.
		while read -r name; do
			[[ -n "${name}" ]] || continue
			rel=$(rpm -q --qf "%{RELEASE}" "${name}")
			case "${rel}" in
				*"${LOCAL_DIST_TAG}"*) ;;
				*)
					echo "    skip-non-local ${name}-${rel}"
					continue
					;;
			esac
			nevra=$(rpm -q --qf "%{NAME}-%{EPOCH}:%{VERSION}-%{RELEASE}.%{ARCH}\n" "${name}" | sed "s/(none)://")
			if ! awk -F"\t" -v n="${nevra}" '\''$2==n {found=1} END{exit !found}'\'' "${manifest}"; then
				echo "error: installed ${nevra} not present in local RPM manifest" >&2
				exit 1
			fi
			echo "    manifest-match ${nevra}"
		done < <(rpm -qa --qf "%{NAME}\n" "freeipa*" "python3-ipa*" | sort -u)
	'

	docker exec "${CONTAINER_NAME}" rpm -qi freeipa-server \
		| grep -E '^(Name|Version|Release|Architecture|Build Date|Build Host|Source RPM)' \
		| sed 's/^/    /'

	log "LOCAL RPM PROVENANCE OK (freeipa-server-${ver}-${rel})"
}

verify_hostname_inside() {
	log "Verifying hostname inside container"
	local fqdn
	fqdn="$(docker exec "${CONTAINER_NAME}" hostname -f)"
	[[ "${fqdn}" == "${IPA_HOSTNAME}" ]] \
		|| die "hostname -f is '${fqdn}', expected '${IPA_HOSTNAME}'"
	docker exec "${CONTAINER_NAME}" getent hosts "${IPA_HOSTNAME}" >/dev/null \
		|| die "getent hosts ${IPA_HOSTNAME} failed inside container"
	log "Hostname OK: ${fqdn}"
}

verify_ldap() {
	log "Verifying LDAP (389-DS)"
	docker exec -e "IPA_DM_PASSWORD=${IPA_DM_PASSWORD}" "${CONTAINER_NAME}" bash -c '
		set -euo pipefail
		ldapsearch -x -H ldap://127.0.0.1:389 -b "" -s base namingContexts >/tmp/ldap-rootdse.out
		grep -qi namingContexts /tmp/ldap-rootdse.out
		basedn=$(python3 - <<PY
from configparser import ConfigParser
c=ConfigParser()
c.read("/etc/ipa/default.conf")
print(c.get("global","basedn", fallback=""))
PY
)
		test -n "${basedn}"
		ldapsearch -x -H ldap://127.0.0.1:389 \
			-D "cn=Directory Manager" -w "${IPA_DM_PASSWORD}" \
			-b "${basedn}" -s base dn >/dev/null
	'
	log "LDAP OK"
}

verify_kerberos_and_ipa_cli() {
	log "Verifying Kerberos + IPA CLI (password not logged)"
	docker exec -e "IPA_ADMIN_PASSWORD=${IPA_ADMIN_PASSWORD}" -e "IPA_REALM=${IPA_REALM}" \
		"${CONTAINER_NAME}" bash -c '
		set -euo pipefail
		export KRB5CCNAME=/tmp/krb5cc_freeipa_dev_verify
		rm -f "${KRB5CCNAME}"
		# Do not echo password.
		printf "%s" "${IPA_ADMIN_PASSWORD}" | kinit "admin@${IPA_REALM}" >/dev/null
		klist -s
		klist | grep -E "admin@${IPA_REALM}|krbtgt/${IPA_REALM}"
		ipa ping
		kdestroy -A >/dev/null 2>&1 || true
		rm -f "${KRB5CCNAME}"
	'
	log "Kerberos + IPA CLI OK"
}

verify_dogtag() {
	log "Verifying Dogtag/CA"
	docker exec "${CONTAINER_NAME}" bash -c '
		set -euo pipefail
		ipactl status | tee /tmp/ipactl-ca.out
		grep -qiE "pki-tomcatd.*RUNNING|ipa-custodia.*RUNNING|CA.*RUNNING" /tmp/ipactl-ca.out \
			|| systemctl is-active --quiet pki-tomcatd@pki-tomcat
	'
	log "Dogtag/CA OK"
}

maybe_reset_broken_volume() {
	# If a previous failed first-install left a half-configured volume, FreeIPA
	# will not reinstall. Detect incomplete state and remove only that volume.
	if ! docker volume inspect "${VOLUME_NAME}" >/dev/null 2>&1; then
		return 0
	fi
	# Probe volume via a throwaway container using the runtime image if present.
	local image_for_probe="${RUNTIME_IMAGE}"
	if ! docker image inspect "${image_for_probe}" >/dev/null 2>&1; then
		image_for_probe="${FEDORA_BASE_IMAGE}:${FEDORA_VERSION}"
	fi
	local state
	state="$(docker run --rm -v "${VOLUME_NAME}:/data:ro" "${image_for_probe}" \
		bash -c '
			if [[ ! -f /data/etc/ipa/default.conf && ! -f /data/var/lib/ipa/sysrestore/sysrestore.index ]]; then
				if [[ -d /data/etc || -d /data/var ]]; then
					echo partial
				else
					echo empty
				fi
			elif [[ -f /data/etc/ipa/default.conf ]]; then
				echo configured
			else
				echo partial
			fi
		' 2>/dev/null || echo unknown)"
	case "${state}" in
		partial)
			warn "Detected incomplete FreeIPA data in volume ${VOLUME_NAME}; removing for clean first install"
			compose down --remove-orphans >/dev/null 2>&1 || true
			docker volume rm -f "${VOLUME_NAME}" >/dev/null
			;;
		configured|empty|unknown) ;;
	esac
}

print_access_info() {
	cat <<EOF

============================================================
FreeIPA development environment is ready
============================================================
Hostname: ${IPA_HOSTNAME}
Domain:   ${IPA_DOMAIN}
Realm:    ${IPA_REALM}

Web UI:
https://${IPA_HOSTNAME}/ipa/ui/

Username:
admin

Password: (from .env IPA_ADMIN_PASSWORD)

Container:
${CONTAINER_NAME}

Image:
${RUNTIME_IMAGE}

Volume:
${VOLUME_NAME}

Integrated DNS: $(dns_enabled && echo enabled || echo disabled)
Source tree: ${REPO_ROOT}

Windows hosts entry (manual):
  127.0.0.1 ${IPA_HOSTNAME}

Useful commands:
  ./dev-container/logs.sh
  ./dev-container/shell.sh
  ./dev-container/rebuild.sh
  ./dev-container/down.sh
============================================================
EOF
}
