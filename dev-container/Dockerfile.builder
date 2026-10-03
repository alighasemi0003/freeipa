# Fedora-based FreeIPA RPM builder for local development.
# Source is bind-mounted at build time; this image only caches tooling.
ARG FEDORA_VERSION=43
ARG FEDORA_BASE_IMAGE=fedora
FROM ${FEDORA_BASE_IMAGE}:${FEDORA_VERSION}

ARG FEDORA_VERSION
LABEL org.opencontainers.image.title="FreeIPA local RPM builder" \
      org.opencontainers.image.description="Build FreeIPA RPMs from a local source tree" \
      freeipa.dev.role="builder" \
      freeipa.dev.fedora="${FEDORA_VERSION}"

RUN set -eux; \
	# Flaky mirrorlists (especially updates) should not block the builder image.
	dnf -y install --setopt=install_weak_deps=False --setopt=skip_if_unavailable=True \
		rpm-build \
		rpmdevtools \
		dnf-plugins-core \
		createrepo_c \
		git \
		rsync \
		which \
		findutils \
		make \
		autoconf \
		automake \
		libtool \
		gettext-devel \
		tar \
		gzip \
		bzip2 \
		xz \
		python3 \
		python3-devel \
		gcc \
		gcc-c++ \
		redhat-rpm-config \
	|| dnf -y install --setopt=install_weak_deps=False --disablerepo='*updates*' \
		rpm-build \
		rpmdevtools \
		dnf-plugins-core \
		createrepo_c \
		git \
		rsync \
		which \
		findutils \
		make \
		autoconf \
		automake \
		libtool \
		gettext-devel \
		tar \
		gzip \
		bzip2 \
		xz \
		python3 \
		python3-devel \
		gcc \
		gcc-c++ \
		redhat-rpm-config; \
	dnf clean all; \
	mkdir -p /build /out /src

COPY scripts/builder-entrypoint.sh /usr/local/bin/builder-entrypoint.sh
RUN chmod +x /usr/local/bin/builder-entrypoint.sh \
	&& mkdir -p /build /out /src

# Stable work root — never deleted by the entrypoint (workspace is /build/freeipa).
WORKDIR /build
VOLUME ["/out"]
ENTRYPOINT ["/usr/local/bin/builder-entrypoint.sh"]
