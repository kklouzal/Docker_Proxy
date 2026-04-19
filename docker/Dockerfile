ARG ALPINE_VERSION=latest

FROM alpine:${ALPINE_VERSION} AS cicap_builder

# Default to Alpine's latest stable image so builds pick up the newest
# Alpine patch/minor release and the newest Squid package available in that
# repository at build time. Override at build time for reproducible pinning,
# e.g.:
#   docker compose build --build-arg ALPINE_VERSION=3.23.4 --build-arg CICAP_GIT_REF=C_ICAP_0.6.4 --build-arg CICAP_MODULES_GIT_REF=C_ICAP_MODULES_0.5.7
ARG CICAP_GIT_REF=C_ICAP_0.6.4
ARG CICAP_MODULES_GIT_REF=C_ICAP_MODULES_0.5.7

# Build dependencies for c-icap and modules.
RUN apk add --no-cache \
		build-base \
		autoconf \
		automake \
		libtool \
		pkgconf \
		linux-headers \
	git \
		tar \
		xz \
		openssl-dev \
		zlib-dev \
		pcre2-dev \
		bzip2-dev \
		libxml2-dev

WORKDIR /tmp/build

# Build and install c-icap.
RUN set -eu; \
	echo "[c-icap] cloning GitHub ref ${CICAP_GIT_REF}"; \
	git clone --depth 1 --branch "${CICAP_GIT_REF}" https://github.com/c-icap/c-icap-server.git c_icap_src; \
	cd c_icap_src; \
	if [ ! -x ./configure ]; then autoreconf -fi; fi; \
	./configure \
		--prefix=/usr \
		--sysconfdir=/etc \
		--localstatedir=/var \
		--disable-static; \
	make -j"$(getconf _NPROCESSORS_ONLN || echo 2)"; \
	make install

# Build and install c-icap modules.
RUN set -eu; \
	echo "[c-icap-modules] cloning GitHub ref ${CICAP_MODULES_GIT_REF}"; \
	git clone --depth 1 --branch "${CICAP_MODULES_GIT_REF}" https://github.com/c-icap/c-icap-modules.git c_icap_modules_src; \
	cd c_icap_modules_src; \
	if [ ! -x ./configure ]; then autoreconf -fi; fi; \
	./configure \
		--prefix=/usr \
		--sysconfdir=/etc \
		--localstatedir=/var \
		--disable-static; \
	make -j"$(getconf _NPROCESSORS_ONLN || echo 2)"; \
	make install

# Stage runtime artifacts for the final image.
RUN set -eu; \
	mkdir -p /out; \
	# Binaries
	mkdir -p /out/usr/sbin /out/usr/bin; \
	if [ -x /usr/sbin/c-icap ]; then cp -a /usr/sbin/c-icap /out/usr/sbin/; fi; \
	if [ -x /usr/bin/c-icap ]; then cp -a /usr/bin/c-icap /out/usr/bin/; fi; \
	if [ -x /usr/bin/c-icap-client ]; then cp -a /usr/bin/c-icap-client /out/usr/bin/; fi; \
	# Core shared libs (c-icap installs libicapapi under /usr/lib)
	if ls /usr/lib/libicapapi.so* >/dev/null 2>&1; then mkdir -p /out/usr/lib; cp -a /usr/lib/libicapapi.so* /out/usr/lib/; fi; \
	# Modules and templates
	if [ -d /usr/lib/c_icap ]; then mkdir -p /out/usr/lib; cp -a /usr/lib/c_icap /out/usr/lib/; fi; \
	if [ -d /usr/share/c_icap ]; then mkdir -p /out/usr/share; cp -a /usr/share/c_icap /out/usr/share/; fi; \
	# Default config directory (we'll override main config in runtime)
	if [ -d /etc/c-icap ]; then mkdir -p /out/etc; cp -a /etc/c-icap /out/etc/; fi; \
	# c-icap-modules configs (virus_scan + clamd_mod)
	if [ -f /etc/virus_scan.conf ]; then mkdir -p /out/etc; cp -a /etc/virus_scan.conf /out/etc/; fi; \
	if [ -f /etc/clamd_mod.conf ]; then mkdir -p /out/etc; cp -a /etc/clamd_mod.conf /out/etc/; fi


FROM alpine:${ALPINE_VERSION}

# Install necessary packages
# Note: Alpine's squid package does not ship the legacy `squidclient` binary.
RUN apk add --no-cache squid dante-server python3 py3-flask py3-gunicorn py3-pip supervisor openssl ca-certificates libatomic \
		pcre2 \
		file

# Set working directory
WORKDIR /app

# Copy the Flask application

COPY web /app
COPY squid /squid
COPY scripts /scripts
COPY docker/entrypoint.sh /entrypoint.sh
COPY docker/supervisord.conf /etc/supervisord.conf
COPY docker/pac_http.conf /etc/supervisor.d/pac_http.conf
COPY docker/healthcheck.sh /healthcheck.sh
COPY docker/squid_logrotate.sh /usr/local/bin/squid_logrotate.sh

# c-icap (built from source in the builder stage)
COPY --from=cicap_builder /out/ /
COPY docker/c-icap.conf /etc/c-icap/c-icap.conf
COPY docker/adblock_req.conf /etc/adblock_req.conf
COPY docker/clamd_mod.conf /etc/clamd_mod.conf
COPY docker/virus_scan.conf /etc/virus_scan.conf

# Python runtime dependencies not shipped by Alpine packages.
RUN python3 -m pip install --no-cache-dir --break-system-packages -r /app/requirements.txt

# Make entrypoint script executable
RUN chmod +x /entrypoint.sh /healthcheck.sh /usr/local/bin/squid_logrotate.sh /scripts/*.sh \
	&& mkdir -p /etc/squid/ssl/certs /var/lib/ssl_db /var/spool/squid

# Install custom Squid error pages (keeps built-in pages intact)
RUN if [ -f /squid/error_pages/en/ERR_WEBFILTER_BLOCKED ] && [ -d /usr/share/squid/errors/en ]; then \
		cp -f /squid/error_pages/en/ERR_WEBFILTER_BLOCKED /usr/share/squid/errors/en/; \
	fi

# Expose ports for Flask, Squid, PAC/HTTP, and Dante (SOCKS5)
EXPOSE 5000 3128 80 1080

# Set the entry point
ENTRYPOINT ["/entrypoint.sh"]