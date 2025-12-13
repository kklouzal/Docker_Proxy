FROM alpine:latest

# Install necessary packages
# Note: Alpine's squid package does not ship the legacy `squidclient` binary.
#
# Adblocking performance: try to enable RE2 (fast regex engine) for adblockparser.
# On Alpine, prefer the packaged Python binding (`py3-re2`) over the PyPI `re2` module,
# which frequently fails to build on newer Python versions.
RUN apk add --no-cache squid dante-server python3 py3-flask py3-gunicorn supervisor openssl ca-certificates py3-re2 py3-brotli \
		clamav clamav-daemon \
	&& apk add --no-cache --virtual .pip-deps py3-pip \
	&& python3 -m pip install --no-cache-dir --break-system-packages adblockparser \
	&& apk del .pip-deps

# Set working directory
WORKDIR /app

# Copy the Flask application

COPY web /app
COPY squid /squid
COPY scripts /scripts
COPY docker/entrypoint.sh /entrypoint.sh
COPY docker/supervisord.conf /etc/supervisord.conf
COPY docker/clamd.conf /etc/clamav/clamd.conf
COPY docker/freshclam.conf /etc/clamav/freshclam.conf
COPY docker/healthcheck.sh /healthcheck.sh

# Make entrypoint script executable
RUN chmod +x /entrypoint.sh /healthcheck.sh /scripts/*.sh \
	&& mkdir -p /etc/squid/ssl/certs /var/lib/ssl_db /var/spool/squid

# Expose ports for Flask, Squid, and Dante (SOCKS5)
EXPOSE 5000 3128 1080

# Set the entry point
ENTRYPOINT ["/entrypoint.sh"]