# Docker Proxy Squid error pages

This directory contains the branded Squid error-page templates that are packaged into the proxy image.

## Packaging contract

- Tracked templates live under `squid/error_pages/en/`.
- The proxy image copies every tracked `ERR_*` template into Squid's runtime English error directory: `/usr/share/squid/errors/en/`.
- `squid/squid.conf.template` points Squid at that packaged directory with `error_directory /usr/share/squid/errors/en`.
- `ERR_WEBFILTER_BLOCKED` is Docker Proxy-specific; the other `ERR_*` files mirror the managed Squid template manifest in `web/services/error_pages.py`.

## Template safety

Squid expands percent-placeholders such as `%U`, `%T`, and `%s` at render time. Keep placeholders in text content, avoid credential-bearing tokens such as `%u` and full-request tokens such as `%R`, and do not place raw request-derived placeholders into links, form actions, or hidden form values.

Run the error-page tests after changing this tree; they verify manifest coverage, placeholder usage, packaging assumptions, and preview rendering.
