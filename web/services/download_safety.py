from __future__ import annotations

import ipaddress
import socket
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlparse


def _is_forbidden_download_ip(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return (
        ip.is_loopback
        or ip.is_private
        or ip.is_reserved
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
    )


def is_internal_host(hostname: str) -> bool:
    h = (hostname or "").strip().lower().rstrip(".")
    if not h:
        return True
    if h in {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}:
        return True
    try:
        return _is_forbidden_download_ip(h)
    except ValueError:
        pass
    if h.endswith((".local", ".internal", ".localhost")):
        return True

    try:
        infos = socket.getaddrinfo(h, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError):
        return True

    resolved = {info[4][0] for info in infos if info and info[4]}
    if not resolved:
        return True
    return any(_is_forbidden_download_ip(address) for address in resolved)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl) -> None:
        return None


def _url_origin(parsed) -> tuple[str, str, int | None]:
    return (
        str(parsed.scheme or "").lower(),
        str(parsed.hostname or "").lower().rstrip("."),
        parsed.port,
    )


def validate_download_url(
    url: str,
    *,
    scheme_error: str = "Only http/https URLs are supported.",
):
    invalid_url_msg = "Download URLs must be valid absolute HTTP/HTTPS URLs."
    source = str(url or "")
    if not source or any(
        ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in source
    ):
        raise ValueError(invalid_url_msg)
    try:
        parsed = urlparse(source)
    except ValueError as exc:
        raise ValueError(invalid_url_msg) from exc
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(scheme_error)
    try:
        hostname = parsed.hostname or ""
        _port = parsed.port
    except ValueError as exc:
        raise ValueError(invalid_url_msg) from exc
    if not parsed.netloc or not hostname:
        raise ValueError(invalid_url_msg)
    if parsed.username or parsed.password:
        msg = "Download URLs must not include embedded credentials."
        raise ValueError(msg)
    if is_internal_host(hostname):
        msg = "Downloads from internal/localhost addresses are not allowed."
        raise ValueError(msg)
    return parsed


def open_download_url(
    url: str,
    *,
    timeout: int,
    user_agent: str,
    max_redirects: int = 5,
    headers: dict[str, str] | None = None,
    scheme_error: str = "Only http/https URLs are supported.",
):
    current = url
    opener = urllib.request.build_opener(_NoRedirectHandler)
    base_headers = {"User-Agent": user_agent}
    request_headers = dict(base_headers)
    if headers:
        request_headers.update({str(k): str(v) for k, v in headers.items() if k and v})
    for _ in range(max_redirects + 1):
        parsed = validate_download_url(current, scheme_error=scheme_error)
        req = urllib.request.Request(current, headers=request_headers)  # noqa: S310
        try:
            return opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as exc:
            if exc.code not in {301, 302, 303, 307, 308}:
                raise
            location = exc.headers.get("Location") if exc.headers is not None else None
            if not location:
                msg = "Download redirect response did not include a Location header."
                raise ValueError(msg) from exc
            redirect_url = urljoin(current, location)
            redirect_parsed = validate_download_url(
                redirect_url,
                scheme_error=scheme_error,
            )
            if _url_origin(redirect_parsed) != _url_origin(parsed):
                request_headers = dict(base_headers)
            current = redirect_url
    msg = f"Download exceeded redirect limit ({max_redirects})."
    raise ValueError(msg)
