from __future__ import annotations

import http.client
import ipaddress
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

_ALLOWED_DOWNLOAD_REQUEST_HEADERS = {
    "if-modified-since": "If-Modified-Since",
    "if-none-match": "If-None-Match",
}


@dataclass(frozen=True)
class _ResolvedDownloadAddress:
    family: int
    socktype: int
    proto: int
    sockaddr: tuple


def _is_forbidden_download_ip(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return (
        ip.is_loopback
        or ip.is_private
        or ip.is_reserved
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or not ip.is_global
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


def _resolve_download_addresses(
    hostname: str,
    port: int,
) -> tuple[_ResolvedDownloadAddress, ...]:
    try:
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError):
        return ()

    addresses: list[_ResolvedDownloadAddress] = []
    seen: set[tuple[int, int, int, tuple]] = set()
    for info in infos:
        if not info or not info[4]:
            continue
        family, socktype, proto, _canonname, sockaddr = info
        address = sockaddr[0]
        if _is_forbidden_download_ip(address):
            return ()
        resolved_sockaddr = (address, port, *sockaddr[2:])
        item = _ResolvedDownloadAddress(family, socktype, proto, resolved_sockaddr)
        key = (item.family, item.socktype, item.proto, item.sockaddr)
        if key in seen:
            continue
        seen.add(key)
        addresses.append(item)
    return tuple(addresses)


def _download_url_port(parsed) -> int:
    port = parsed.port
    if port is None:
        return 443 if parsed.scheme == "https" else 80
    return port


def _create_download_connection(
    addresses: tuple[_ResolvedDownloadAddress, ...],
):
    def create_connection(
        _address,
        timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
        source_address=None,
    ):
        last_error: OSError | None = None
        for address in addresses:
            try:
                return socket.create_connection(
                    address.sockaddr,
                    timeout,
                    source_address,
                )
            except OSError as exc:
                last_error = exc
        if last_error is not None:
            raise last_error
        raise OSError("no vetted download addresses available")

    return create_connection


def _download_connection_class(
    base_class: type[http.client.HTTPConnection],
    addresses: tuple[_ResolvedDownloadAddress, ...],
) -> type[http.client.HTTPConnection]:
    class _VettedDownloadConnection(base_class):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._create_connection = _create_download_connection(addresses)

    return _VettedDownloadConnection


class _BoundAddressHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, addresses: tuple[_ResolvedDownloadAddress, ...]):
        super().__init__()
        self._addresses = addresses

    def http_open(self, req):
        return self.do_open(
            _download_connection_class(http.client.HTTPConnection, self._addresses),
            req,
        )


class _BoundAddressHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, addresses: tuple[_ResolvedDownloadAddress, ...]):
        super().__init__()
        self._addresses = addresses

    def https_open(self, req):
        return self.do_open(
            _download_connection_class(http.client.HTTPSConnection, self._addresses),
            req,
            context=self._context,
        )


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl) -> None:
        return None


def _url_origin(parsed) -> tuple[str, str, int | None]:
    scheme = str(parsed.scheme or "").lower()
    port = parsed.port
    if port is None:
        if scheme == "http":
            port = 80
        elif scheme == "https":
            port = 443
    return (
        scheme,
        str(parsed.hostname or "").lower().rstrip("."),
        port,
    )


def _safe_extra_download_headers(headers: dict[str, str] | None) -> dict[str, str]:
    if not headers:
        return {}
    safe_headers: dict[str, str] = {}
    for key, value in headers.items():
        if not key or not value:
            continue
        name = str(key)
        header_value = str(value)
        if (
            name != name.strip()
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in name)
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in header_value)
        ):
            continue
        safe_name = _ALLOWED_DOWNLOAD_REQUEST_HEADERS.get(name.lower())
        if safe_name is None:
            continue
        safe_headers[safe_name] = header_value
    return safe_headers


def _build_download_request(
    url: str,
    *,
    headers: dict[str, str],
) -> urllib.request.Request:
    return urllib.request.Request(url, headers=headers, method="GET")  # noqa: S310


def validate_download_url(
    url: str,
    *,
    scheme_error: str = "Only http/https URLs are supported.",
):
    invalid_url_msg = "Download URLs must be valid absolute HTTP/HTTPS URLs."
    source = str(url or "")
    if (
        not source
        or "\\" in source
        or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in source)
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
    base_headers = {"User-Agent": user_agent}
    safe_headers = _safe_extra_download_headers(headers)
    request_headers = {**safe_headers, **base_headers}
    for _ in range(max_redirects + 1):
        parsed = validate_download_url(current, scheme_error=scheme_error)
        addresses = _resolve_download_addresses(
            str(parsed.hostname or ""),
            _download_url_port(parsed),
        )
        if not addresses:
            msg = "Downloads from internal/localhost addresses are not allowed."
            raise ValueError(msg)
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _BoundAddressHTTPHandler(addresses),
            _BoundAddressHTTPSHandler(addresses),
            _NoRedirectHandler,
        )
        req = _build_download_request(current, headers=request_headers)
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
            if parsed.scheme == "https" and redirect_parsed.scheme == "http":
                msg = "Download redirects must not downgrade from https to http."
                raise ValueError(msg) from exc
            if _url_origin(redirect_parsed) != _url_origin(parsed):
                request_headers = dict(base_headers)
            current = redirect_url
    msg = f"Download exceeded redirect limit ({max_redirects})."
    raise ValueError(msg)
