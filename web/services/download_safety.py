from __future__ import annotations

import http.client
import ipaddress
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

_ALLOWED_DOWNLOAD_REQUEST_HEADERS = {
    "if-modified-since": "If-Modified-Since",
    "if-none-match": "If-None-Match",
}

_RESERVED_DOWNLOAD_HOSTS = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "home.arpa",
}
_RESERVED_DOWNLOAD_SUFFIXES = (
    ".local",
    ".localdomain",
    ".internal",
    ".localhost",
    ".home.arpa",
)


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


def _canonical_download_hostname(hostname: str) -> str:
    h = (hostname or "").strip()
    if not h:
        return ""
    try:
        return h.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        msg = "Download hostname must be a valid DNS name or IP address."
        raise ValueError(msg) from exc


def _is_ambiguous_ipv4_download_host(hostname: str) -> bool:
    candidate = hostname.rstrip(".").lower()
    if not candidate:
        return False
    labels = candidate.split(".")
    if not 1 <= len(labels) <= 4:
        return False
    for label in labels:
        if not label:
            return False
        if label.isdecimal():
            continue
        if label.startswith("0x"):
            digits = label.removeprefix("0x")
            if digits and all(ch in "0123456789abcdef" for ch in digits):
                continue
        return False
    return True


def _canonical_download_url(parsed, hostname: str) -> str:
    host = f"[{hostname}]" if ":" in hostname else hostname
    port = parsed.port
    if port is not None:
        host = f"{host}:{port}"
    return parsed._replace(netloc=host).geturl()


def is_internal_host(hostname: str) -> bool:
    try:
        h = _canonical_download_hostname(hostname)
    except ValueError:
        return True
    if not h:
        return True
    if h in _RESERVED_DOWNLOAD_HOSTS:
        return True
    try:
        return _is_forbidden_download_ip(h)
    except ValueError:
        pass
    if _is_ambiguous_ipv4_download_host(h):
        return True
    if h.endswith(_RESERVED_DOWNLOAD_SUFFIXES):
        return True
    if "." not in h:
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


def _has_empty_explicit_authority_port(netloc: str) -> bool:
    authority = netloc.rsplit("@", 1)[-1]
    if authority.startswith("["):
        bracket_end = authority.find("]")
        return bracket_end >= 0 and authority[bracket_end + 1 :] == ":"
    return authority.endswith(":") and ":" in authority


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
            sock = None
            try:
                if len(address.sockaddr) == 2:
                    return socket.create_connection(
                        address.sockaddr,
                        timeout,
                        source_address,
                    )
                sock = socket.socket(address.family, address.socktype, address.proto)
                if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                    sock.settimeout(timeout)
                if source_address:
                    sock.bind(source_address)
                sock.connect(address.sockaddr)
                return sock
            except OSError as exc:
                last_error = exc
                if sock is not None:
                    sock.close()
        if last_error is not None:
            raise last_error
        msg = "no vetted download addresses available"
        raise OSError(msg)

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


def _has_http_header_control_chars(value: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


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
            or _has_http_header_control_chars(name)
            or _has_http_header_control_chars(header_value)
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


def _validate_download_redirect_location(location: str) -> None:
    if (
        not location
        or "\\" in location
        or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in location)
    ):
        msg = "Download redirect Location must be a valid HTTP URI reference."
        raise ValueError(msg)


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
    if _has_empty_explicit_authority_port(parsed.netloc) or "%" in parsed.netloc:
        raise ValueError(invalid_url_msg)
    try:
        hostname = parsed.hostname or ""
        _port = parsed.port
    except ValueError as exc:
        raise ValueError(invalid_url_msg) from exc
    if _port is not None and _port < 1:
        raise ValueError(invalid_url_msg)
    if not parsed.netloc or not hostname or parsed.fragment:
        raise ValueError(invalid_url_msg)
    if parsed.username or parsed.password:
        msg = "Download URLs must not include embedded credentials."
        raise ValueError(msg)
    try:
        hostname = _canonical_download_hostname(hostname)
    except ValueError as exc:
        raise ValueError(invalid_url_msg) from exc
    if is_internal_host(hostname):
        msg = "Downloads from internal/localhost addresses are not allowed."
        raise ValueError(msg)
    return parsed


def _remaining_download_timeout(deadline: float, timeout_seconds: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        msg = f"Download timed out after {timeout_seconds:g} seconds."
        raise TimeoutError(msg)
    return remaining


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
    user_agent_value = str(user_agent)
    if _has_http_header_control_chars(user_agent_value):
        msg = "Download user agent must be a valid HTTP header value."
        raise ValueError(msg)
    base_headers = {"User-Agent": user_agent_value}
    safe_headers = _safe_extra_download_headers(headers)
    request_headers = {**safe_headers, **base_headers}
    timeout_seconds = float(timeout)
    deadline = time.monotonic() + timeout_seconds
    for _ in range(max_redirects + 1):
        _remaining_download_timeout(deadline, timeout_seconds)
        parsed = validate_download_url(current, scheme_error=scheme_error)
        hostname = _canonical_download_hostname(str(parsed.hostname or ""))
        current = _canonical_download_url(parsed, hostname)
        addresses = _resolve_download_addresses(
            hostname,
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
            return opener.open(
                req,
                timeout=_remaining_download_timeout(deadline, timeout_seconds),
            )
        except urllib.error.HTTPError as exc:
            if exc.code not in {301, 302, 303, 307, 308}:
                raise
            location = exc.headers.get("Location") if exc.headers is not None else None
            if not location:
                msg = "Download redirect response did not include a Location header."
                raise ValueError(msg) from exc
            _validate_download_redirect_location(str(location))
            redirect_url = urljoin(current, location)
            redirect_parsed = validate_download_url(
                redirect_url,
                scheme_error=scheme_error,
            )
            redirect_url = _canonical_download_url(
                redirect_parsed,
                _canonical_download_hostname(str(redirect_parsed.hostname or "")),
            )
            if parsed.scheme == "https" and redirect_parsed.scheme == "http":
                msg = "Download redirects must not downgrade from https to http."
                raise ValueError(msg) from exc
            if _url_origin(redirect_parsed) != _url_origin(parsed):
                request_headers = dict(base_headers)
            current = redirect_url
    msg = f"Download exceeded redirect limit ({max_redirects})."
    raise ValueError(msg)
