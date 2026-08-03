from __future__ import annotations

import contextlib
import hashlib
import inspect
import ipaddress
import json
import os
import shutil
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from services.pac_private_local import (
    LOCAL_DOMAIN_SUFFIXES,
    PAC_PRIVATE_LOCAL_IPV4_NETS,
    PAC_PRIVATE_LOCAL_IPV6_HEXTET_RANGES,
)
from services.pac_profiles_store import (
    PacProfile,
    _normalize_pac_dst_v4_cidr,
    _normalize_proxy_host_port,
    get_pac_profiles_store,
)
from services.pac_profiles_store import (
    _normalize_domain as _normalize_pac_direct_domain,
)
from services.proxy_context import (
    get_proxy_id,
    normalize_proxy_id,
    reset_proxy_id,
    set_proxy_id,
)
from services.proxy_registry import (
    _parse_public_pac_url,
    get_proxy_registry,
    normalize_public_pac_path,
)
from services.public_endpoint import (
    _is_ambiguous_ipv4_host,
    _is_reserved_public_dns_host,
    _is_unsafe_request_host_ip,
)
from services.public_endpoint import (
    coerce_public_port as _coerce_port,
)
from services.public_endpoint import (
    normalize_public_host as _normalize_public_host,
)
from services.public_endpoint import (
    normalize_public_scheme as _normalize_pac_scheme,
)
from services.sslfilter_store import get_sslfilter_store

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

PAC_HOST_PLACEHOLDER = "__PAC_PROXY_HOST__"
PAC_MANIFEST_FILENAME = "manifest.json"
PAC_STATE_SHA_FILENAME = ".state-sha256"
PAC_RENDER_DIR = "/var/lib/squid-flask-proxy/pac"
_PAC_MATERIALIZATION_TARGET_LOCKS_GUARD = threading.Lock()
_PAC_MATERIALIZATION_TARGET_LOCKS: dict[str, threading.Lock] = {}


def _pac_materialization_target_key(path: str | os.PathLike[str]) -> str:
    return str(Path(path).resolve(strict=False))


def _lock_for_pac_materialization_target(
    path: str | os.PathLike[str],
) -> threading.Lock:
    target_key = _pac_materialization_target_key(path)
    with _PAC_MATERIALIZATION_TARGET_LOCKS_GUARD:
        return _PAC_MATERIALIZATION_TARGET_LOCKS.setdefault(
            target_key,
            threading.Lock(),
        )


@contextlib.contextmanager
def _locked_pac_materialization_target(target: str | os.PathLike[str]):
    lock = _lock_for_pac_materialization_target(target)
    lock.acquire()
    try:
        yield
    finally:
        lock.release()


def _fsync_parent_dir(path: str | os.PathLike[str]) -> None:
    """Best-effort fsync for directory entries created/replaced near path."""
    directory = Path(path).parent or Path()
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    fd: int | None = None
    try:
        fd = os.open(directory, flags)
        os.fsync(fd)
    except OSError:
        # Some platforms/filesystems do not support opening or fsyncing dirs.
        return
    finally:
        if fd is not None:
            with contextlib.suppress(OSError):
                os.close(fd)


def _fsync_dir(path: str | os.PathLike[str]) -> None:
    """Best-effort fsync for a directory's own metadata entries."""
    directory = Path(path)
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    fd: int | None = None
    try:
        fd = os.open(directory, flags)
        os.fsync(fd)
    except OSError:
        return
    finally:
        if fd is not None:
            with contextlib.suppress(OSError):
                os.close(fd)


def _write_pac_text_file(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    with path.open("rb") as handle:
        os.fsync(handle.fileno())
    _fsync_parent_dir(path)


def _build_pac_url(
    *,
    scheme: str,
    host: str,
    port: int,
    path: str = "/proxy.pac",
) -> str:
    clean_host = format_proxy_host(host)
    if not clean_host:
        return ""
    normalized_scheme = _normalize_pac_scheme(scheme)
    default_port = 443 if normalized_scheme == "https" else 80
    port_part = "" if int(port) == default_port else f":{int(port)}"
    pac_path = normalize_public_pac_path(path)
    return f"{normalized_scheme}://{clean_host}{port_part}{pac_path}"


def _normalize_domain_rule(domain: str) -> str:
    normalized, _err = _normalize_pac_direct_domain(domain)
    return normalized or ""


def _domain_match_expression(domain: str) -> str:
    normalized = _normalize_domain_rule(domain)
    wildcard = normalized.startswith("*.")
    normalized = normalized[2:] if wildcard else normalized.lstrip(".")
    if not normalized:
        return ""
    if wildcard:
        return (
            f"host === {json.dumps(normalized)} || "
            f"dnsDomainIs(host, {json.dumps(f'.{normalized}')})"
        )
    return f"host === {json.dumps(normalized)}"


def _normalize_backup_proxy_entry(
    proxy_host: object | None,
    proxy_port: object | None,
) -> tuple[str, int] | None:
    host, port, _err = _normalize_proxy_host_port(
        str(proxy_host or ""),
        proxy_port,
    )
    if host is None or port is None:
        return None
    return _format_host_only_for_pac(host), int(port)


@dataclass(frozen=True)
class ProxyPacTarget:
    proxy_id: str
    public_host: str
    pac_scheme: str
    pac_port: int
    http_proxy_port: int
    backup_proxies: tuple[tuple[str, object | None], ...] = ()
    direct_enabled: bool = True
    pac_path: str = "/proxy.pac"

    @property
    def uses_request_host_fallback(self) -> bool:
        return not bool(self.public_host)

    @property
    def proxy_host_token(self) -> str:
        return (
            format_proxy_host(self.public_host)
            if self.public_host
            else PAC_HOST_PLACEHOLDER
        )

    @property
    def pac_url(self) -> str:
        if not self.public_host:
            return ""
        return _build_pac_url(
            scheme=self.pac_scheme,
            host=self.public_host,
            port=self.pac_port,
            path=self.pac_path,
        )

    @property
    def proxy_chain(self) -> str:
        return self._build_proxy_chain(display=False)

    @property
    def proxy_chain_display(self) -> str:
        return self._build_proxy_chain(display=True)

    @property
    def normalized_backup_proxies(self) -> tuple[tuple[str, int], ...]:
        entries: list[tuple[str, int]] = []
        for backup_host, backup_port in self.backup_proxies:
            normalized = _normalize_backup_proxy_entry(backup_host, backup_port)
            if normalized is None:
                continue
            entries.append(normalized)
        return tuple(entries)

    def _build_proxy_chain(self, *, display: bool) -> str:
        if display and not self.public_host:
            host = "<request-host>"
        else:
            host = self.proxy_host_token
        seen_endpoints = {
            _proxy_chain_endpoint_key(self.proxy_host_token, self.http_proxy_port),
        }
        entries = [f"PROXY {host}:{self.http_proxy_port}"]
        for rendered_host, backup_port in self.normalized_backup_proxies:
            endpoint_key = _proxy_chain_endpoint_key(rendered_host, backup_port)
            if endpoint_key in seen_endpoints:
                continue
            seen_endpoints.add(endpoint_key)
            entries.append(f"PROXY {rendered_host}:{int(backup_port)}")
        if self.direct_enabled:
            entries.append("DIRECT")
        return "; ".join(entries)


@dataclass(frozen=True)
class RenderedPacFile:
    relative_path: str
    content: str


@dataclass(frozen=True)
class ProxyPacState:
    proxy_id: str
    state_sha256: str
    files: tuple[RenderedPacFile, ...]


def _request_host_only(raw_host: str) -> str:
    candidate = (raw_host or "").strip()
    if not candidate:
        return "127.0.0.1"
    if "://" in candidate:
        try:
            parsed = urlsplit(candidate)
            if parsed.hostname:
                return parsed.hostname
        except Exception:
            pass
    if candidate.count(":") > 1 and not candidate.startswith("["):
        return candidate
    try:
        parsed = urlsplit(f"//{candidate}")
        if parsed.hostname:
            return parsed.hostname
    except Exception:
        pass
    if candidate.startswith("[") and "]" in candidate:
        return candidate[1 : candidate.find("]")]
    if candidate.count(":") == 1:
        host, port = candidate.rsplit(":", 1)
        if port.isdigit():
            return host or "127.0.0.1"
    return candidate


def _valid_proxy_dns_host(value: str) -> bool:
    candidate = value.rstrip(".").lower()
    if not candidate or len(candidate) > 253:
        return False
    labels = candidate.split(".")
    return not any(
        not label
        or len(label) > 63
        or not ("a" <= label[0] <= "z" or "0" <= label[0] <= "9")
        or not ("a" <= label[-1] <= "z" or "0" <= label[-1] <= "9")
        or any(not ("a" <= ch <= "z" or "0" <= ch <= "9" or ch == "-") for ch in label)
        for label in labels
    )


def _normalize_proxy_host_only(host: str, *, allow_private: bool = False) -> str:
    candidate = str(host or "").strip()
    if not candidate:
        return "127.0.0.1"
    try:
        parsed_ip = ipaddress.ip_address(candidate)
    except ValueError:
        normalized_dns = candidate.rstrip(".").lower()
        if (
            _is_ambiguous_ipv4_host(normalized_dns)
            or not _valid_proxy_dns_host(normalized_dns)
            or _is_reserved_public_dns_host(normalized_dns)
        ):
            return "127.0.0.1"
        return normalized_dns
    if getattr(parsed_ip, "scope_id", None):
        return "127.0.0.1"
    if allow_private and not _is_unsafe_request_host_ip(parsed_ip):
        return str(parsed_ip)
    if parsed_ip.is_multicast or not parsed_ip.is_global:
        return "127.0.0.1"
    return str(parsed_ip)


def format_proxy_host(raw_host: str) -> str:
    host = _normalize_proxy_host_only(_request_host_only(raw_host))
    return _format_host_only_for_pac(host)


def _format_request_proxy_host(raw_host: str) -> str:
    host = _normalize_proxy_host_only(
        _request_host_only(raw_host),
        allow_private=True,
    )
    return _format_host_only_for_pac(host)


def _format_host_only_for_pac(host: str) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host or "127.0.0.1"


def _proxy_chain_endpoint_key(host: str, port: object) -> tuple[str, int]:
    normalized_host = str(host or "").strip()
    if normalized_host.startswith("[") and "]" in normalized_host:
        normalized_host = normalized_host[1 : normalized_host.find("]")]
    normalized_host = normalized_host.rstrip(".").lower()
    try:
        normalized_host = str(ipaddress.ip_address(normalized_host))
    except ValueError:
        pass
    return normalized_host, int(port)


def resolve_proxy_pac_target(
    proxy_id: object | None = None,
    *,
    pac_profiles_store: object | None = None,
    proxy_registry: object | None = None,
) -> ProxyPacTarget:
    normalized_proxy_id = (
        get_proxy_id() if proxy_id is None else normalize_proxy_id(proxy_id)
    )
    try:
        registry = proxy_registry or get_proxy_registry()
        proxy = registry.get_proxy(normalized_proxy_id)
    except Exception:
        proxy = None

    (
        url_public_host,
        url_pac_scheme,
        url_pac_port,
        url_pac_path,
    ) = _parse_public_pac_url(
        os.environ.get("PROXY_PUBLIC_PAC_URL"),
    )
    env_public_host = (
        _normalize_public_host(
            os.environ.get("PROXY_PUBLIC_HOST"),
            allow_single_label=True,
        )
        or url_public_host
    )
    proxy_public_host = _normalize_public_host(
        getattr(proxy, "public_host", ""),
        allow_single_label=True,
    )
    public_host = proxy_public_host or env_public_host

    env_pac_scheme = _normalize_pac_scheme(
        os.environ.get("PROXY_PUBLIC_PAC_SCHEME") or url_pac_scheme,
    )
    proxy_owns_public_endpoint = bool(proxy_public_host)
    pac_scheme = _normalize_pac_scheme(
        getattr(proxy, "public_pac_scheme", None)
        if proxy is not None and proxy_owns_public_endpoint
        else env_pac_scheme,
    )
    default_pac_port = 443 if pac_scheme == "https" else 80
    env_pac_port = _coerce_port(
        os.environ.get("PROXY_PUBLIC_PAC_PORT"),
        url_pac_port or default_pac_port,
    )
    pac_port = _coerce_port(
        getattr(proxy, "public_pac_port", None)
        if proxy is not None and proxy_owns_public_endpoint
        else os.environ.get("PROXY_PUBLIC_PAC_PORT"),
        env_pac_port,
    )
    env_http_proxy_port = _coerce_port(
        os.environ.get("PROXY_PUBLIC_HTTP_PROXY_PORT"),
        3128,
    )
    http_proxy_port = _coerce_port(
        getattr(proxy, "public_http_proxy_port", None)
        if proxy is not None and proxy_owns_public_endpoint
        else os.environ.get("PROXY_PUBLIC_HTTP_PROXY_PORT"),
        env_http_proxy_port,
    )
    proxy_pac_path = normalize_public_pac_path(
        getattr(proxy, "public_pac_path", "") or "",
        default="",
    )
    pac_path = proxy_pac_path if proxy_owns_public_endpoint else url_pac_path
    if not pac_path:
        pac_path = "/proxy.pac"
    backup_proxies: tuple[tuple[str, object | None], ...] = ()
    direct_enabled = True
    token = set_proxy_id(normalized_proxy_id)
    try:
        store = pac_profiles_store or get_pac_profiles_store()
        chain_settings = store.list_proxy_chain_settings()
        backup_proxies = tuple(
            (
                str(getattr(item, "proxy_host", "") or ""),
                getattr(item, "proxy_port", None),
            )
            for item in list(getattr(chain_settings, "backup_proxies", []) or [])
        )
        direct_enabled = bool(getattr(chain_settings, "direct_enabled", True))
    except Exception:
        backup_proxies = ()
        direct_enabled = True
    finally:
        reset_proxy_id(token)
    return ProxyPacTarget(
        proxy_id=normalized_proxy_id,
        public_host=public_host,
        pac_scheme=pac_scheme,
        pac_port=pac_port,
        http_proxy_port=http_proxy_port,
        backup_proxies=backup_proxies,
        direct_enabled=direct_enabled,
        pac_path=pac_path,
    )


def build_public_pac_url(raw_host: str = "", *, proxy_id: object | None = None) -> str:
    if proxy_id is not None:
        return resolve_proxy_pac_target(proxy_id).pac_url
    candidate = (raw_host or "").strip()
    if not candidate:
        return ""
    return _build_pac_url(scheme="http", host=candidate, port=80)


def _cidr_to_mask(cidr: str) -> str:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return "255.255.255.255"
    if net.version != 4:
        return "255.255.255.255"
    return str(net.netmask)


def _render_pac(
    proxy_chain: str,
    *,
    proxy_host: str,
    direct_domains: list[str],
    direct_dst_nets: list[str],
    include_private: bool,
) -> str:
    lines: list[str] = []
    lines.extend(
        (
            "function FindProxyForURL(url, host) {",
            "  function normalizePacHost(value) {",
            "    var normalized = (value || '').toLowerCase().replace(/^\\s+|\\s+$/g, '');",
            "    if (normalized.charAt(0) === '[') {",
            "      var bracketEnd = normalized.indexOf(']');",
            "      if (bracketEnd >= 0) normalized = normalized.substring(1, bracketEnd);",
            "    } else {",
            "      var colon = normalized.lastIndexOf(':');",
            "      if (colon >= 0 && normalized.indexOf(':') === colon) {",
            "        var maybePort = normalized.substring(colon + 1);",
            "        if (/^\\d+$/.test(maybePort)) normalized = normalized.substring(0, colon);",
            "      }",
            "    }",
            "    return normalized.replace(/\\.+$/, '');",
            "  }",
            "  host = normalizePacHost(host);",
            f"  var proxyHost = {json.dumps(str(proxy_host or PAC_HOST_PLACEHOLDER))};",
            "  var normalizedProxyHost = normalizePacHost(proxyHost);",
            "  var isIpv6Literal = host.indexOf(':') >= 0;",
            "  var ipv6FirstHextet = isIpv6Literal ? host.split(':', 1)[0] : '';",
            "  function isIpv4Address(value) {",
            "    if (!/^(?:\\d{1,3}\\.){3}\\d{1,3}$/.test(value || '')) return false;",
            "    var parts = value.split('.');",
            "    for (var i = 0; i < parts.length; i += 1) {",
            "      var octet = parseInt(parts[i], 10);",
            "      if (octet < 0 || octet > 255 || String(octet) !== parts[i]) return false;",
            "    }",
            "    return true;",
            "  }",
            "  if (host === 'localhost' || host === '127.0.0.1' || host === '::1') return 'DIRECT';",
            "  if (isIpv4Address(host) && isInNet(host, '127.0.0.0', '255.0.0.0')) return 'DIRECT';",
            "  if (!isIpv6Literal && isPlainHostName(host)) return 'DIRECT';",
            "  if (host === normalizedProxyHost) return 'DIRECT';",
        ),
    )
    lines.extend(
        f"  if (dnsDomainIs(host, {json.dumps(suffix)})) return 'DIRECT';"
        for suffix in LOCAL_DOMAIN_SUFFIXES
    )
    lines.extend(
        (
            "",
            "  var cachedIp = '';",
            "  function hostIp() {",
            "    if (cachedIp) return cachedIp;",
            "    if (isIpv4Address(host)) {",
            "      cachedIp = host;",
            "      return cachedIp;",
            "    }",
            "    cachedIp = dnsResolve(host) || '';",
            "    return cachedIp;",
            "  }",
        ),
    )

    normalized_domains: set[str] = set()
    for domain in direct_domains:
        d = _normalize_domain_rule(domain)
        if not d:
            continue
        normalized_domains.add(d)
    for d in sorted(normalized_domains):
        match_expression = _domain_match_expression(d)
        if match_expression:
            lines.append(f"  if ({match_expression}) return 'DIRECT';")

    needs_ip_lookup = bool(direct_dst_nets or include_private)
    if needs_ip_lookup:
        lines.extend(
            (
                "",
                "  var ip = hostIp();",
                "  var hasIpv4 = isIpv4Address(ip);",
                "  if (hasIpv4 && isInNet(ip, '127.0.0.0', '255.0.0.0')) return 'DIRECT';",
            ),
        )

    normalized_dst_nets: set[str] = set()
    for cidr in direct_dst_nets:
        canonical_cidr, _err = _normalize_pac_dst_v4_cidr(cidr)
        if not canonical_cidr:
            continue
        normalized_dst_nets.add(canonical_cidr)

    for canonical_cidr in sorted(
        normalized_dst_nets,
        key=lambda value: ipaddress.ip_network(value, strict=False),
    ):
        net = ipaddress.ip_network(canonical_cidr, strict=False)
        lines.append(
            f"  if (hasIpv4 && isInNet(ip, '{net.network_address}', '{_cidr_to_mask(canonical_cidr)}')) return 'DIRECT';",
        )

    if include_private:
        ipv6_private_conditions = " || ".join(
            f"(ipv6FirstHextetValue >= 0x{first:04x} && "
            f"ipv6FirstHextetValue <= 0x{last:04x})"
            for _cidr, first, last in PAC_PRIVATE_LOCAL_IPV6_HEXTET_RANGES
        )
        lines.extend(
            (
                "  if (isIpv6Literal && /^[0-9a-f]{1,4}$/.test(ipv6FirstHextet)) {",
                "    var ipv6FirstHextetValue = parseInt(ipv6FirstHextet, 16);",
                f"    if ({ipv6_private_conditions}) return 'DIRECT';",
                "  }",
            ),
        )
        for cidr in PAC_PRIVATE_LOCAL_IPV4_NETS:
            net = ipaddress.ip_network(cidr, strict=False)
            lines.append(
                f"  if (hasIpv4 && isInNet(ip, '{net.network_address}', '{_cidr_to_mask(cidr)}')) return 'DIRECT';",
            )

    lines.extend((f"  return {json.dumps(str(proxy_chain or ''))};", "}"))
    return "\n".join(lines) + "\n"


def _pac_include_private_nets(*, sslfilter_store: object | None = None) -> bool:
    store = sslfilter_store or get_sslfilter_store()
    return bool(
        getattr(store.list_all(), "exclude_private_nets", False),
    )


def _render_profile_pac(
    profile: PacProfile,
    target: ProxyPacTarget | None = None,
    *,
    include_private: bool | None = None,
) -> str:
    resolved_target = target or resolve_proxy_pac_target()
    return _render_pac(
        resolved_target.proxy_chain,
        proxy_host=resolved_target.proxy_host_token,
        direct_domains=list(getattr(profile, "direct_domains", []) or []),
        direct_dst_nets=list(getattr(profile, "direct_dst_nets", []) or []),
        include_private=_pac_include_private_nets()
        if include_private is None
        else bool(include_private),
    )


def _render_fallback_pac(
    target: ProxyPacTarget | None = None,
    *,
    include_private: bool | None = None,
) -> str:
    resolved_target = target or resolve_proxy_pac_target()
    return _render_pac(
        resolved_target.proxy_chain,
        proxy_host=resolved_target.proxy_host_token,
        # Squid SSL-filter/no-cache destination policy still goes through the proxy;
        # it is not a client-side DIRECT rule. Only explicit PAC profiles and the
        # private/local destination option should generate DIRECT routing.
        direct_domains=[],
        direct_dst_nets=[],
        include_private=_pac_include_private_nets()
        if include_private is None
        else bool(include_private),
    )


def build_emergency_pac(target: ProxyPacTarget | None = None) -> str:
    resolved_target = target or resolve_proxy_pac_target()
    return _render_pac(
        resolved_target.proxy_chain,
        proxy_host=resolved_target.proxy_host_token,
        direct_domains=[],
        direct_dst_nets=[],
        include_private=False,
    )


def _profile_sort_key(profile: PacProfile) -> tuple[int, int]:
    return (1 if not profile.client_cidr else 0, int(profile.id))


def _manifest_profiles(profiles: Iterable[PacProfile]) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = [
        {
            "profile_id": int(profile.id),
            "name": str(profile.name or ""),
            "client_cidr": str(profile.client_cidr or ""),
            "file": f"profile-{int(profile.id)}.pac",
        }
        for profile in sorted(profiles, key=_profile_sort_key)
    ]
    return entries


def calculate_pac_state_sha(
    files: Sequence[RenderedPacFile] | Iterable[RenderedPacFile],
) -> str:
    digest = hashlib.sha256()
    for item in sorted(files, key=lambda current: current.relative_path):
        digest.update(str(item.relative_path).encode("utf-8", errors="replace"))
        digest.update(b"\0")
        digest.update(str(item.content or "").encode("utf-8", errors="replace"))
        digest.update(b"\0")
    return digest.hexdigest()


def _resolve_proxy_pac_target_for_state(
    proxy_id: str,
    *,
    pac_profiles_store: object,
    proxy_registry: object | None,
) -> ProxyPacTarget:
    try:
        signature = inspect.signature(resolve_proxy_pac_target)
    except (TypeError, ValueError):
        signature = None
    parameters = signature.parameters if signature is not None else {}
    accepts_runtime_stores = any(
        param.kind is inspect.Parameter.VAR_KEYWORD for param in parameters.values()
    ) or {"pac_profiles_store", "proxy_registry"}.issubset(parameters)
    if accepts_runtime_stores:
        return resolve_proxy_pac_target(
            proxy_id,
            pac_profiles_store=pac_profiles_store,
            proxy_registry=proxy_registry,
        )
    return resolve_proxy_pac_target(proxy_id)


def build_proxy_pac_state(
    proxy_id: object | None = None,
    *,
    pac_profiles_store: object | None = None,
    sslfilter_store: object | None = None,
    proxy_registry: object | None = None,
) -> ProxyPacState:
    normalized_proxy_id = (
        get_proxy_id() if proxy_id is None else normalize_proxy_id(proxy_id)
    )
    token = set_proxy_id(normalized_proxy_id)
    try:
        store = pac_profiles_store or get_pac_profiles_store()
        target = _resolve_proxy_pac_target_for_state(
            normalized_proxy_id,
            pac_profiles_store=store,
            proxy_registry=proxy_registry,
        )
        sorted_profiles = sorted(
            store.list_profiles(),
            key=_profile_sort_key,
        )
        include_private = _pac_include_private_nets(sslfilter_store=sslfilter_store)
        pac_files = {
            f"profile-{int(profile.id)}.pac": _render_profile_pac(
                profile,
                target,
                include_private=include_private,
            )
            for profile in sorted_profiles
        }
        fallback_file = "fallback.pac"
        pac_files[fallback_file] = _render_fallback_pac(
            target,
            include_private=include_private,
        )

        manifest = {
            "proxy_id": normalized_proxy_id,
            "host_placeholder": PAC_HOST_PLACEHOLDER,
            "public_host": target.public_host,
            "public_pac_url": target.pac_url,
            "public_pac_scheme": target.pac_scheme,
            "public_pac_port": target.pac_port,
            "public_pac_path": target.pac_path,
            "public_http_proxy_port": target.http_proxy_port,
            "uses_request_host_fallback": target.uses_request_host_fallback,
            "proxy_chain": target.proxy_chain_display,
            "backup_proxies": [
                {"proxy_host": host, "proxy_port": port}
                for host, port in target.normalized_backup_proxies
            ],
            "direct_enabled": target.direct_enabled,
            "profiles": _manifest_profiles(sorted_profiles),
            "fallback_file": fallback_file,
            "state_sha256": "",
        }
        manifest_text_for_hash = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        files_for_hash = [
            RenderedPacFile(relative_path=path, content=content)
            for path, content in sorted(pac_files.items())
        ]
        files_for_hash.append(
            RenderedPacFile(
                relative_path=PAC_MANIFEST_FILENAME,
                content=manifest_text_for_hash,
            ),
        )
        state_sha256 = calculate_pac_state_sha(files_for_hash)

        manifest["state_sha256"] = state_sha256
        manifest_text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"

        files = [
            RenderedPacFile(relative_path=path, content=content)
            for path, content in sorted(pac_files.items())
        ]
        files.extend(
            (
                RenderedPacFile(
                    relative_path=PAC_MANIFEST_FILENAME,
                    content=manifest_text,
                ),
                RenderedPacFile(
                    relative_path=PAC_STATE_SHA_FILENAME,
                    content=state_sha256 + "\n",
                ),
            ),
        )
        return ProxyPacState(
            proxy_id=normalized_proxy_id,
            state_sha256=state_sha256,
            files=tuple(files),
        )
    finally:
        reset_proxy_id(token)


def _safe_pac_state_relative_path(value: object) -> str:
    candidate = str(value or "").strip().replace("\\", "/")
    if not candidate or candidate.startswith("/"):
        return ""
    parts = candidate.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return ""
    if ":" in parts[0]:
        return ""
    rel_path = os.path.normpath(candidate).replace("\\", "/")
    if not rel_path or rel_path in {".", ".."} or rel_path.startswith("../"):
        return ""
    return rel_path


def materialize_proxy_pac_state(
    target_dir: str | os.PathLike[str],
    *,
    state: ProxyPacState,
) -> None:
    target = Path(target_dir)
    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True)

    stage_root = Path(tempfile.mkdtemp(prefix=".pac-stage-", dir=str(parent)))
    try:
        _materialize_proxy_pac_state_from_stage(target, stage_root, state=state)
    finally:
        shutil.rmtree(stage_root, ignore_errors=True)
        _fsync_parent_dir(stage_root)


def _materialize_proxy_pac_state_from_stage(
    target: Path,
    stage_root: Path,
    *,
    state: ProxyPacState,
) -> None:
    payload_dir = stage_root / "payload"
    payload_dir.mkdir(parents=True, exist_ok=True)
    backup_dir: Path | None = None

    for item in state.files:
        rel = _safe_pac_state_relative_path(item.relative_path)
        if not rel:
            msg = f"Unsafe PAC materialization path: {item.relative_path}"
            raise ValueError(msg)
        dest = payload_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        _write_pac_text_file(dest, str(item.content or ""))
    _fsync_dir(payload_dir)

    parent = target.parent
    with _locked_pac_materialization_target(target):
        try:
            if target.exists():
                backup_dir = parent / (
                    f".pac-backup-{os.getpid()}-{int(time.time() * 1000)}"
                )
                if backup_dir.exists():
                    shutil.rmtree(backup_dir, ignore_errors=True)
                    _fsync_parent_dir(backup_dir)
                Path(str(target)).replace(str(backup_dir))
                _fsync_parent_dir(target)

            Path(str(payload_dir)).replace(str(target))
            _fsync_parent_dir(target)
            if backup_dir is not None:
                shutil.rmtree(backup_dir, ignore_errors=True)
                _fsync_parent_dir(backup_dir)
        except Exception:
            if backup_dir is not None and backup_dir.exists() and not target.exists():
                with contextlib.suppress(Exception):
                    Path(str(backup_dir)).replace(str(target))
                    _fsync_parent_dir(target)
            raise


def read_materialized_pac_state_sha(
    target_dir: str | os.PathLike[str] | None = None,
) -> str:
    root = Path(target_dir or os.environ.get("PAC_RENDER_DIR") or PAC_RENDER_DIR)
    marker = root / PAC_STATE_SHA_FILENAME
    try:
        return marker.read_text(encoding="utf-8", errors="replace").strip()
    except Exception:
        return ""


def _safe_manifest_relative_path(value: object) -> str:
    return _safe_pac_state_relative_path(value)


def _manifest_fallback_file(manifest: dict[str, object]) -> str:
    return _safe_manifest_relative_path(manifest.get("fallback_file")) or "fallback.pac"


def _manifest_profile_id(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        candidate = value.strip()
        if candidate.isdecimal():
            return int(candidate)
    return None


def _manifest_profile_order_key(profile_id: int | None, order: int) -> tuple[int, int, int]:
    if profile_id is not None:
        return (0, profile_id, order)
    return (1, order, order)


def select_manifest_file(manifest: dict[str, object], client_ip: str) -> str:
    fallback_file = _manifest_fallback_file(manifest)
    profiles = manifest.get("profiles")
    if not isinstance(profiles, list):
        return fallback_file

    try:
        parsed_ip = ipaddress.ip_address((client_ip or "").strip())
    except Exception:
        parsed_ip = None
    if parsed_ip is not None and getattr(parsed_ip, "ipv4_mapped", None) is not None:
        # Some WSGI/proxy stacks report IPv4 clients as IPv4-mapped IPv6
        # addresses (for example ::ffff:10.2.3.4).  PAC client profiles are
        # operator-facing source networks, so mapped IPv4 clients should select
        # the same IPv4 CIDR profiles as their canonical dotted-quad form.
        parsed_ip = parsed_ip.ipv4_mapped

    catch_all = ""
    catch_all_key: tuple[int, int, int] | None = None
    best_match = ""
    best_match_key: tuple[int, int, int, int] | None = None
    for order, entry in enumerate(profiles):
        if not isinstance(entry, dict):
            continue
        client_cidr = str(entry.get("client_cidr") or "").strip()
        file_name = _safe_manifest_relative_path(entry.get("file"))
        if not file_name:
            continue
        profile_id = _manifest_profile_id(entry.get("profile_id"))
        profile_order_key = _manifest_profile_order_key(profile_id, order)
        if not client_cidr:
            if catch_all_key is None or profile_order_key < catch_all_key:
                catch_all = file_name
                catch_all_key = profile_order_key
            continue
        if parsed_ip is None:
            continue
        try:
            network = ipaddress.ip_network(client_cidr, strict=False)
        except Exception:
            continue
        if parsed_ip.version != network.version:
            continue
        if parsed_ip in network:
            match_key = (-int(network.prefixlen), *profile_order_key)
            if best_match_key is None or match_key < best_match_key:
                best_match = file_name
                best_match_key = match_key

    if best_match:
        return best_match
    if catch_all:
        return catch_all
    return fallback_file


def _pac_string_literal_fragment(value: str) -> str:
    # PAC artifacts place the placeholder inside JavaScript string literals.
    # Replace it with the JSON/JavaScript-escaped payload without adding a
    # second pair of quotes, so malformed Host headers cannot break PAC syntax.
    return json.dumps(str(value or ""))[1:-1]


def substitute_request_host(content: str, request_host: str) -> str:
    return str(content or "").replace(
        PAC_HOST_PLACEHOLDER,
        _pac_string_literal_fragment(_format_request_proxy_host(request_host)),
    )


def render_proxy_pac_for_request(
    *,
    proxy_id: object | None = None,
    requester_ip: str = "",
    request_host: str = "",
) -> str:
    state = build_proxy_pac_state(proxy_id)
    file_map = {item.relative_path: item.content for item in state.files}
    try:
        manifest = json.loads(file_map.get(PAC_MANIFEST_FILENAME, "{}") or "{}")
    except Exception:
        manifest = {}
    selected = select_manifest_file(
        manifest if isinstance(manifest, dict) else {},
        requester_ip,
    )
    pac = file_map.get(selected) or file_map.get(
        str(manifest.get("fallback_file") or "fallback.pac"),
        "",
    )
    if not pac:
        pac = build_emergency_pac(resolve_proxy_pac_target(proxy_id))
    return substitute_request_host(pac, request_host)
