from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import json
import os
import shutil
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from services.domain_normalization import normalize_domain as _shared_normalize_domain
from services.pac_profiles_store import (
    PacProfile,
    _normalize_proxy_host_port,
    get_pac_profiles_store,
)
from services.proxy_context import (
    get_proxy_id,
    normalize_proxy_id,
    reset_proxy_id,
    set_proxy_id,
)
from services.proxy_registry import get_proxy_registry, normalize_public_pac_path
from services.sslfilter_store import get_sslfilter_store

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

PAC_HOST_PLACEHOLDER = "__PAC_PROXY_HOST__"
PAC_MANIFEST_FILENAME = "manifest.json"
PAC_STATE_SHA_FILENAME = ".state-sha256"
PAC_RENDER_DIR = "/var/lib/squid-flask-proxy/pac"
LOCAL_DOMAIN_SUFFIXES = (".local", ".localdomain", ".home.arpa", ".localhost")


def _normalize_pac_scheme(value: object | None) -> str:
    candidate = str(value or "").strip().lower()
    if candidate in {"http", "https"}:
        return candidate
    return "http"


def _parse_public_pac_url(raw_url: object | None) -> tuple[str, str, int, str]:
    candidate = str(raw_url or "").strip()
    if not candidate:
        return "", "http", 80, "/proxy.pac"
    if "://" not in candidate:
        candidate = f"http://{candidate}"
    try:
        parsed = urlsplit(candidate)
    except Exception:
        return "", "http", 80, "/proxy.pac"
    scheme = _normalize_pac_scheme(parsed.scheme)
    host = str(parsed.hostname or "").strip()
    default_port = 443 if scheme == "https" else 80
    try:
        parsed_port = parsed.port
    except ValueError:
        parsed_port = None
    path = normalize_public_pac_path(candidate)
    return host, scheme, int(parsed_port or default_port), path


def _coerce_port(value: object | None, default: int) -> int:
    try:
        parsed = int(str(value or "").strip() or str(default))
    except Exception:
        parsed = int(default)
    if parsed < 1 or parsed > 65535:
        return int(default)
    return parsed


def _coerce_bool(value: object | None, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return bool(default)
    candidate = str(value).strip().lower()
    if not candidate:
        return bool(default)
    if candidate in {"1", "true", "yes", "on"}:
        return True
    if candidate in {"0", "false", "no", "off"}:
        return False
    return bool(default)


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
    raw = (domain or "").strip()
    if not raw:
        return ""
    if any(ch.isspace() for ch in raw):
        return ""
    wildcard = raw.lower().startswith("*.") and "://" not in raw
    raw = raw[2:] if wildcard else raw.removeprefix(".")
    normalized = _shared_normalize_domain(raw)
    if not normalized or ":" in normalized:
        return ""
    labels = normalized.split(".")
    if any(
        not label
        or len(label) > 63
        or not label.isascii()
        or not label[0].isalnum()
        or not label[-1].isalnum()
        or any(not (ch.isalnum() or ch == "-") for ch in label)
        for label in labels
    ):
        return ""
    return f"*.{normalized}" if wildcard else normalized


def _domain_match_expression(domain: str) -> str:
    normalized = _normalize_domain_rule(domain)
    normalized = normalized.removeprefix("*.")
    normalized = normalized.lstrip(".")
    if not normalized:
        return ""
    suffix = f".{normalized}"
    return f"(host === {json.dumps(normalized)} || dnsDomainIs(host, {json.dumps(suffix)}))"


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
    return format_proxy_host(host), int(port)


@dataclass(frozen=True)
class ProxyPacTarget:
    proxy_id: str
    public_host: str
    pac_scheme: str
    pac_port: int
    http_proxy_port: int
    backup_proxies: tuple[tuple[str, int], ...] = ()
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
        entries = [f"PROXY {host}:{self.http_proxy_port}"]
        for rendered_host, backup_port in self.normalized_backup_proxies:
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


def format_proxy_host(raw_host: str) -> str:
    host = _request_host_only(raw_host)
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host or "127.0.0.1"


def resolve_proxy_pac_target(proxy_id: object | None = None) -> ProxyPacTarget:
    normalized_proxy_id = (
        get_proxy_id() if proxy_id is None else normalize_proxy_id(proxy_id)
    )
    try:
        proxy = get_proxy_registry().get_proxy(normalized_proxy_id)
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
        os.environ.get("PROXY_PUBLIC_HOST") or ""
    ).strip() or url_public_host
    proxy_public_host = str(getattr(proxy, "public_host", "") or "").strip()
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
    backup_proxies: tuple[tuple[str, int], ...] = ()
    direct_enabled = True
    token = set_proxy_id(normalized_proxy_id)
    try:
        chain_settings = get_pac_profiles_store().list_proxy_chain_settings()
        backup_proxies = tuple(
            (
                str(getattr(item, "proxy_host", "") or ""),
                _coerce_port(getattr(item, "proxy_port", None), 3128),
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
            "  host = host.toLowerCase();",
            f"  var proxyHost = {json.dumps(str(proxy_host or PAC_HOST_PLACEHOLDER))};",
            "  var normalizedProxyHost = proxyHost.replace(/^\\[/, '').replace(/\\]$/, '').toLowerCase();",
            "  if (host === 'localhost' || host === '127.0.0.1' || host === '::1') return 'DIRECT';",
            "  if (isPlainHostName(host)) return 'DIRECT';",
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
            "    if (/^(?:\\d{1,3}\\.){3}\\d{1,3}$/.test(host)) {",
            "      cachedIp = host;",
            "      return cachedIp;",
            "    }",
            "    cachedIp = dnsResolve(host) || '';",
            "    return cachedIp;",
            "  }",
        ),
    )

    seen_domains: set[str] = set()
    for domain in direct_domains:
        d = _normalize_domain_rule(domain)
        canonical = d.removeprefix("*.")
        canonical = canonical.lstrip(".")
        if not canonical or canonical in seen_domains:
            continue
        seen_domains.add(canonical)
        match_expression = _domain_match_expression(d)
        if match_expression:
            lines.append(f"  if {match_expression} return 'DIRECT';")

    needs_ip_lookup = bool(direct_dst_nets or include_private)
    if needs_ip_lookup:
        lines.extend(
            (
                "",
                "  var ip = hostIp();",
                "  if (ip && isInNet(ip, '127.0.0.0', '255.0.0.0')) return 'DIRECT';",
            ),
        )

    for cidr in direct_dst_nets:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except Exception:
            continue
        if net.version != 4:
            continue
        lines.append(
            f"  if (ip && isInNet(ip, '{net.network_address}', '{_cidr_to_mask(str(net))}')) return 'DIRECT';",
        )

    if include_private:
        lines.extend(
            (
                "  if (ip && isInNet(ip, '10.0.0.0', '255.0.0.0')) return 'DIRECT';",
                "  if (ip && isInNet(ip, '172.16.0.0', '255.240.0.0')) return 'DIRECT';",
                "  if (ip && isInNet(ip, '192.168.0.0', '255.255.0.0')) return 'DIRECT';",
                "  if (ip && isInNet(ip, '169.254.0.0', '255.255.0.0')) return 'DIRECT';",
            ),
        )

    lines.extend((f"  return {json.dumps(str(proxy_chain or ''))};", "}"))
    return "\n".join(lines) + "\n"


def _pac_include_private_nets() -> bool:
    return bool(
        getattr(get_sslfilter_store().list_all(), "exclude_private_nets", False),
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


def build_proxy_pac_state(proxy_id: object | None = None) -> ProxyPacState:
    normalized_proxy_id = normalize_proxy_id(proxy_id)
    token = set_proxy_id(normalized_proxy_id)
    try:
        target = resolve_proxy_pac_target(normalized_proxy_id)
        sorted_profiles = sorted(
            get_pac_profiles_store().list_profiles(),
            key=_profile_sort_key,
        )
        include_private = _pac_include_private_nets()
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


def materialize_proxy_pac_state(
    target_dir: str | os.PathLike[str],
    *,
    state: ProxyPacState,
) -> None:
    target = Path(target_dir)
    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True)

    stage_root = Path(tempfile.mkdtemp(prefix=".pac-stage-", dir=str(parent)))
    payload_dir = stage_root / "payload"
    payload_dir.mkdir(parents=True, exist_ok=True)
    backup_dir: Path | None = None

    try:
        for item in state.files:
            raw_rel = str(item.relative_path or "").replace("\\", "/")
            rel = os.path.normpath(raw_rel).replace("\\", "/")
            if not rel or rel.startswith(("../", "/")) or rel in {".", ".."}:
                msg = f"Unsafe PAC materialization path: {item.relative_path}"
                raise ValueError(msg)
            dest = payload_dir / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(str(item.content or ""), encoding="utf-8")

        if target.exists():
            backup_dir = parent / f".pac-backup-{os.getpid()}-{int(time.time() * 1000)}"
            if backup_dir.exists():
                shutil.rmtree(backup_dir, ignore_errors=True)
            Path(str(target)).replace(str(backup_dir))

        Path(str(payload_dir)).replace(str(target))
        if backup_dir is not None:
            shutil.rmtree(backup_dir, ignore_errors=True)
    except Exception:
        if backup_dir is not None and backup_dir.exists() and not target.exists():
            with contextlib.suppress(Exception):
                Path(str(backup_dir)).replace(str(target))
        raise
    finally:
        shutil.rmtree(stage_root, ignore_errors=True)


def read_materialized_pac_state_sha(
    target_dir: str | os.PathLike[str] | None = None,
) -> str:
    root = Path(target_dir or os.environ.get("PAC_RENDER_DIR") or PAC_RENDER_DIR)
    marker = root / PAC_STATE_SHA_FILENAME
    try:
        return marker.read_text(encoding="utf-8", errors="replace").strip()
    except Exception:
        return ""


def select_manifest_file(manifest: dict[str, object], client_ip: str) -> str:
    profiles = manifest.get("profiles")
    if not isinstance(profiles, list):
        fallback = manifest.get("fallback_file")
        return str(fallback or "fallback.pac")

    try:
        parsed_ip = ipaddress.ip_address((client_ip or "").strip())
    except Exception:
        parsed_ip = None

    catch_all = ""
    best_match = ""
    best_prefix_len = -1
    for entry in profiles:
        if not isinstance(entry, dict):
            continue
        client_cidr = str(entry.get("client_cidr") or "").strip()
        file_name = str(entry.get("file") or "").strip()
        if not file_name:
            continue
        if not client_cidr:
            if not catch_all:
                catch_all = file_name
            continue
        if parsed_ip is None:
            continue
        try:
            network = ipaddress.ip_network(client_cidr, strict=False)
        except Exception:
            continue
        if parsed_ip.version != network.version:
            continue
        if parsed_ip in network and network.prefixlen > best_prefix_len:
            best_match = file_name
            best_prefix_len = int(network.prefixlen)

    if best_match:
        return best_match
    if catch_all:
        return catch_all
    return str(manifest.get("fallback_file") or "fallback.pac")


def _pac_string_literal_fragment(value: str) -> str:
    # PAC artifacts place the placeholder inside JavaScript string literals.
    # Replace it with the JSON/JavaScript-escaped payload without adding a
    # second pair of quotes, so malformed Host headers cannot break PAC syntax.
    return json.dumps(str(value or ""))[1:-1]


def substitute_request_host(content: str, request_host: str) -> str:
    return str(content or "").replace(
        PAC_HOST_PLACEHOLDER,
        _pac_string_literal_fragment(format_proxy_host(request_host)),
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
