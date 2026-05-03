from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import shutil
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence
from urllib.parse import urlsplit

from services.exclusions_store import get_exclusions_store
from services.pac_profiles_store import PacProfile, get_pac_profiles_store
from services.proxy_context import normalize_proxy_id, reset_proxy_id, set_proxy_id
from services.proxy_registry import get_proxy_registry


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


def _build_pac_url(*, scheme: str, host: str, port: int) -> str:
    clean_host = format_proxy_host(host)
    if not clean_host:
        return ""
    normalized_scheme = _normalize_pac_scheme(scheme)
    default_port = 443 if normalized_scheme == "https" else 80
    port_part = "" if int(port) == default_port else f":{int(port)}"
    return f"{normalized_scheme}://{clean_host}{port_part}/proxy.pac"


def _normalize_domain_rule(domain: str) -> str:
    return (domain or "").strip().lower()


def _domain_match_expression(domain: str) -> str:
    normalized = _normalize_domain_rule(domain)
    if normalized.startswith("*."):
        normalized = normalized[2:]
    normalized = normalized.lstrip(".")
    if not normalized:
        return ""
    suffix = f".{normalized}"
    return f"(host === {json.dumps(normalized)} || dnsDomainIs(host, {json.dumps(suffix)}))"


@dataclass(frozen=True)
class ProxyPacTarget:
    proxy_id: str
    public_host: str
    pac_scheme: str
    pac_port: int
    http_proxy_port: int

    @property
    def uses_request_host_fallback(self) -> bool:
        return not bool(self.public_host)

    @property
    def proxy_host_token(self) -> str:
        return format_proxy_host(self.public_host) if self.public_host else PAC_HOST_PLACEHOLDER

    @property
    def pac_url(self) -> str:
        if not self.public_host:
            return ""
        return _build_pac_url(scheme=self.pac_scheme, host=self.public_host, port=self.pac_port)

    @property
    def proxy_chain(self) -> str:
        return f"PROXY {self.proxy_host_token}:{self.http_proxy_port}; DIRECT"

    @property
    def proxy_chain_display(self) -> str:
        host = self.public_host or "<request-host>"
        return f"PROXY {host}:{self.http_proxy_port}; DIRECT"


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
    normalized_proxy_id = normalize_proxy_id(proxy_id)
    try:
        proxy = get_proxy_registry().get_proxy(normalized_proxy_id)
    except Exception:
        proxy = None

    env_public_host = (os.environ.get("PROXY_PUBLIC_HOST") or "").strip()
    public_host = str(getattr(proxy, "public_host", "") or "").strip() or env_public_host
    pac_scheme = _normalize_pac_scheme(
        getattr(proxy, "public_pac_scheme", None) if proxy is not None else os.environ.get("PROXY_PUBLIC_PAC_SCHEME")
    )
    default_pac_port = 443 if pac_scheme == "https" else 80
    pac_port = _coerce_port(
        getattr(proxy, "public_pac_port", None) if proxy is not None else os.environ.get("PROXY_PUBLIC_PAC_PORT"),
        _coerce_port(os.environ.get("PROXY_PUBLIC_PAC_PORT"), default_pac_port),
    )
    http_proxy_port = _coerce_port(
        getattr(proxy, "public_http_proxy_port", None)
        if proxy is not None
        else os.environ.get("PROXY_PUBLIC_HTTP_PROXY_PORT"),
        _coerce_port(os.environ.get("PROXY_PUBLIC_HTTP_PROXY_PORT"), 3128),
    )
    return ProxyPacTarget(
        proxy_id=normalized_proxy_id,
        public_host=public_host,
        pac_scheme=pac_scheme,
        pac_port=pac_port,
        http_proxy_port=http_proxy_port,
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
    lines.append("function FindProxyForURL(url, host) {")
    lines.append("  host = host.toLowerCase();")
    lines.append(f"  var proxyHost = {json.dumps(str(proxy_host or PAC_HOST_PLACEHOLDER))};")
    lines.append("  var normalizedProxyHost = proxyHost.replace(/^\\[/, '').replace(/\\]$/, '').toLowerCase();")
    lines.append("  if (host === 'localhost' || host === '127.0.0.1' || host === '::1') return 'DIRECT';")
    lines.append("  if (isPlainHostName(host)) return 'DIRECT';")
    lines.append("  if (host === normalizedProxyHost) return 'DIRECT';")
    for suffix in LOCAL_DOMAIN_SUFFIXES:
        lines.append(f"  if (dnsDomainIs(host, {json.dumps(suffix)})) return 'DIRECT';")
    lines.append("")
    lines.append("  var cachedIp = '';")
    lines.append("  function hostIp() {")
    lines.append("    if (cachedIp) return cachedIp;")
    lines.append("    if (/^(?:\\d{1,3}\\.){3}\\d{1,3}$/.test(host)) {")
    lines.append("      cachedIp = host;")
    lines.append("      return cachedIp;")
    lines.append("    }")
    lines.append("    cachedIp = dnsResolve(host) || '';")
    lines.append("    return cachedIp;")
    lines.append("  }")

    seen_domains: set[str] = set()
    for domain in direct_domains:
        d = _normalize_domain_rule(domain)
        if not d or d in seen_domains:
            continue
        seen_domains.add(d)
        match_expression = _domain_match_expression(d)
        if match_expression:
            lines.append(f"  if {match_expression} return 'DIRECT';")

    needs_ip_lookup = bool(direct_dst_nets or include_private)
    if needs_ip_lookup:
        lines.append("")
        lines.append("  var ip = hostIp();")
        lines.append("  if (ip && isInNet(ip, '127.0.0.0', '255.0.0.0')) return 'DIRECT';")

    for cidr in direct_dst_nets:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except Exception:
            continue
        if net.version != 4:
            continue
        lines.append(
            f"  if (ip && isInNet(ip, '{net.network_address}', '{_cidr_to_mask(str(net))}')) return 'DIRECT';"
        )

    if include_private:
        lines.append("  if (ip && isInNet(ip, '10.0.0.0', '255.0.0.0')) return 'DIRECT';")
        lines.append("  if (ip && isInNet(ip, '172.16.0.0', '255.240.0.0')) return 'DIRECT';")
        lines.append("  if (ip && isInNet(ip, '192.168.0.0', '255.255.0.0')) return 'DIRECT';")
        lines.append("  if (ip && isInNet(ip, '169.254.0.0', '255.255.0.0')) return 'DIRECT';")

    lines.append(f"  return '{proxy_chain}';")
    lines.append("}")
    return "\n".join(lines) + "\n"


def _render_profile_pac(profile: PacProfile, target: ProxyPacTarget | None = None) -> str:
    resolved_target = target or resolve_proxy_pac_target()
    return _render_pac(
        resolved_target.proxy_chain,
        proxy_host=resolved_target.proxy_host_token,
        direct_domains=list(getattr(profile, "direct_domains", []) or []),
        direct_dst_nets=list(getattr(profile, "direct_dst_nets", []) or []),
        include_private=False,
    )


def _render_fallback_pac(target: ProxyPacTarget | None = None) -> str:
    exclusions = get_exclusions_store().list_all()
    resolved_target = target or resolve_proxy_pac_target()
    return _render_pac(
        resolved_target.proxy_chain,
        proxy_host=resolved_target.proxy_host_token,
        direct_domains=[str(item) for item in (getattr(exclusions, "domains", []) or [])],
        direct_dst_nets=[],
        include_private=bool(getattr(exclusions, "exclude_private_nets", False)),
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
    entries: list[dict[str, object]] = []
    for profile in sorted(list(profiles), key=_profile_sort_key):
        entries.append(
            {
                "profile_id": int(profile.id),
                "name": str(profile.name or ""),
                "client_cidr": str(profile.client_cidr or ""),
                "file": f"profile-{int(profile.id)}.pac",
            }
        )
    return entries


def calculate_pac_state_sha(files: Sequence[RenderedPacFile] | Iterable[RenderedPacFile]) -> str:
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
        profiles = get_pac_profiles_store().list_profiles()
        pac_files = {
            f"profile-{int(profile.id)}.pac": _render_profile_pac(profile, target)
            for profile in sorted(list(profiles), key=_profile_sort_key)
        }
        fallback_file = "fallback.pac"
        pac_files[fallback_file] = _render_fallback_pac(target)

        manifest = {
            "proxy_id": normalized_proxy_id,
            "host_placeholder": PAC_HOST_PLACEHOLDER,
            "public_host": target.public_host,
            "public_pac_url": target.pac_url,
            "public_pac_scheme": target.pac_scheme,
            "public_pac_port": target.pac_port,
            "public_http_proxy_port": target.http_proxy_port,
            "uses_request_host_fallback": target.uses_request_host_fallback,
            "proxy_chain": target.proxy_chain_display,
            "profiles": _manifest_profiles(profiles),
            "fallback_file": fallback_file,
            "state_sha256": "",
        }
        manifest_text_for_hash = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        files_for_hash = [RenderedPacFile(relative_path=path, content=content) for path, content in sorted(pac_files.items())]
        files_for_hash.append(RenderedPacFile(relative_path=PAC_MANIFEST_FILENAME, content=manifest_text_for_hash))
        state_sha256 = calculate_pac_state_sha(files_for_hash)

        manifest["state_sha256"] = state_sha256
        manifest_text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"

        files = [RenderedPacFile(relative_path=path, content=content) for path, content in sorted(pac_files.items())]
        files.append(RenderedPacFile(relative_path=PAC_MANIFEST_FILENAME, content=manifest_text))
        files.append(RenderedPacFile(relative_path=PAC_STATE_SHA_FILENAME, content=state_sha256 + "\n"))
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
            rel = os.path.normpath(str(item.relative_path or "")).replace("\\", "/")
            if not rel or rel.startswith("../") or rel.startswith("/") or rel == "..":
                raise ValueError(f"Unsafe PAC materialization path: {item.relative_path}")
            dest = payload_dir / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(str(item.content or ""), encoding="utf-8")

        if target.exists():
            backup_dir = parent / f".pac-backup-{os.getpid()}-{int(time.time() * 1000)}"
            if backup_dir.exists():
                shutil.rmtree(backup_dir, ignore_errors=True)
            os.replace(str(target), str(backup_dir))

        os.replace(str(payload_dir), str(target))
        if backup_dir is not None:
            shutil.rmtree(backup_dir, ignore_errors=True)
    except Exception:
        if backup_dir is not None and backup_dir.exists() and not target.exists():
            try:
                os.replace(str(backup_dir), str(target))
            except Exception:
                pass
        raise
    finally:
        shutil.rmtree(stage_root, ignore_errors=True)


def read_materialized_pac_state_sha(target_dir: str | os.PathLike[str] | None = None) -> str:
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
        if parsed_ip in network:
            return file_name

    if catch_all:
        return catch_all
    return str(manifest.get("fallback_file") or "fallback.pac")


def substitute_request_host(content: str, request_host: str) -> str:
    return str(content or "").replace(PAC_HOST_PLACEHOLDER, format_proxy_host(request_host))


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
    selected = select_manifest_file(manifest if isinstance(manifest, dict) else {}, requester_ip)
    pac = file_map.get(selected) or file_map.get(str(manifest.get("fallback_file") or "fallback.pac"), "")
    if not pac:
        pac = build_emergency_pac(resolve_proxy_pac_target(proxy_id))
    return substitute_request_host(pac, request_host)
