from __future__ import annotations

import hashlib
import os
import pathlib
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from services.materialized_files import write_managed_text_files
from services.proxy_context import normalize_proxy_id, reset_proxy_id, set_proxy_id
from services.sslfilter_store import get_sslfilter_store
from services.webfilter_core import get_proxy_webfilter_store

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence


@dataclass(frozen=True)
class MaterializedPolicyFile:
    path: str
    content: str


@dataclass(frozen=True)
class ProxyPolicyState:
    proxy_id: str
    policy_sha256: str
    files: tuple[MaterializedPolicyFile, ...]


def _materialized_policy_path_key(path: str) -> str:
    return str(pathlib.Path(path).resolve(strict=False))


def _validated_materialized_policy_files(
    files: Sequence[MaterializedPolicyFile] | Iterable[MaterializedPolicyFile],
) -> tuple[MaterializedPolicyFile, ...]:
    validated: list[MaterializedPolicyFile] = []
    by_target: dict[str, MaterializedPolicyFile] = {}
    for raw_file in files:
        item = MaterializedPolicyFile(
            path=str(raw_file.path),
            content=str(raw_file.content or ""),
        )
        if not item.path.strip():
            msg = "Materialized policy file target path is empty"
            raise ValueError(msg)
        target_key = _materialized_policy_path_key(item.path)
        existing = by_target.get(target_key)
        if existing is None:
            by_target[target_key] = item
            validated.append(item)
            continue
        conflict = (
            "conflicting content"
            if existing.content != item.content
            else "duplicate target"
        )
        msg = (
            f"Materialized policy file target has {conflict}: "
            f"{existing.path!r} and {item.path!r}"
        )
        raise ValueError(msg)
    return tuple(validated)


def calculate_policy_sha(
    files: Sequence[MaterializedPolicyFile] | Iterable[MaterializedPolicyFile],
) -> str:
    items = sorted(
        _validated_materialized_policy_files(files),
        key=lambda item: _materialized_policy_path_key(item.path),
    )
    digest = hashlib.sha256()
    for item in items:
        target_key = _materialized_policy_path_key(item.path)
        digest.update(target_key.encode("utf-8", errors="replace"))
        digest.update(b"\0")
        digest.update(item.content.encode("utf-8", errors="replace"))
        digest.update(b"\0")
    return digest.hexdigest()


def build_proxy_policy_state_from_stores(
    proxy_id: object | None = None,
    *,
    sslfilter_store: object,
    webfilter_store: object,
) -> ProxyPolicyState:
    normalized_proxy_id = normalize_proxy_id(proxy_id)
    token = set_proxy_id(normalized_proxy_id)
    try:
        webfilter_state = webfilter_store.render_materialized_state()
        sslfilter_state = sslfilter_store.render_materialized_state()
        files = _validated_materialized_policy_files(
            (
                MaterializedPolicyFile(
                    path=str(sslfilter_store.squid_include_path),
                    content=str(sslfilter_state.include_text or ""),
                ),
                MaterializedPolicyFile(
                    path=str(sslfilter_store.nobump_list_path),
                    content=str(sslfilter_state.nobump_src_list_text or ""),
                ),
                MaterializedPolicyFile(
                    path=str(sslfilter_store.nocache_src_list_path),
                    content=str(sslfilter_state.nocache_src_list_text or ""),
                ),
                MaterializedPolicyFile(
                    path=str(webfilter_store.squid_include_path),
                    content=str(webfilter_state.include_text or ""),
                ),
                MaterializedPolicyFile(
                    path=str(webfilter_store.whitelist_path),
                    content=str(webfilter_state.whitelist_text or ""),
                ),
            ),
        )
        return ProxyPolicyState(
            proxy_id=normalized_proxy_id,
            policy_sha256=calculate_policy_sha(files),
            files=files,
        )
    finally:
        reset_proxy_id(token)


def build_proxy_policy_state(proxy_id: object | None = None) -> ProxyPolicyState:
    return build_proxy_policy_state_from_stores(
        proxy_id,
        sslfilter_store=get_sslfilter_store(),
        webfilter_store=get_proxy_webfilter_store(),
    )


_POLICY_LKG_DIR_DEFAULT = "/var/lib/squid-flask-proxy/policy-last-known-good"


def _policy_lkg_dir() -> pathlib.Path:
    return pathlib.Path(
        (os.environ.get("PROXY_POLICY_LKG_DIR") or _POLICY_LKG_DIR_DEFAULT).strip()
        or _POLICY_LKG_DIR_DEFAULT,
    )


def _policy_lkg_path(path: str) -> pathlib.Path:
    key = _materialized_policy_path_key(path)
    digest = hashlib.sha256(key.encode("utf-8", errors="replace")).hexdigest()[:16]
    return _policy_lkg_dir() / f"{digest}-{pathlib.Path(key).name}"


def _read_text_or_none(path: pathlib.Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None


def remember_last_known_good_policy_files(files: Iterable[tuple[str, str]]) -> None:
    """Mirror materialized policy files onto the proxy's durable volume.

    The Squid policy includes live in the container's ephemeral /etc/squid; the
    mirror lets a restart without control-plane access serve the last policy
    this proxy applied instead of an empty (filtering-disabled) include.
    """
    changed = [
        (str(lkg_path), content)
        for path, content in files
        if _read_text_or_none(lkg_path := _policy_lkg_path(path)) != content
    ]
    if changed:
        _policy_lkg_dir().mkdir(parents=True, exist_ok=True)
        write_managed_text_files(*changed)


def restore_last_known_good_policy_file(path: str) -> bool:
    """Restore path from the durable mirror; return False when none exists."""
    content = _read_text_or_none(_policy_lkg_path(path))
    if content is None:
        return False
    write_managed_text_files((path, content))
    return True


_ICAP_SERVICE_URI_RE = re.compile(r"^\s*icap_service\s+\S+\s+\S+\s+(\S+)", re.MULTILINE)


def _icap_service_uris(text: str) -> list[str]:
    return sorted(_ICAP_SERVICE_URI_RE.findall(text))


def restore_last_known_good_icap_runtime(
    icap_include_path: str,
    virus_scan_config_path: str,
) -> bool:
    """Replace the boot-time ICAP startup fallback with the last applied policy.

    The entrypoint can only write a conservative ICAP include (adblock routing
    off, download-only AV) because the persisted UI policy lives in MySQL. When
    this proxy previously applied the policy for the same ICAP services
    (worker count and ports unchanged), restore that include and the matching
    c-icap virus_scan config so adblock and file-security policy keep working
    without the control plane, and a reachable control plane finds nothing to
    reconfigure. Returns False when there is no compatible mirror.
    """
    mirrored_include = _read_text_or_none(_policy_lkg_path(icap_include_path))
    startup_include = _read_text_or_none(pathlib.Path(icap_include_path))
    if mirrored_include is None or startup_include is None:
        return False
    if _icap_service_uris(mirrored_include) != _icap_service_uris(startup_include):
        return False
    files = [(icap_include_path, mirrored_include)]
    mirrored_virus_scan = _read_text_or_none(_policy_lkg_path(virus_scan_config_path))
    if mirrored_virus_scan is not None:
        files.append((virus_scan_config_path, mirrored_virus_scan))
    write_managed_text_files(*files)
    return True
