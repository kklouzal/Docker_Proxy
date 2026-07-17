from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

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


def calculate_policy_sha(
    files: Sequence[MaterializedPolicyFile] | Iterable[MaterializedPolicyFile],
) -> str:
    items = sorted(
        [
            MaterializedPolicyFile(path=str(f.path), content=str(f.content or ""))
            for f in files
        ],
        key=lambda item: item.path,
    )
    digest = hashlib.sha256()
    for item in items:
        digest.update(item.path.encode("utf-8", errors="replace"))
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
        files = (
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
