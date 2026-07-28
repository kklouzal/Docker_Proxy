from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
WEB_ROOT = REPO_ROOT / "web"


def _ensure_web_import_path() -> None:
    web_root = str(WEB_ROOT)
    if web_root not in sys.path:
        sys.path.insert(0, web_root)


def test_policy_materializer_rejects_conflicting_same_target_files(tmp_path) -> None:
    _ensure_web_import_path()

    from services.policy_materializer import (
        build_proxy_policy_state_from_stores,  # type: ignore
    )

    shared_path = tmp_path / "policy.conf"
    sslfilter_store = SimpleNamespace(
        squid_include_path=str(shared_path),
        nobump_list_path=str(shared_path),
        nocache_src_list_path=str(tmp_path / "nocache-src.txt"),
        render_materialized_state=lambda: SimpleNamespace(
            include_text="# ssl include\n",
            nobump_src_list_text="10.0.0.0/8\n",
            nocache_src_list_text="",
        ),
    )
    webfilter_store = SimpleNamespace(
        squid_include_path=str(tmp_path / "webfilter.conf"),
        whitelist_path=str(tmp_path / "whitelist.txt"),
        render_materialized_state=lambda: SimpleNamespace(
            include_text="# web include\n",
            whitelist_text="",
        ),
    )

    with pytest.raises(ValueError, match="conflicting content"):
        build_proxy_policy_state_from_stores(
            "proxy-a",
            sslfilter_store=sslfilter_store,
            webfilter_store=webfilter_store,
        )
