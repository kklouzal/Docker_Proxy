from __future__ import annotations

import sys
from pathlib import Path

WEB_DIR = Path(__file__).resolve().parents[1]
if str(WEB_DIR) not in sys.path:
    sys.path.insert(0, str(WEB_DIR))

from services import proxy_context  # type: ignore  # noqa: E402


def test_normalize_proxy_id_sanitizes_defaults_and_truncates() -> None:
    assert proxy_context.normalize_proxy_id(None) == "default"
    assert proxy_context.normalize_proxy_id("  edge-2  ") == "edge-2"
    assert proxy_context.normalize_proxy_id("Proxy-PR") == "Proxy-PR"
    assert proxy_context.normalize_proxy_id("proxy.name:blue_01") == "proxy.name:blue_01"
    assert proxy_context.normalize_proxy_id(" bad value!* ") == "bad-value"
    assert proxy_context.normalize_proxy_id("bad//evil") == "bad-evil"
    assert proxy_context.normalize_proxy_id("***") == "default"
    assert len(proxy_context.normalize_proxy_id("a" * 100)) == 63


def test_normalize_proxy_id_strips_delimiters_and_rejects_traversal() -> None:
    assert proxy_context.normalize_proxy_id("bad-") == "bad"
    assert proxy_context.normalize_proxy_id("--bad::") == "bad"
    assert proxy_context.normalize_proxy_id("bad/../../evil") == "default"
    assert proxy_context.normalize_proxy_id("bad/..evil") == "default"
    assert proxy_context.normalize_proxy_id("../evil") == "default"
    assert proxy_context.normalize_proxy_id("..") == "default"
    assert proxy_context.normalize_proxy_id("a" * 62 + "-tail") == "a" * 62


def test_normalize_route_proxy_id_accepts_only_exact_safe_selectors() -> None:
    assert proxy_context.normalize_route_proxy_id("  edge-2  ") == "edge-2"
    assert (
        proxy_context.normalize_route_proxy_id("proxy.name:blue_01")
        == "proxy.name:blue_01"
    )

    lossy_selectors = (
        "edge 2",
        "edge/2",
        "--edge-2::",
        "../../edge-2",
        "a" * 63 + "-other",
    )
    for selector in lossy_selectors:
        assert proxy_context.normalize_proxy_id(selector) != selector.strip()
        assert proxy_context.normalize_route_proxy_id(selector) == "default"


def test_get_default_proxy_id_env_precedence_and_context_reset(monkeypatch) -> None:
    monkeypatch.setenv("DEFAULT_PROXY_ID", "default-env")
    monkeypatch.setenv("PROXY_INSTANCE_ID", "instance-env")
    monkeypatch.setenv("PROXY_ID", "proxy-env")
    assert proxy_context.get_default_proxy_id() == "default-env"
    assert proxy_context.get_proxy_id() == "default-env"
    assert proxy_context.get_proxy_id("preferred") == "preferred"

    token = proxy_context.set_proxy_id("active proxy")
    try:
        assert proxy_context.get_proxy_id() == "active-proxy"
        assert proxy_context.get_proxy_id("ignored") == "active-proxy"
    finally:
        proxy_context.reset_proxy_id(token)

    assert proxy_context.get_proxy_id() == "default-env"
