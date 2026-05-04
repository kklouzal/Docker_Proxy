from __future__ import annotations

import sys
from pathlib import Path


def _add_web_to_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


def test_normalize_proxy_id_sanitizes_defaults_and_truncates() -> None:
    _add_web_to_path()
    import services.proxy_context as proxy_context  # type: ignore

    assert proxy_context.normalize_proxy_id(None) == "default"
    assert proxy_context.normalize_proxy_id("  edge-2  ") == "edge-2"
    assert proxy_context.normalize_proxy_id(" bad value!* ") == "bad-value"
    assert proxy_context.normalize_proxy_id("***") == "default"
    assert len(proxy_context.normalize_proxy_id("a" * 100)) == 63


def test_get_default_proxy_id_env_precedence_and_context_reset(monkeypatch) -> None:
    _add_web_to_path()
    import services.proxy_context as proxy_context  # type: ignore

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
