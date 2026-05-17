from __future__ import annotations

import sys
from pathlib import Path


def _add_repo_paths() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    web_root = repo_root / "web"
    for path in (repo_root, web_root):
        path_str = str(path)
        if path_str not in sys.path:
            sys.path.insert(0, path_str)


def test_pac_render_dir_is_cached_until_explicitly_cleared(monkeypatch) -> None:
    _add_repo_paths()
    from services import pac_http  # type: ignore

    pac_http.pac_render_dir.cache_clear()
    monkeypatch.setenv("PAC_RENDER_DIR", "/tmp/pac-one")

    first = pac_http.pac_render_dir()
    monkeypatch.setenv("PAC_RENDER_DIR", "/tmp/pac-two")
    second = pac_http.pac_render_dir()

    assert first == "/tmp/pac-one"
    assert second == "/tmp/pac-one"

    pac_http.pac_render_dir.cache_clear()
    assert pac_http.pac_render_dir() == "/tmp/pac-two"
