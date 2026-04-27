from __future__ import annotations

import importlib
import sys
from pathlib import Path


def _add_repo_paths() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    web_root = repo_root / "web"
    for path in (repo_root, web_root):
        path_str = str(path)
        if path_str not in sys.path:
            sys.path.insert(0, path_str)


def _import_sslfilter_store_module():
    _add_repo_paths()
    import services.sslfilter_store as module  # type: ignore

    importlib.reload(module)
    return module


def _import_webfilter_core_module():
    _add_repo_paths()
    import services.webfilter_core as module  # type: ignore

    importlib.reload(module)
    return module


def test_sslfilter_apply_squid_include_writes_materialized_files(tmp_path, monkeypatch):
    module = _import_sslfilter_store_module()
    store = module.SslFilterStore(
        squid_include_path=str(tmp_path / "etc" / "squid" / "conf.d" / "10-sslfilter.conf"),
        nobump_list_path=str(tmp_path / "var" / "lib" / "sslfilter_nobump.txt"),
    )
    state = module.SslFilterMaterializedState(
        include_text="# include\nssl_bump splice sslfilter_nobump\n",
        list_text="10.0.0.0/8\n",
    )
    monkeypatch.setattr(store, "render_materialized_state", lambda: state)

    store.apply_squid_include()

    assert Path(store.squid_include_path).read_text(encoding="utf-8") == state.include_text
    assert Path(store.nobump_list_path).read_text(encoding="utf-8") == state.list_text


def test_webfilter_apply_squid_include_writes_materialized_files(tmp_path, monkeypatch):
    module = _import_webfilter_core_module()
    store = module.ProxyWebFilterStore(
        squid_include_path=str(tmp_path / "etc" / "squid" / "conf.d" / "30-webfilter.conf"),
        whitelist_path=str(tmp_path / "var" / "lib" / "webfilter_whitelist.txt"),
    )
    state = module.WebFilterMaterializedState(
        include_text="# include\nhttp_access deny webfilter_block_adult\n",
        whitelist_text="example.com\n",
    )
    monkeypatch.setattr(store, "render_materialized_state", lambda: state)

    store.apply_squid_include()

    assert Path(store.squid_include_path).read_text(encoding="utf-8") == state.include_text
    assert Path(store.whitelist_path).read_text(encoding="utf-8") == state.whitelist_text