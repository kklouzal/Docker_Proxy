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


def test_write_managed_text_files_restores_previous_files_when_late_replace_fails(tmp_path, monkeypatch):
    _add_repo_paths()
    import services.materialized_files as materialized_files  # type: ignore

    first = tmp_path / "first.conf"
    second = tmp_path / "second.conf"
    first.write_text("old first\n", encoding="utf-8")
    second.write_text("old second\n", encoding="utf-8")
    real_replace = materialized_files.os.replace
    replace_calls: list[tuple[str, str]] = []

    def flaky_replace(src, dst):
        replace_calls.append((str(src), str(dst)))
        if str(dst) == str(second):
            raise OSError("disk full")
        return real_replace(src, dst)

    monkeypatch.setattr(materialized_files.os, "replace", flaky_replace)

    try:
        materialized_files.write_managed_text_files((str(first), "new first\n"), (str(second), "new second\n"))
    except OSError as exc:
        assert "disk full" in str(exc)
    else:  # pragma: no cover - defensive assertion
        raise AssertionError("expected second replace failure")

    assert replace_calls and replace_calls[-1][1] == str(second)
    assert first.read_text(encoding="utf-8") == "old first\n"
    assert second.read_text(encoding="utf-8") == "old second\n"
