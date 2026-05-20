from __future__ import annotations

import sys
from pathlib import Path

import pytest


def _add_repo_paths() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    web_root = repo_root / "web"
    for path in (repo_root, web_root):
        path_str = str(path)
        if path_str not in sys.path:
            sys.path.insert(0, path_str)


class StopLoop(BaseException):
    pass


def _stop_sleep(_seconds: float) -> None:
    raise StopLoop


def test_live_stats_tailer_does_not_open_db_connection_while_idle(
    monkeypatch, tmp_path
) -> None:
    _add_repo_paths()
    from services import live_stats  # type: ignore

    log_path = tmp_path / "access.log"
    log_path.write_text("", encoding="utf-8")
    store = live_stats.LiveStatsStore(access_log_path=str(log_path))
    monkeypatch.setattr(store, "seed_from_recent_log", lambda: None)
    monkeypatch.setattr(
        store,
        "_connect",
        lambda: (_ for _ in ()).throw(
            AssertionError("idle tailer opened a DB connection")
        ),
    )
    monkeypatch.setattr(live_stats.time, "sleep", _stop_sleep)

    with pytest.raises(StopLoop):
        store._tail_loop()


def test_diagnostic_tailer_does_not_open_db_connection_while_idle(
    monkeypatch, tmp_path
) -> None:
    _add_repo_paths()
    from services import diagnostic_store  # type: ignore

    log_path = tmp_path / "diagnostic.log"
    log_path.write_text("", encoding="utf-8")
    store = diagnostic_store.DiagnosticStore(
        access_log_path=str(log_path), icap_log_path=str(tmp_path / "icap.log")
    )
    monkeypatch.setattr(
        store,
        "_connect",
        lambda: (_ for _ in ()).throw(
            AssertionError("idle tailer opened a DB connection")
        ),
    )
    monkeypatch.setattr(diagnostic_store.time, "sleep", _stop_sleep)

    with pytest.raises(StopLoop):
        store._tail_file_loop(
            str(log_path),
            lambda _line: None,
            lambda _conn, _rows: None,
            "test-diagnostic",
        )


def test_ssl_errors_tailer_does_not_open_db_connection_while_idle(
    monkeypatch, tmp_path
) -> None:
    _add_repo_paths()
    from services import ssl_errors_store  # type: ignore

    log_path = tmp_path / "cache.log"
    log_path.write_text("", encoding="utf-8")
    store = ssl_errors_store.SslErrorsStore(cache_log_path=str(log_path))
    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "seed_from_recent_log", lambda: None)
    monkeypatch.setattr(
        store,
        "_connect",
        lambda: (_ for _ in ()).throw(
            AssertionError("idle tailer opened a DB connection")
        ),
    )
    monkeypatch.setattr(ssl_errors_store.time, "sleep", _stop_sleep)

    with pytest.raises(StopLoop):
        store._tail_loop()


def test_adblock_blocklog_tailer_does_not_open_db_connection_when_log_missing(
    monkeypatch, tmp_path
) -> None:
    _add_repo_paths()
    from services import adblock_store  # type: ignore

    store = adblock_store.AdblockStore(
        cicap_access_log_path=str(tmp_path / "missing-cicap.log")
    )
    monkeypatch.setattr(
        store,
        "_connect",
        lambda: (_ for _ in ()).throw(
            AssertionError("missing-log tailer opened a DB connection")
        ),
    )
    monkeypatch.setattr(adblock_store.time, "sleep", _stop_sleep)

    with pytest.raises(StopLoop):
        store._blocklog_tail_loop()


def test_adblock_checkpoint_updates_existing_meta_rows_without_upsert(monkeypatch) -> None:
    _add_repo_paths()
    from services import adblock_store  # type: ignore

    calls: list[tuple[str, tuple[object, ...]]] = []

    class Conn:
        def execute(self, sql, params=()):
            calls.append((" ".join(str(sql).split()), tuple(params or ())))

            class Result:
                rowcount = 1

            return Result()

    monkeypatch.setattr(adblock_store, "get_proxy_id", lambda: "proxy-a")
    store = adblock_store.AdblockStore()
    store._set_proxy_meta_values(
        Conn(),
        {"cicap_access_pos": "20", "cicap_access_inode": "10"},
    )

    assert calls == [
        (
            "UPDATE adblock_proxy_meta SET v=%s WHERE proxy_id=%s AND k=%s",
            ("10", "proxy-a", "cicap_access_inode"),
        ),
        (
            "UPDATE adblock_proxy_meta SET v=%s WHERE proxy_id=%s AND k=%s",
            ("20", "proxy-a", "cicap_access_pos"),
        ),
    ]
