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


def test_ssl_errors_tailer_does_not_initialize_db_when_log_missing(
    monkeypatch, tmp_path
) -> None:
    _add_repo_paths()
    from services import ssl_errors_store  # type: ignore

    store = ssl_errors_store.SslErrorsStore(
        cache_log_path=str(tmp_path / "missing-cache.log")
    )
    monkeypatch.setattr(
        store,
        "init_db",
        lambda: (_ for _ in ()).throw(
            AssertionError("missing-log tailer initialized the database")
        ),
    )
    monkeypatch.setattr(ssl_errors_store.time, "sleep", _stop_sleep)

    with pytest.raises(StopLoop):
        store._tail_loop()


def test_ssl_errors_tailer_ignores_irrelevant_lines_without_database(
    monkeypatch, tmp_path
) -> None:
    _add_repo_paths()
    from services import ssl_errors_store  # type: ignore

    log_path = tmp_path / "cache.log"
    log_path.write_text("", encoding="utf-8")
    store = ssl_errors_store.SslErrorsStore(cache_log_path=str(log_path))
    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(
        store,
        "_connect",
        lambda: (_ for _ in ()).throw(
            AssertionError("irrelevant cache.log line opened a DB connection")
        ),
    )

    assert store.ingest_line("2026/05/20 12:00:00 kid1| storeDirWriteCleanLogs: Starting...") is None


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


def test_adblock_proxy_meta_insert_duplicate_falls_back_to_update(monkeypatch) -> None:
    _add_repo_paths()
    from services import adblock_store  # type: ignore

    class DuplicateKeyError(Exception):
        def __init__(self) -> None:
            super().__init__(1062, "Duplicate entry 'proxy-a-cache_current_size' for key 'PRIMARY'")

    calls: list[tuple[str, tuple[object, ...]]] = []

    class Conn:
        def execute(self, sql, params=()):
            normalized = " ".join(str(sql).split())
            calls.append((normalized, tuple(params or ())))
            if normalized.startswith("INSERT INTO adblock_proxy_meta"):
                raise DuplicateKeyError

            class Result:
                rowcount = 0 if len(calls) == 1 else 1

            return Result()

    monkeypatch.setattr(adblock_store, "INTEGRITY_ERRORS", (DuplicateKeyError,))
    monkeypatch.setattr(adblock_store, "get_proxy_id", lambda: "proxy-a")

    adblock_store.AdblockStore()._set_proxy_meta(Conn(), "cache_current_size", "42")

    assert calls == [
        (
            "UPDATE adblock_proxy_meta SET v=%s WHERE proxy_id=%s AND k=%s",
            ("42", "proxy-a", "cache_current_size"),
        ),
        (
            "INSERT INTO adblock_proxy_meta(proxy_id,k,v) VALUES(%s,%s,%s)",
            ("proxy-a", "cache_current_size", "42"),
        ),
        (
            "UPDATE adblock_proxy_meta SET v=%s WHERE proxy_id=%s AND k=%s",
            ("42", "proxy-a", "cache_current_size"),
        ),
    ]


def test_adblock_meta_insert_duplicate_falls_back_to_update(monkeypatch) -> None:
    _add_repo_paths()
    from services import adblock_store  # type: ignore

    class DuplicateKeyError(Exception):
        def __init__(self) -> None:
            super().__init__(1062, "Duplicate entry 'refresh_requested' for key 'PRIMARY'")

    calls: list[tuple[str, tuple[object, ...]]] = []

    class Conn:
        def execute(self, sql, params=()):
            normalized = " ".join(str(sql).split())
            calls.append((normalized, tuple(params or ())))
            if normalized.startswith("INSERT INTO adblock_meta"):
                raise DuplicateKeyError

            class Result:
                rowcount = 0 if len(calls) == 1 else 1

            return Result()

    monkeypatch.setattr(adblock_store, "INTEGRITY_ERRORS", (DuplicateKeyError,))

    adblock_store.AdblockStore()._set_meta(Conn(), "refresh_requested", "123")

    assert calls[-1] == (
        "UPDATE adblock_meta SET v=%s WHERE k=%s",
        ("123", "refresh_requested"),
    )


def test_adblock_blocklog_tailer_logs_database_outage_without_traceback(
    monkeypatch, tmp_path
) -> None:
    _add_repo_paths()
    import pymysql  # type: ignore
    from services import adblock_store  # type: ignore

    log_path = tmp_path / "cicap.log"
    log_path.write_text("", encoding="utf-8")
    store = adblock_store.AdblockStore(cicap_access_log_path=str(log_path))
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        store,
        "_connect",
        lambda: (_ for _ in ()).throw(
            pymysql.err.OperationalError(2003, "connect timed out")
        ),
    )
    monkeypatch.setattr(
        adblock_store,
        "log_database_unavailable",
        lambda _logger, key, message, _exc: calls.append((key, message)),
    )
    monkeypatch.setattr(
        adblock_store,
        "log_exception_throttled",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("database outage used traceback logging")
        ),
    )
    monkeypatch.setattr(adblock_store.time, "sleep", _stop_sleep)

    with pytest.raises(StopLoop):
        store._blocklog_tail_loop()

    assert calls == [
        (
            "adblock_store.blocklog.db_unavailable",
            "Adblock blocklog tailer deferred database work while MySQL is unavailable",
        )
    ]


def test_live_stats_tailer_logs_database_outage_without_traceback(
    monkeypatch, tmp_path
) -> None:
    _add_repo_paths()
    import pymysql  # type: ignore
    from services import live_stats  # type: ignore

    log_path = tmp_path / "access.log"
    log_path.write_text("", encoding="utf-8")
    store = live_stats.LiveStatsStore(access_log_path=str(log_path))
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(store, "_accumulate_line", lambda _batch, _line: True)
    monkeypatch.setattr(
        store,
        "_connect",
        lambda: (_ for _ in ()).throw(
            pymysql.err.OperationalError(2003, "connect timed out")
        ),
    )
    monkeypatch.setattr(
        live_stats,
        "log_database_unavailable",
        lambda _logger, key, message, _exc: calls.append((key, message)),
    )
    monkeypatch.setattr(
        live_stats,
        "log_exception_throttled",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("database outage used traceback logging")
        ),
    )
    times = iter([100.0, 101.0, 102.0])
    monkeypatch.setattr(live_stats.time, "time", lambda: next(times))
    monkeypatch.setattr(live_stats.time, "sleep", _stop_sleep)

    class Handle:
        def __init__(self) -> None:
            self.calls = 0

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def seek(self, *_args):
            return 0

        def tell(self) -> int:
            return 0

        def readline(self) -> str:
            self.calls += 1
            return "access line\n" if self.calls == 1 else ""

    monkeypatch.setattr(live_stats.pathlib.Path, "open", lambda *_args, **_kwargs: Handle())

    with pytest.raises(StopLoop):
        store._tail_loop()

    assert calls == [
        (
            "live_stats.idle_commit.db",
            "Live stats tailer deferred idle flush while MySQL is unavailable",
        )
    ]


def test_diagnostic_tailer_logs_database_outage_without_traceback(
    monkeypatch, tmp_path
) -> None:
    _add_repo_paths()
    import pymysql  # type: ignore
    from services import diagnostic_store  # type: ignore

    log_path = tmp_path / "diagnostic.log"
    log_path.write_text("", encoding="utf-8")
    store = diagnostic_store.DiagnosticStore(
        access_log_path=str(log_path), icap_log_path=str(tmp_path / "icap.log")
    )
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        store,
        "_connect",
        lambda: (_ for _ in ()).throw(
            pymysql.err.OperationalError(2003, "connect timed out")
        ),
    )
    monkeypatch.setattr(
        diagnostic_store,
        "log_database_unavailable",
        lambda _logger, key, message, _exc: calls.append((key, message)),
    )
    monkeypatch.setattr(
        diagnostic_store,
        "log_exception_throttled",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("database outage used traceback logging")
        ),
    )
    times = iter([100.0, 101.0, 102.0])
    monkeypatch.setattr(diagnostic_store.time, "time", lambda: next(times))
    monkeypatch.setattr(diagnostic_store.time, "sleep", _stop_sleep)

    class Handle:
        def __init__(self) -> None:
            self.calls = 0

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def seek(self, *_args):
            return 0

        def tell(self) -> int:
            return 0

        def readline(self) -> str:
            self.calls += 1
            return "diagnostic line\n" if self.calls == 1 else ""

    monkeypatch.setattr(
        diagnostic_store.pathlib.Path, "open", lambda *_args, **_kwargs: Handle()
    )

    with pytest.raises(StopLoop):
        store._tail_file_loop(
            str(log_path),
            lambda _line: ("row",),
            lambda _conn, _rows: None,
            "test-diagnostic",
        )

    assert calls == [
        (
            "diagnostic_store.idle_commit.test-diagnostic.db",
            "Diagnostic tailer deferred idle flush in test-diagnostic while MySQL is unavailable",
        )
    ]
