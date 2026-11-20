from __future__ import annotations

import pytest

from .clock_patching import patch_module_clock
from .lifecycle_guard_fakes import is_lifecycle_state_query, lifecycle_state_row


class StopLoop(BaseException):
    pass


def _stop_sleep(_seconds: float) -> None:
    raise StopLoop


class _NullConn:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class _Clock:
    """Mutable monotonic clock shared by the tail runner and its backoff."""

    def __init__(self, now: float = 100.0) -> None:
        self.now = now

    def install(self, monkeypatch) -> None:
        patch_module_clock(
            monkeypatch,
            "services.log_follower",
            "services.observability_backoff",
            "services.logutil",
            monotonic=lambda: self.now,
        )


@pytest.fixture
def adblock_store():
    from services import adblock_store as module  # type: ignore

    return module


@pytest.fixture
def diagnostic_store():
    from services import diagnostic_store as module  # type: ignore

    return module


@pytest.fixture
def ssl_errors_store():
    from services import ssl_errors_store as module  # type: ignore

    return module


def test_diagnostic_tailer_does_not_open_db_connection_while_idle(
    monkeypatch, tmp_path, diagnostic_store
) -> None:
    log_path = tmp_path / "diagnostic.log"
    log_path.write_text("", encoding="utf-8")
    store = diagnostic_store.DiagnosticStore(
        access_log_path=str(log_path), icap_log_path=str(tmp_path / "icap.log")
    )
    store._db_initialized = True
    monkeypatch.setattr(
        store,
        "_connect",
        lambda: (_ for _ in ()).throw(
            AssertionError("idle tailer opened a DB connection")
        ),
    )
    monkeypatch.setattr(store._stop_event, "wait", _stop_sleep)

    with pytest.raises(StopLoop):
        store._tail_file_loop(
            diagnostic_store.LogFollower(str(log_path)),
            lambda _line: None,
            lambda _conn, _rows: None,
            "test-diagnostic",
        )


def test_diagnostic_tailer_keeps_partial_line_until_newline(
    monkeypatch, tmp_path, diagnostic_store
) -> None:
    log_path = tmp_path / "diagnostic.log"
    log_path.write_text("", encoding="utf-8")
    store = diagnostic_store.DiagnosticStore(
        access_log_path=str(log_path), icap_log_path=str(tmp_path / "icap.log")
    )
    store._db_initialized = True
    partial = "diagnostic line"
    sleep_calls = 0
    build_calls: list[str] = []
    flushed_rows: list[tuple[object, ...]] = []
    clock = _Clock()

    def sleep(_seconds: float) -> None:
        nonlocal sleep_calls
        sleep_calls += 1
        clock.now += 1.0
        if sleep_calls == 1:
            log_path.write_text(partial, encoding="utf-8")
            return
        if sleep_calls == 2:
            assert build_calls == []
            assert flushed_rows == []
            log_path.write_text(partial + "\n", encoding="utf-8")
            return
        if sleep_calls < 5:
            return
        raise StopLoop

    def build_row(line: str):
        build_calls.append(line)
        return ("row", line)

    monkeypatch.setenv("DIAGNOSTIC_COMMIT_INTERVAL_SECONDS", "1")
    monkeypatch.setattr(store, "_connect", _NullConn)
    clock.install(monkeypatch)
    monkeypatch.setattr(store._stop_event, "wait", sleep)

    with pytest.raises(StopLoop):
        store._tail_file_loop(
            diagnostic_store.LogFollower(str(log_path)),
            build_row,
            lambda _conn, rows: flushed_rows.extend(rows),
            "test-diagnostic",
        )

    assert build_calls == [partial]
    assert flushed_rows == [("row", partial)]


def test_diagnostic_tailer_restarts_at_zero_after_copytruncate_regrowth(
    monkeypatch, tmp_path, diagnostic_store
) -> None:
    log_path = tmp_path / "diagnostic.log"
    log_path.write_text("", encoding="utf-8")
    store = diagnostic_store.DiagnosticStore(
        access_log_path=str(log_path), icap_log_path=str(tmp_path / "icap.log")
    )
    store._db_initialized = True
    sleep_calls = 0
    build_calls: list[str] = []

    def sleep(_seconds: float) -> None:
        nonlocal sleep_calls
        sleep_calls += 1
        if sleep_calls == 1:
            log_path.write_text("old record\n", encoding="utf-8")
            return
        if sleep_calls == 2:
            # Model copytruncate plus rapid regrowth past the old cursor before
            # the tailer's next poll.
            log_path.write_text("replacement record\n", encoding="utf-8")
            return
        raise StopLoop

    def build_row(line: str):
        build_calls.append(line)
        return ("row", line)

    monkeypatch.setenv("DIAGNOSTIC_COMMIT_INTERVAL_SECONDS", "10")
    _Clock().install(monkeypatch)
    monkeypatch.setattr(store._stop_event, "wait", sleep)

    with pytest.raises(StopLoop):
        store._tail_file_loop(
            diagnostic_store.LogFollower(str(log_path)),
            build_row,
            lambda _conn, _rows: None,
            "test-diagnostic",
        )

    assert build_calls == ["old record", "replacement record"]


def test_diagnostic_tailer_recovers_when_partial_line_rotates(
    monkeypatch, tmp_path, diagnostic_store
) -> None:
    log_path = tmp_path / "diagnostic.log"
    rotated_path = tmp_path / "diagnostic.log.1"
    log_path.write_text("", encoding="utf-8")
    store = diagnostic_store.DiagnosticStore(
        access_log_path=str(log_path), icap_log_path=str(tmp_path / "icap.log")
    )
    store._db_initialized = True
    sleep_calls = 0
    build_calls: list[str] = []
    flushes: list[list[tuple[str, str]]] = []
    clock = _Clock()

    def sleep(_seconds: float) -> None:
        nonlocal sleep_calls
        sleep_calls += 1
        clock.now += 0.1
        if sleep_calls == 1:
            log_path.write_text("ready\npartial", encoding="utf-8")
            return
        if sleep_calls == 2:
            log_path.rename(rotated_path)
            log_path.write_text("after\n", encoding="utf-8")
            return
        if sleep_calls < 6:
            clock.now += 1.0
            return
        raise StopLoop

    def build_row(line: str):
        build_calls.append(line)
        return ("row", line)

    monkeypatch.setenv("DIAGNOSTIC_COMMIT_INTERVAL_SECONDS", "1")
    monkeypatch.setattr(store, "_connect", _NullConn)
    clock.install(monkeypatch)
    monkeypatch.setattr(store._stop_event, "wait", sleep)

    with pytest.raises(StopLoop):
        store._tail_file_loop(
            diagnostic_store.LogFollower(str(log_path)),
            build_row,
            lambda _conn, rows: flushes.append(list(rows)),
            "test-diagnostic",
        )

    # The unterminated fragment of the replaced file is never parsed; the
    # pending row is flushed before following the new file from its start.
    assert build_calls == ["ready", "after"]
    assert flushes[0] == [("row", "ready")]
    assert [("row", "after")] in flushes


def test_ssl_errors_tailer_does_not_open_db_connection_while_idle(
    monkeypatch, tmp_path, ssl_errors_store
) -> None:
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
    monkeypatch.setattr(
        store,
        "_tailer_connect",
        lambda: (_ for _ in ()).throw(
            AssertionError("idle tailer opened an unpooled DB connection")
        ),
    )
    monkeypatch.setattr(store._stop_event, "wait", _stop_sleep)

    with pytest.raises(StopLoop):
        store._tail_loop()


def test_ssl_errors_tailer_keeps_partial_line_until_newline(
    monkeypatch, tmp_path, ssl_errors_store
) -> None:
    log_path = tmp_path / "cache.log"
    log_path.write_text("", encoding="utf-8")
    store = ssl_errors_store.SslErrorsStore(cache_log_path=str(log_path))
    partial = "2026/08/09 12:00:00| TLS handshake failed host=split."
    suffix = "example detail=complete\n"
    sleep_calls = 0
    connections = 0
    ingested: list[tuple[str, str]] = []

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    def sleep(_seconds: float) -> None:
        nonlocal sleep_calls
        sleep_calls += 1
        if sleep_calls == 1:
            with log_path.open("a", encoding="utf-8") as log_file:
                log_file.write(partial)
            return
        if sleep_calls == 2:
            assert ingested == []
            assert connections == 0
            with log_path.open("a", encoding="utf-8") as log_file:
                log_file.write(suffix)
            return
        raise StopLoop

    def connect() -> Conn:
        nonlocal connections
        connections += 1
        return Conn()

    monkeypatch.setenv("SSL_ERRORS_COMMIT_INTERVAL_SECONDS", "10")
    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "_tailer_connect", connect)
    monkeypatch.setattr(
        store,
        "_upsert",
        lambda _conn, domain, _category, _reason, _ts, sample: ingested.append(
            (domain, sample)
        ),
    )
    patch_module_clock(monkeypatch, ssl_errors_store, time=lambda: 100.0)
    monkeypatch.setattr(store._stop_event, "wait", sleep)

    with pytest.raises(StopLoop):
        store._tail_loop()

    assert connections == 1
    assert ingested == [
        ("split.example", "TLS handshake failed host=split.example detail=complete")
    ]


def test_ssl_errors_tailer_idle_flush_uses_monotonic_elapsed_time(
    monkeypatch, tmp_path, ssl_errors_store
) -> None:
    log_path = tmp_path / "cache.log"
    log_path.write_text("", encoding="utf-8")
    store = ssl_errors_store.SslErrorsStore(cache_log_path=str(log_path))
    header = (
        "2026/08/09 12:00:00| Cannot accept a TLS connection host=rollback.example\n"
    )
    flushed: list[str] = []
    sleep_calls = 0

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    def sleep(_seconds: float) -> None:
        nonlocal sleep_calls
        sleep_calls += 1
        if sleep_calls == 1:
            log_path.write_text(header, encoding="utf-8")
            return
        raise StopLoop

    def flush_pending(_conn) -> bool:
        if store._pending_error is None:
            return False
        flushed.append(str(store._pending_error["domain"]))
        store._pending_error["committed"] = True
        return True

    monotonic_times = iter([100.0, 100.1, 100.2, 101.2])
    monkeypatch.setenv("SSL_ERRORS_COMMIT_INTERVAL_SECONDS", "1")
    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "_tailer_connect", Conn)
    monkeypatch.setattr(store, "_flush_pending_error", flush_pending)
    patch_module_clock(
        monkeypatch, ssl_errors_store, monotonic=lambda: next(monotonic_times, 101.2)
    )
    patch_module_clock(
        monkeypatch,
        ssl_errors_store,
        time=lambda: (_ for _ in ()).throw(AssertionError("cadence used wall time")),
    )
    monkeypatch.setattr(store._stop_event, "wait", sleep)

    with pytest.raises(StopLoop):
        store._tail_loop()

    assert flushed == ["rollback.example"]


def test_ssl_errors_tailer_retries_idle_flush_after_database_error(
    monkeypatch, tmp_path, ssl_errors_store
) -> None:
    import pymysql  # type: ignore

    log_path = tmp_path / "cache.log"
    log_path.write_text("", encoding="utf-8")
    store = ssl_errors_store.SslErrorsStore(cache_log_path=str(log_path))
    header = "2026/08/09 12:00:00| Cannot accept a TLS connection host=retry.example\n"
    sleep_calls = 0
    attempts: list[str] = []

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    def sleep(_seconds: float) -> None:
        nonlocal sleep_calls
        sleep_calls += 1
        if sleep_calls == 1:
            log_path.write_text(header, encoding="utf-8")
            return
        if sleep_calls == 2:
            assert attempts == ["retry.example"]
            assert store._has_uncommitted_pending_error()
            return
        raise StopLoop

    def flush_pending(_conn) -> bool:
        if store._pending_error is None:
            return False
        domain = str(store._pending_error["domain"])
        attempts.append(domain)
        if len(attempts) == 1:
            raise pymysql.err.OperationalError(2003, "connect timed out")
        store._pending_error["committed"] = True
        return True

    monotonic_times = iter([100.0, 100.1, 100.2, 101.2, 102.3])
    monkeypatch.setenv("SSL_ERRORS_COMMIT_INTERVAL_SECONDS", "1")
    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "_tailer_connect", Conn)
    monkeypatch.setattr(store, "_flush_pending_error", flush_pending)
    patch_module_clock(
        monkeypatch,
        ssl_errors_store,
        "services.logutil",
        monotonic=lambda: next(monotonic_times, 102.3),
    )
    monkeypatch.setattr(store._stop_event, "wait", sleep)

    with pytest.raises(StopLoop):
        store._tail_loop()

    assert attempts == ["retry.example", "retry.example"]
    assert not store._has_uncommitted_pending_error()


def test_ssl_errors_tailer_restarts_at_zero_after_copytruncate_regrowth(
    monkeypatch, tmp_path, ssl_errors_store
) -> None:
    log_path = tmp_path / "cache.log"
    log_path.write_text("", encoding="utf-8")
    original_inode = log_path.stat().st_ino
    store = ssl_errors_store.SslErrorsStore(cache_log_path=str(log_path))
    original_line = (
        "2026/08/06 07:00:00| TLS handshake failed host=old.example detail="
        + ("x" * 200)
        + "\n"
    )
    replacement_line = (
        "2026/08/06 07:00:01| TLS handshake failed host=replacement.example\n"
    )
    replacement_content = replacement_line + ("cache filler " + ("x" * 300) + "\n")
    assert len(replacement_line) < len(original_line) < len(replacement_content)
    sleep_calls = 0
    domains: list[str] = []

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    def sleep(_seconds: float) -> None:
        nonlocal sleep_calls
        sleep_calls += 1
        if sleep_calls == 1:
            log_path.write_text(original_line, encoding="utf-8")
            return
        if sleep_calls == 2:
            assert log_path.stat().st_size == len(original_line)
            log_path.write_text(replacement_content, encoding="utf-8")
            assert log_path.stat().st_ino == original_inode
            assert log_path.stat().st_size > len(original_line)
            return
        raise StopLoop

    monkeypatch.setenv("SSL_ERRORS_COMMIT_INTERVAL_SECONDS", "10")
    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "_tailer_connect", Conn)
    monkeypatch.setattr(
        store,
        "_upsert",
        lambda _conn, domain, _category, _reason, _ts, _sample: domains.append(domain),
    )
    patch_module_clock(
        monkeypatch, ssl_errors_store, "services.runtime_helpers", time=lambda: 100.0
    )
    monkeypatch.setattr(store._stop_event, "wait", sleep)

    with pytest.raises(StopLoop):
        store._tail_loop()

    assert domains == ["old.example", "replacement.example"]


def test_ssl_errors_tailer_does_not_initialize_db_when_log_missing(
    monkeypatch, tmp_path, ssl_errors_store
) -> None:
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
    monkeypatch.setattr(store._stop_event, "wait", _stop_sleep)

    with pytest.raises(StopLoop):
        store._tail_loop()


def test_ssl_errors_tailer_seeds_restart_gap_then_tails_from_capture(
    monkeypatch, tmp_path, ssl_errors_store
) -> None:
    """Errors logged while the runtime restarted, or while seeding, are kept."""
    log_path = tmp_path / "cache.log"
    log_path.write_text("2026/05/20 12:00:00 kid1| before restart\n", encoding="utf-8")
    store = ssl_errors_store.SslErrorsStore(cache_log_path=str(log_path))
    seeded: list[int] = []
    tailed: list[str] = []

    def seed() -> None:
        seeded.append(1)
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write("2026/05/20 12:00:01 kid1| during seed\n")

    def ingest(_conn, line: str) -> bool:
        tailed.append(line)
        return False

    monkeypatch.setattr(store, "seed_from_recent_log", seed)
    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "_line_requires_database", lambda _line: True)
    monkeypatch.setattr(store, "_tailer_connect", _NullConn)
    monkeypatch.setattr(store, "_ingest_line_with_conn", ingest)
    monkeypatch.setattr(store._stop_event, "wait", _stop_sleep)

    with pytest.raises(StopLoop):
        store._tail_loop()

    assert seeded == [1]
    assert tailed == ["2026/05/20 12:00:01 kid1| during seed"]


def test_ssl_errors_tailer_ignores_irrelevant_lines_without_database(
    monkeypatch, tmp_path, ssl_errors_store
) -> None:
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

    assert (
        store.ingest_line(
            "2026/05/20 12:00:00 kid1| storeDirWriteCleanLogs: Starting..."
        )
        is None
    )


def test_adblock_blocklog_tailer_does_not_open_db_connection_when_log_missing(
    monkeypatch, tmp_path, adblock_store
) -> None:
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
    monkeypatch.setattr(store._blocklog_stop_event, "wait", _stop_sleep)

    with pytest.raises(StopLoop):
        store._blocklog_tail_loop()


def test_adblock_proxy_meta_values_write_one_row_alias_upsert(
    monkeypatch, adblock_store
) -> None:
    calls: list[tuple[str, tuple[object, ...]]] = []

    class Conn:
        def execute(self, sql, params=()):
            calls.append((" ".join(str(sql).split()), tuple(params or ())))

            class Result:
                rowcount = 2

            return Result()

    monkeypatch.setattr(adblock_store, "get_proxy_id", lambda: "proxy-a")
    store = adblock_store.AdblockStore()
    store._set_proxy_meta_values(
        Conn(),
        {"cicap_access_pos": "20", "cicap_access_inode": "10"},
    )

    # One statement for every key; the row alias avoids the deprecated VALUES()
    # function, and unchanged values cannot fall into an UPDATE/INSERT/UPDATE
    # retry chain (MySQL reports 0 affected rows for an unchanged UPDATE).
    assert calls == [
        (
            (
                "INSERT INTO adblock_proxy_meta(proxy_id,k,v) VALUES (%s,%s,%s),(%s,%s,%s) "
                "AS incoming ON DUPLICATE KEY UPDATE v=incoming.v"
            ),
            (
                "proxy-a",
                "cicap_access_inode",
                "10",
                "proxy-a",
                "cicap_access_pos",
                "20",
            ),
        ),
    ]


def test_adblock_tailer_keeps_partial_line_until_newline(
    monkeypatch, tmp_path, adblock_store
) -> None:
    log_path = tmp_path / "cicap-access.log"
    partial = (
        "1710000000\t10.0.0.5\t127.0.0.1\tREQMOD\t/adblockreq\t200\t"
        "GET http://ads.example/banner.js HTTP/1.1\t"
    )
    suffix = "http://ads.example/banner.js\tHTTP/1.1 403 Forbidden\textra\n"
    log_path.write_text(partial, encoding="utf-8")

    meta = {"cicap_access_inode": "0", "cicap_access_pos": "0"}
    inserted: list[tuple[object, ...]] = []
    calls: list[str] = []

    meta_writes: list[dict[str, str]] = []

    class Result:
        def __init__(self, row=None, *, rows=None, rowcount: int = 1) -> None:
            self._row = row
            self._rows = list(rows or ())
            self.rowcount = rowcount

        def fetchone(self):
            return self._row

        def fetchall(self):
            return list(self._rows)

    class Conn:
        native = object()

        def execute(self, sql, params=()):
            normalized = " ".join(str(sql).split())
            calls.append(normalized)
            if "SELECT k, v FROM adblock_proxy_meta" in normalized:
                keys = [str(key) for key in tuple(params or ())[1:]]
                return Result(rows=[(key, meta[key]) for key in keys if key in meta])
            if "CREATE TABLE IF NOT EXISTS proxy_lifecycle_tombstones" in normalized:
                return Result()
            if is_lifecycle_state_query(normalized):
                return Result(lifecycle_state_row(registry_status="healthy"))
            if "GET_LOCK" in normalized:
                return Result({"acquired": 1})
            if "RELEASE_LOCK" in normalized:
                return Result()
            if normalized.startswith("INSERT INTO adblock_proxy_meta"):
                values = tuple(params or ())
                for offset in range(0, len(values), 3):
                    _proxy_id, key, value = values[offset : offset + 3]
                    meta[str(key)] = str(value)
                meta_writes.append(dict(meta))
            elif normalized.startswith("INSERT IGNORE INTO adblock_events"):
                inserted.append(tuple(params or ()))

            return Result()

        def executemany(self, sql, rows):
            normalized = " ".join(str(sql).split())
            if normalized.startswith("INSERT IGNORE INTO adblock_events"):
                inserted.extend(tuple(row) for row in rows)
            return Result(rowcount=len(inserted))

        def commit(self) -> None:
            return None

        def rollback(self) -> None:
            return None

    monkeypatch.setattr(adblock_store, "get_proxy_id", lambda: "proxy-a")
    store = adblock_store.AdblockStore(cicap_access_log_path=str(log_path))
    conn = Conn()

    store._ingest_new_cicap_lines(conn)

    assert inserted == []
    assert meta["cicap_access_pos"] == "0"
    assert meta["cicap_access_inode"] == str(log_path.stat().st_ino)
    assert any("proxy_lifecycle_tombstones" in call for call in calls)
    assert any("FROM proxy_instances" in call for call in calls)
    assert any("GET_LOCK" in call for call in calls)

    log_path.write_text(partial + suffix, encoding="utf-8")

    store._ingest_new_cicap_lines(conn)

    assert len(inserted) == 1
    assert inserted[0][0] == "proxy-a"
    assert inserted[0][5] == "http://ads.example/banner.js"
    assert meta["cicap_access_pos"] == str(log_path.stat().st_size)
    # The inode changed on the first pass and the position on the second; each
    # pass wrote only the keys that moved.
    assert [sorted(write) for write in meta_writes] == [
        ["cicap_access_inode", "cicap_access_pos"],
        ["cicap_access_inode", "cicap_access_pos"],
    ]

    assert store._cicap_checkpoint == (
        log_path.stat().st_ino,
        log_path.stat().st_size,
    )
    assert store._cicap_log_unchanged(str(log_path)) is True

    # An idle poll with an unchanged checkpoint reads once and writes nothing:
    # no lifecycle lock, no upsert, no commit traffic.
    calls.clear()
    store._ingest_new_cicap_lines(conn)
    assert len(meta_writes) == 2
    assert not any("GET_LOCK" in call for call in calls)
    assert [call for call in calls if "adblock_proxy_meta" in call] == [
        "SELECT k, v FROM adblock_proxy_meta WHERE proxy_id=%s AND k IN (%s,%s)"
    ]


def test_adblock_seed_ignores_syntactically_valid_partial_trailing_record(
    monkeypatch, tmp_path, adblock_store
) -> None:
    log_path = tmp_path / "cicap-access.log"
    complete = (
        "1710000000\t10.0.0.5\t127.0.0.1\tREQMOD\t/adblockreq\t200\t"
        "GET http://ads.example/complete.js HTTP/1.1\t"
        "http://ads.example/complete.js\tHTTP/1.1 403 Forbidden\teasylist\trule"
    )
    partial = (
        "1710000001\t10.0.0.5\t127.0.0.1\tREQMOD\t/adblockreq\t200\t"
        "GET http://ads.example/partial.js HTTP/1.1\t"
        "http://ads.example/partial.js\tHTTP/1.1 403 Forbidden"
    )
    log_path.write_text(complete + "\n" + partial, encoding="utf-8")
    inserted: list[dict[str, object]] = []
    store = adblock_store.AdblockStore(cicap_access_log_path=str(log_path))
    assert store._parse_cicap_access_line(partial) is not None
    monkeypatch.setattr(store, "_insert_event", lambda _conn, row: inserted.append(row))
    monkeypatch.setattr(store, "_prune_events", lambda _conn: None)

    store._seed_from_recent_log(object())

    assert [row["url"] for row in inserted] == ["http://ads.example/complete.js"]


def _pad_cicap_record(base: bytes, *, total_size: int, newline: bool) -> bytes:
    body_size = total_size - int(newline)
    remaining = body_size - len(base)
    chunks: list[bytes] = []
    while remaining > 1001:
        chunks.append(b"\t" + (b"x" * 1000))
        remaining -= 1001
    if remaining:
        chunks.append(b"\t" + (b"x" * (remaining - 1)))
    return base + b"".join(chunks) + (b"\n" if newline else b"")


def test_adblock_seed_reader_drops_plausible_truncated_suffix_without_newline(
    tmp_path, adblock_store
) -> None:
    log_path = tmp_path / "cicap-access.log"
    plausible_suffix = (
        b"1710000002\t10.0.0.5\t127.0.0.1\tREQMOD\t/adblockreq\t200\t"
        b"GET http://ads.example/truncated.js HTTP/1.1\t"
        b"http://ads.example/truncated.js\tHTTP/1.1 403 Forbidden\t"
    )
    plausible_suffix = _pad_cicap_record(
        plausible_suffix,
        total_size=1_000_000,
        newline=False,
    )
    assert len(plausible_suffix) == 1_000_000
    log_path.write_bytes(b"oversized-record-prefix" + plausible_suffix)
    store = adblock_store.AdblockStore(cicap_access_log_path=str(log_path))
    assert store._parse_cicap_access_line(plausible_suffix.decode()) is not None

    lines = store._read_last_lines(str(log_path), max_lines=10)

    assert lines == []


def test_adblock_seed_reader_keeps_line_when_window_starts_at_boundary(
    tmp_path, adblock_store
) -> None:
    log_path = tmp_path / "cicap-access.log"
    base = (
        b"1710000003\t10.0.0.5\t127.0.0.1\tREQMOD\t/adblockreq\t200\t"
        b"GET http://ads.example/boundary.js HTTP/1.1\t"
        b"http://ads.example/boundary.js\tHTTP/1.1 403 Forbidden\t"
    )
    tailed_record = _pad_cicap_record(base, total_size=1_000_000, newline=True)
    assert len(tailed_record) == 1_000_000
    log_path.write_bytes(b"earlier-record\n" + tailed_record)
    store = adblock_store.AdblockStore(cicap_access_log_path=str(log_path))

    lines = store._read_last_lines(str(log_path), max_lines=1)

    assert lines == [tailed_record.decode().rstrip("\n")]


def test_adblock_meta_set_is_one_row_alias_upsert(monkeypatch, adblock_store) -> None:
    calls: list[tuple[str, tuple[object, ...]]] = []

    class Conn:
        def execute(self, sql, params=()):
            calls.append((" ".join(str(sql).split()), tuple(params or ())))

            class Result:
                rowcount = 0

            return Result()

    adblock_store.AdblockStore()._set_meta(Conn(), "refresh_requested", "1")

    assert calls == [
        (
            "INSERT INTO adblock_meta(k,v) VALUES(%s,%s) AS incoming ON DUPLICATE KEY UPDATE v=incoming.v",
            ("refresh_requested", "1"),
        ),
    ]


def test_adblock_blocklog_tailer_logs_database_outage_without_traceback(
    monkeypatch, tmp_path, adblock_store
) -> None:
    import pymysql  # type: ignore

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
    monkeypatch.setattr(store._blocklog_stop_event, "wait", _stop_sleep)

    with pytest.raises(StopLoop):
        store._blocklog_tail_loop()

    assert calls == [
        (
            "adblock_store.blocklog.db_unavailable",
            "Adblock blocklog tailer deferred database work while MySQL is unavailable",
        )
    ]


def test_diagnostic_tailer_logs_database_outage_without_traceback(
    monkeypatch, tmp_path, diagnostic_store
) -> None:
    import pymysql  # type: ignore
    from services import log_follower

    log_path = tmp_path / "diagnostic.log"
    log_path.write_text("", encoding="utf-8")
    store = diagnostic_store.DiagnosticStore(
        access_log_path=str(log_path), icap_log_path=str(tmp_path / "icap.log")
    )
    store._db_initialized = True
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        store,
        "_connect",
        lambda: (_ for _ in ()).throw(
            pymysql.err.OperationalError(2003, "connect timed out")
        ),
    )
    monkeypatch.setattr(
        log_follower,
        "log_database_unavailable",
        lambda _logger, key, message, _exc: calls.append((key, message)),
    )
    monkeypatch.setattr(
        log_follower,
        "log_exception_throttled",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("database outage used traceback logging")
        ),
    )
    clock = _Clock()
    sleeps = 0

    def sleep(_seconds: float) -> None:
        nonlocal sleeps
        sleeps += 1
        clock.now += 2.0
        if sleeps == 1:
            log_path.write_text("diagnostic line\n", encoding="utf-8")
            return
        if sleeps < 3:
            return
        raise StopLoop

    clock.install(monkeypatch)
    monkeypatch.setenv("DIAGNOSTIC_COMMIT_INTERVAL_SECONDS", "1")
    monkeypatch.setattr(store._stop_event, "wait", sleep)

    with pytest.raises(StopLoop):
        store._tail_file_loop(
            diagnostic_store.LogFollower(str(log_path)),
            lambda _line: ("row",),
            lambda _conn, _rows: None,
            "test-diagnostic",
        )

    assert calls[0][0] in {
        "diagnostic_store.test-diagnostic.commit.db",
        "diagnostic_store.test-diagnostic.idle_commit.db",
    }
    assert calls[0][1].startswith("Diagnostic tailer for test-diagnostic deferred ")
    assert "flush while MySQL is unavailable; retrying in about " in calls[0][1]


def test_diagnostic_tailer_retains_rotation_rows_until_retry_succeeds(
    monkeypatch, tmp_path, diagnostic_store
) -> None:
    import pymysql  # type: ignore
    from services import log_follower

    log_path = tmp_path / "diagnostic.log"
    log_path.write_text("", encoding="utf-8")
    store = diagnostic_store.DiagnosticStore(
        access_log_path=str(log_path), icap_log_path=str(tmp_path / "icap.log")
    )
    store._db_initialized = True
    rows_flushed: list[tuple[object, ...]] = []
    flush_attempts = 0

    def connect():
        nonlocal flush_attempts
        flush_attempts += 1
        if flush_attempts == 1:
            raise pymysql.err.OperationalError(2003, "connect timed out")
        return _NullConn()

    outage_logs: list[tuple[str, str]] = []
    clock = _Clock()
    sleeps = 0

    def sleep(_seconds: float) -> None:
        nonlocal sleeps
        sleeps += 1
        clock.now += 0.1
        if sleeps == 1:
            log_path.write_text("diagnostic line\n", encoding="utf-8")
        elif sleeps == 2:
            log_path.rename(tmp_path / "diagnostic.log.1")
            log_path.write_text("", encoding="utf-8")
        elif flush_attempts >= 2 or sleeps >= 40:
            raise StopLoop

    monkeypatch.setenv("DIAGNOSTIC_COMMIT_INTERVAL_SECONDS", "1")
    monkeypatch.setenv("DIAGNOSTIC_DB_WRITE_BACKOFF_INITIAL_SECONDS", "0.25")
    monkeypatch.setenv("DIAGNOSTIC_DB_WRITE_BACKOFF_MAX_SECONDS", "0.25")
    monkeypatch.setenv("DIAGNOSTIC_DB_WRITE_BACKOFF_JITTER_RATIO", "0")
    monkeypatch.setattr(store, "_connect", connect)
    clock.install(monkeypatch)
    monkeypatch.setattr(store._stop_event, "wait", sleep)
    monkeypatch.setattr(
        log_follower,
        "log_database_unavailable",
        lambda _logger, key, message, _exc: outage_logs.append((key, message)),
    )

    with pytest.raises(StopLoop):
        store._tail_file_loop(
            diagnostic_store.LogFollower(str(log_path)),
            lambda _line: ("retained-row",),
            lambda _conn, rows: rows_flushed.extend(rows),
            "test-diagnostic",
        )

    assert rows_flushed == [("retained-row",)]
    assert flush_attempts == 2
    assert outage_logs[0][0] == "diagnostic_store.test-diagnostic.rotate.db"
    assert outage_logs[0][1].startswith(
        "Diagnostic tailer for test-diagnostic deferred rotation flush while MySQL is unavailable; retrying in about "
    )


def test_diagnostic_tailer_skips_rotation_flush_while_backoff_active(
    monkeypatch, tmp_path, diagnostic_store
) -> None:
    import pymysql  # type: ignore
    from services import log_follower

    log_path = tmp_path / "diagnostic.log"
    log_path.write_text("", encoding="utf-8")
    store = diagnostic_store.DiagnosticStore(
        access_log_path=str(log_path), icap_log_path=str(tmp_path / "icap.log")
    )
    store._db_initialized = True
    flush_attempts = 0

    def connect():
        nonlocal flush_attempts
        flush_attempts += 1
        raise pymysql.err.OperationalError(2003, "connect timed out")

    outage_logs: list[tuple[str, str]] = []
    clock = _Clock()
    sleeps = 0

    def sleep(_seconds: float) -> None:
        nonlocal sleeps
        sleeps += 1
        clock.now += 0.3
        if sleeps == 1:
            log_path.write_text("diagnostic line\n", encoding="utf-8")
        elif sleeps == 2:
            log_path.rename(tmp_path / "diagnostic.log.1")
            log_path.write_text("", encoding="utf-8")
        elif sleeps >= 4:
            raise StopLoop

    monkeypatch.setenv("DIAGNOSTIC_COMMIT_BATCH", "25")
    monkeypatch.setenv("DIAGNOSTIC_COMMIT_INTERVAL_SECONDS", "0.25")
    monkeypatch.setenv("DIAGNOSTIC_DB_WRITE_BACKOFF_INITIAL_SECONDS", "10")
    monkeypatch.setenv("DIAGNOSTIC_DB_WRITE_BACKOFF_MAX_SECONDS", "10")
    monkeypatch.setenv("DIAGNOSTIC_DB_WRITE_BACKOFF_JITTER_RATIO", "0")
    monkeypatch.setattr(store, "_connect", connect)
    clock.install(monkeypatch)
    monkeypatch.setattr(store._stop_event, "wait", sleep)
    monkeypatch.setattr(
        log_follower,
        "log_database_unavailable",
        lambda _logger, key, message, _exc: outage_logs.append((key, message)),
    )

    with pytest.raises(StopLoop):
        store._tail_file_loop(
            diagnostic_store.LogFollower(str(log_path)),
            lambda _line: ("retained-row",),
            lambda _conn, _rows: None,
            "test-diagnostic",
        )

    # The first failure arms a 10 s backoff; the rotation that follows must
    # not hammer MySQL again inside that window.
    assert flush_attempts == 1
    assert [key for key, _message in outage_logs] == [
        "diagnostic_store.test-diagnostic.commit.db"
    ]


@pytest.mark.parametrize(
    ("module_fixture", "make_store", "start_name", "stop_name", "event_name"),
    [
        (
            "adblock_store",
            lambda module, path: module.AdblockStore(cicap_access_log_path=str(path)),
            "start_blocklog_background",
            "stop_blocklog_background",
            "_blocklog_stop_event",
        ),
        (
            "ssl_errors_store",
            lambda module, path: module.SslErrorsStore(cache_log_path=str(path)),
            "start_background",
            "stop_background",
            "_stop_event",
        ),
        (
            "diagnostic_store",
            lambda module, path: module.DiagnosticStore(
                access_log_path=str(path), icap_log_path=str(path)
            ),
            "start_background",
            "stop_background",
            "_stop_event",
        ),
    ],
)
def test_missing_log_poll_is_interruptible_by_bounded_stop(
    request,
    monkeypatch,
    tmp_path,
    module_fixture,
    make_store,
    start_name,
    stop_name,
    event_name,
) -> None:
    """A stop signal must wake tailers instead of waiting out their poll delay."""
    module = request.getfixturevalue(module_fixture)
    store = make_store(module, tmp_path / "missing.log")
    entered_wait = __import__("threading").Event()
    stop_event = getattr(store, event_name)
    real_wait = stop_event.wait

    def observed_wait(timeout: float) -> bool:
        entered_wait.set()
        return real_wait(timeout)

    monkeypatch.setattr(stop_event, "wait", observed_wait)
    if hasattr(store, "init_db"):
        monkeypatch.setattr(store, "init_db", lambda: None)
    if hasattr(store, "seed_from_recent_log"):
        monkeypatch.setattr(store, "seed_from_recent_log", lambda: None)
    if hasattr(store, "seed_from_recent_logs"):
        monkeypatch.setattr(store, "seed_from_recent_logs", lambda: None)

    getattr(store, start_name)()
    assert entered_wait.wait(1.0), "tailer did not enter its interruptible poll wait"
    assert getattr(store, stop_name)(timeout=0.25) is True


def test_adblock_tailer_poll_skips_mysql_while_log_is_unchanged(
    monkeypatch, tmp_path, adblock_store
) -> None:
    log_path = tmp_path / "cicap-access.log"
    log_path.write_text("", encoding="utf-8")
    store = adblock_store.AdblockStore(cicap_access_log_path=str(log_path))
    ingests: list[int] = []

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    def fake_ingest(_conn) -> None:
        ingests.append(1)
        st = log_path.stat()
        store._cicap_checkpoint = (st.st_ino, st.st_size)

    polls = iter(range(4))

    def wait_once(_seconds: float) -> bool:
        index = next(polls, None)
        if index == 1:
            # The log grows after the second idle poll.
            log_path.write_text("x\n", encoding="utf-8")
        if index is None or index >= 3:
            store._blocklog_stop_event.set()
        return False

    monkeypatch.setattr(store, "_connect", Conn)
    monkeypatch.setattr(store, "_ingest_new_cicap_lines", fake_ingest)
    monkeypatch.setattr(store._blocklog_stop_event, "wait", wait_once)

    store._blocklog_tail_loop()

    # First poll establishes the checkpoint; identical (inode, size) polls do
    # not open a connection; growth goes back to MySQL once.
    assert len(ingests) == 2
