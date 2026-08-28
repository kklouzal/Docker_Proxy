import importlib
import io
import os
import time
from pathlib import Path
from typing import NoReturn

import pytest
from services import blocked_log_runtime, schema_lifecycle

from .mysql_test_utils import configure_test_mysql_env


def _webcat_acl_module():
    from tools import webcat_acl  # type: ignore

    return webcat_acl


def test_webcat_acl_uses_local_snapshot_for_parent_domain_lookups(
    tmp_path, monkeypatch
) -> None:
    configure_test_mysql_env(tmp_path / "webcat-acl")

    from services.db import connect  # type: ignore

    webcat_acl = _webcat_acl_module()
    with connect() as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS webcat_domains (domain VARCHAR(255) PRIMARY KEY, categories TEXT NOT NULL)"
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS webcat_meta (k VARCHAR(64) PRIMARY KEY, v LONGTEXT NOT NULL)"
        )
        conn.execute(
            "INSERT INTO webcat_domains(domain, categories) VALUES(%s, %s) ON DUPLICATE KEY UPDATE categories=VALUES(categories)",
            ("example.com", "adult|phishing"),
        )
        conn.execute(
            "INSERT INTO webcat_meta(k, v) VALUES(%s, %s) ON DUPLICATE KEY UPDATE v=VALUES(v)",
            ("built_ts", "123"),
        )

    snapshot_dir = tmp_path / "snapshot"
    monkeypatch.setenv("WEBFILTER_SNAPSHOT_DIR", str(snapshot_dir))
    db = webcat_acl._Db()

    assert db._build_snapshot_from_db(expected_built_ts=123) is True
    assert (snapshot_dir / "webcat.sqlite").exists()

    db._conn = None
    db._last_open_attempt = webcat_acl._now()

    assert db.lookup_categories("cdn.example.com") == {"adult", "phishing"}


def test_webcat_acl_refreshes_stale_disk_snapshot_before_negative_lookup(
    tmp_path, monkeypatch
) -> None:
    configure_test_mysql_env(tmp_path / "webcat-acl-stale-snapshot")

    from services.db import connect  # type: ignore

    webcat_acl = _webcat_acl_module()
    snapshot_dir = tmp_path / "snapshot"
    monkeypatch.setenv("WEBFILTER_SNAPSHOT_DIR", str(snapshot_dir))
    db = webcat_acl._Db()

    with connect() as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS webcat_domains (domain VARCHAR(255) PRIMARY KEY, categories TEXT NOT NULL)"
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS webcat_meta (k VARCHAR(64) PRIMARY KEY, v LONGTEXT NOT NULL)"
        )
        conn.execute(
            "INSERT INTO webcat_meta(k, v) VALUES(%s, %s) ON DUPLICATE KEY UPDATE v=VALUES(v)",
            ("built_ts", "100"),
        )

    assert db._build_snapshot_from_db(expected_built_ts=100) is True

    with connect() as conn:
        conn.execute(
            "INSERT INTO webcat_domains(domain, categories) VALUES(%s, %s) ON DUPLICATE KEY UPDATE categories=VALUES(categories)",
            ("traffic-fixture", "adult"),
        )
        conn.execute(
            "INSERT INTO webcat_meta(k, v) VALUES(%s, %s) ON DUPLICATE KEY UPDATE v=VALUES(v)",
            ("built_ts", "200"),
        )

    fresh_db = webcat_acl._Db()
    fresh_db.start = lambda: None

    assert fresh_db.lookup_categories("traffic-fixture") == {"adult"}


def test_webcat_acl_refreshes_snapshot_lock_while_building(
    tmp_path, monkeypatch
) -> None:
    configure_test_mysql_env(tmp_path / "webcat-acl-lock-refresh")

    webcat_acl = _webcat_acl_module()
    snapshot_dir = tmp_path / "snapshot"
    monkeypatch.setenv("WEBFILTER_SNAPSHOT_DIR", str(snapshot_dir))
    db = webcat_acl._Db()

    class FakeCursor:
        def __init__(self) -> None:
            self.calls = 0

        def execute(self, *_args, **_kwargs) -> None:
            return None

        def fetchmany(self, _size):
            self.calls += 1
            if self.calls == 1:
                return [("a.example", "adult")] * 2
            if self.calls == 2:
                return [("b.example", "adult")] * 2
            return []

        def close(self) -> None:
            return None

    class FakeNative:
        def cursor(self):
            return FakeCursor()

    class FakeConn:
        native = FakeNative()

        def execute(self, sql, _params=None):
            class Result:
                def fetchone(self):
                    return ("123",)

            return Result()

        def commit(self) -> None:
            return None

        def rollback(self) -> None:
            return None

        def close(self) -> None:
            return None

    refresh_calls = []
    monkeypatch.setattr(db, "_connect", FakeConn)
    monkeypatch.setattr(db, "_load_remote_built_ts", lambda: 123)
    monkeypatch.setattr(db, "_refresh_snapshot_lock", refresh_calls.append)

    assert db._build_snapshot_from_db(expected_built_ts=123) is True
    assert len(refresh_calls) >= 2
    assert all(fd is not None for fd in refresh_calls)


def test_webcat_acl_snapshot_lock_reclaims_stale_owner(tmp_path, monkeypatch) -> None:
    webcat_acl = _webcat_acl_module()
    monkeypatch.setenv("WEBFILTER_SNAPSHOT_DIR", str(tmp_path / "snapshot"))
    db = webcat_acl._Db()
    db._snapshot_lock_stale_seconds = 1.0
    db._snapshot_dir.mkdir(parents=True)
    db._snapshot_lock_path.write_text("stale")
    stale_time = time.time() - 2.0
    os.utime(db._snapshot_lock_path, (stale_time, stale_time))

    fd = db._acquire_snapshot_lock()

    assert fd is not None
    assert db._owns_snapshot_lock(fd)
    db._release_snapshot_lock(fd)
    assert not db._snapshot_lock_path.exists()


def test_webcat_acl_snapshot_lock_old_owner_cannot_refresh_or_release_new_lock(
    tmp_path, monkeypatch
) -> None:
    webcat_acl = _webcat_acl_module()
    monkeypatch.setenv("WEBFILTER_SNAPSHOT_DIR", str(tmp_path / "snapshot"))
    old_owner = webcat_acl._Db()
    new_owner = webcat_acl._Db()

    old_fd = old_owner._acquire_snapshot_lock()
    assert old_fd is not None
    old_owner._snapshot_lock_path.unlink()
    new_fd = new_owner._acquire_snapshot_lock()
    assert new_fd is not None
    new_mtime_ns = new_owner._snapshot_lock_path.stat().st_mtime_ns

    old_owner._refresh_snapshot_lock(old_fd)
    old_owner._release_snapshot_lock(old_fd)

    assert new_owner._snapshot_lock_path.stat().st_mtime_ns == new_mtime_ns
    assert new_owner._owns_snapshot_lock(new_fd)
    new_owner._release_snapshot_lock(new_fd)


def test_webcat_acl_rejects_corrupt_completed_snapshot_before_publication(
    tmp_path, monkeypatch
) -> None:
    webcat_acl = _webcat_acl_module()
    snapshot_dir = tmp_path / "snapshot"
    snapshot_dir.mkdir()
    snapshot_path = snapshot_dir / "webcat.sqlite"
    monkeypatch.setenv("WEBFILTER_SNAPSHOT_DIR", str(snapshot_dir))

    with webcat_acl.sqlite3.connect(snapshot_path) as conn:
        conn.execute(
            "CREATE TABLE domains (domain TEXT PRIMARY KEY, categories TEXT NOT NULL)"
        )
        conn.execute("CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)")
        conn.execute("INSERT INTO meta VALUES('built_ts', '100')")
        conn.execute("INSERT INTO meta VALUES('row_count', '0')")
    known_good = snapshot_path.read_bytes()

    class FakeCursor:
        def execute(self, *_args, **_kwargs) -> None:
            return None

        def fetchmany(self, _size):
            return []

        def close(self) -> None:
            return None

    class FakeRemote:
        native = type("Native", (), {"cursor": lambda self: FakeCursor()})()

        def execute(self, *_args, **_kwargs):
            return type("Result", (), {"fetchone": lambda self: ("200",)})()

        def commit(self) -> None:
            return None

        def rollback(self) -> None:
            return None

        def close(self) -> None:
            return None

    real_connect = webcat_acl.sqlite3.connect

    class CorruptOnClose:
        def __init__(self, conn, path) -> None:
            self._conn = conn
            self._path = path

        def __getattr__(self, name):
            return getattr(self._conn, name)

        def close(self) -> None:
            self._conn.close()
            self._path.write_bytes(b"not a sqlite database")

    def corrupting_connect(database, *args, **kwargs):
        conn = real_connect(database, *args, **kwargs)
        path = Path(database) if isinstance(database, (str, Path)) else None
        if path is not None and ".tmp-" in path.name:
            return CorruptOnClose(conn, path)
        return conn

    db = webcat_acl._Db()
    monkeypatch.setattr(db, "_connect", FakeRemote)
    monkeypatch.setattr(webcat_acl.sqlite3, "connect", corrupting_connect)

    assert db._build_snapshot_from_db(expected_built_ts=200) is False
    assert snapshot_path.read_bytes() == known_good
    assert not list(snapshot_dir.glob("webcat.sqlite.tmp-*"))


def test_webcat_acl_snapshot_metadata_and_domains_share_mysql_snapshot(
    tmp_path, monkeypatch
) -> None:
    webcat_acl = _webcat_acl_module()
    snapshot_dir = tmp_path / "snapshot"
    monkeypatch.setenv("WEBFILTER_SNAPSHOT_DIR", str(snapshot_dir))

    class FakeCursor:
        def __init__(self, conn) -> None:
            self.conn = conn
            self.fetched = False

        def execute(self, *_args, **_kwargs) -> None:
            assert self.conn.snapshot_generation is not None
            # Simulate a concurrent atomic table publication after the SELECT
            # starts. A consistent snapshot must retain generation 100.
            self.conn.live_generation = 200

        def fetchmany(self, _size):
            if self.fetched:
                return []
            self.fetched = True
            generation = self.conn.snapshot_generation or self.conn.live_generation
            return (
                [("old.example", "adult")]
                if generation == 100
                else [("new.example", "games")]
            )

        def close(self) -> None:
            return None

    class FakeNative:
        def __init__(self, conn) -> None:
            self.conn = conn

        def cursor(self):
            return FakeCursor(self.conn)

    class FakeConn:
        def __init__(self) -> None:
            self.live_generation = 100
            self.snapshot_generation = None
            self.native = FakeNative(self)
            self.closed = False

        def execute(self, sql, _params=None):
            if sql.startswith("START TRANSACTION"):
                self.snapshot_generation = self.live_generation

                class EmptyResult:
                    pass

                return EmptyResult()

            assert "webcat_meta" in sql
            generation = self.snapshot_generation or self.live_generation

            class Result:
                def fetchone(self):
                    return (str(generation),)

            return Result()

        def commit(self) -> None:
            self.snapshot_generation = None

        def rollback(self) -> None:
            self.snapshot_generation = None

        def close(self) -> None:
            self.closed = True

    db = webcat_acl._Db()
    conn = FakeConn()
    monkeypatch.setattr(db, "_connect", lambda: conn)

    assert db._build_snapshot_from_db(expected_built_ts=100) is True
    assert conn.closed is True
    assert db._local_snapshot_built_ts == 100
    assert db._lookup_categories_from_snapshot("old.example") == {"adult"}
    assert db._lookup_categories_from_snapshot("new.example") == set()


def test_webcat_acl_close_interrupts_long_refresh_wait_and_supports_restart(
    monkeypatch,
) -> None:
    webcat_acl = _webcat_acl_module()
    db = webcat_acl._Db()
    db._snapshot_refresh_seconds = 3600.0
    monkeypatch.setattr(db, "_load_snapshot_from_disk", lambda **_kwargs: False)
    monkeypatch.setattr(db, "_ensure_snapshot", lambda **_kwargs: False)

    db.start()
    first_thread = db._snapshot_thread
    db.start()

    assert first_thread is not None
    assert db._snapshot_thread is first_thread
    assert db.close(timeout=1.0) is True
    assert first_thread.is_alive() is False
    assert db.close(timeout=0.0) is True

    db.start()
    second_thread = db._snapshot_thread
    assert second_thread is not None
    assert second_thread is not first_thread
    assert db.close(timeout=1.0) is True


def test_webcat_acl_close_is_bounded_and_worker_owns_connection_cleanup(
    monkeypatch,
) -> None:
    webcat_acl = _webcat_acl_module()
    entered = webcat_acl.threading.Event()
    release = webcat_acl.threading.Event()

    class FakeConn:
        def __init__(self) -> None:
            self.closed = 0

        def close(self) -> None:
            self.closed += 1

    remote_conn = FakeConn()
    local_conn = FakeConn()
    db = webcat_acl._Db()
    db._snapshot_refresh_seconds = 0.0
    monkeypatch.setattr(db, "_load_snapshot_from_disk", lambda **_kwargs: False)
    monkeypatch.setattr(db, "_ensure_snapshot", lambda **_kwargs: False)

    def blocked_metadata() -> int:
        db._conn = remote_conn
        with db._snapshot_state_lock:
            db._local_conn = local_conn
        entered.set()
        assert release.wait(timeout=5.0)
        return 0

    monkeypatch.setattr(db, "_load_remote_built_ts", blocked_metadata)
    db.start()
    assert entered.wait(timeout=1.0)

    assert db.close(timeout=0.0) is False
    assert remote_conn.closed == 0
    assert local_conn.closed == 0

    release.set()
    assert db.close(timeout=1.0) is True
    assert remote_conn.closed == 1
    assert local_conn.closed == 1
    assert db._conn is None
    assert db._local_conn is None


def test_webcat_acl_start_failure_rolls_back_for_retry(monkeypatch) -> None:
    webcat_acl = _webcat_acl_module()

    class FakeConn:
        def __init__(self) -> None:
            self.closed = 0

        def close(self) -> None:
            self.closed += 1

    db = webcat_acl._Db()
    remote_conn = FakeConn()
    local_conn = FakeConn()
    db._conn = remote_conn
    db._local_conn = local_conn
    monkeypatch.setattr(db, "_load_snapshot_from_disk", lambda **_kwargs: False)
    monkeypatch.setattr(db, "_ensure_snapshot", lambda **_kwargs: False)
    real_thread = webcat_acl.threading.Thread

    class FailingThread:
        def __init__(self, **_kwargs) -> None:
            pass

        def start(self) -> None:
            msg = "thread unavailable"
            raise RuntimeError(msg)

    monkeypatch.setattr(webcat_acl.threading, "Thread", FailingThread)
    with pytest.raises(RuntimeError, match="thread unavailable"):
        db.start()
    assert db._snapshot_started is False
    assert db._snapshot_thread is None
    assert remote_conn.closed == 1
    assert local_conn.closed == 1

    monkeypatch.setattr(webcat_acl.threading, "Thread", real_thread)
    db.start()
    assert db.close(timeout=1.0) is True


@pytest.mark.parametrize("stdin", ["", "example.com adult\n"])
def test_webcat_acl_main_closes_resources_on_normal_and_exceptional_exit(
    monkeypatch, stdin
) -> None:
    webcat_acl = _webcat_acl_module()
    closed: list[str] = []

    class FakeDb:
        def lookup_categories(self, _domain):
            msg = "lookup failed"
            raise RuntimeError(msg)

        def close(self) -> bool:
            closed.append("db")
            return True

    class FakeLogDb:
        def __init__(self, **_kwargs) -> None:
            pass

        def start(self) -> None:
            pass

        def close(self) -> bool:
            closed.append("log")
            return True

    monkeypatch.setattr(webcat_acl, "_Db", FakeDb)
    monkeypatch.setattr(webcat_acl, "_BlockedLogDb", FakeLogDb)
    monkeypatch.setattr(webcat_acl.sys, "stdin", io.StringIO(stdin))

    if stdin:
        with pytest.raises(RuntimeError, match="lookup failed"):
            webcat_acl.main([])
    else:
        assert webcat_acl.main([]) == 0
    assert closed == ["db", "log"]


def test_webcat_acl_normalizes_explicit_proxy_uri_host() -> None:
    webcat_acl = _webcat_acl_module()

    assert (
        webcat_acl._norm_domain("http://traffic-fixture:8080/live.js")
        == "traffic-fixture"
    )
    assert webcat_acl._norm_domain("traffic-fixture:8080") == "traffic-fixture"


def test_webcat_acl_prefers_uri_host_over_dst_field() -> None:
    webcat_acl = _webcat_acl_module()

    channel, src_ip, domain, url, category = webcat_acl._parse_line(
        "7 172.18.0.4 93.184.216.34 http://traffic-fixture:8080/live.js malware",
    )

    assert channel == "7"
    assert src_ip == "172.18.0.4"
    assert domain == "93.184.216.34"
    assert webcat_acl._norm_domain(url) == "traffic-fixture"
    assert category == "malware"


def test_webcat_acl_response_can_include_matched_category(capsys) -> None:
    webcat_acl = _webcat_acl_module()

    webcat_acl._write_response("7", True, message="category=adult")

    assert capsys.readouterr().out == "7 OK message=category=adult\n"


@pytest.mark.parametrize("env_value", ["", "not-an-int"])
def test_webcat_acl_ignores_invalid_log_max_rows_env_for_argparse_help(
    monkeypatch, capsys, env_value
) -> None:
    webcat_acl = _webcat_acl_module()
    monkeypatch.setenv("WEBFILTER_LOG_MAX_ROWS", env_value)

    try:
        webcat_acl.main(["--help"])
    except SystemExit as exc:
        assert exc.code == 0
    else:  # pragma: no cover - argparse --help should exit
        msg = "expected argparse --help to exit"
        raise AssertionError(msg)

    assert "--log-max-rows" in capsys.readouterr().out


def test_webcat_acl_discards_stale_remote_connection_after_lookup_error() -> None:
    webcat_acl = _webcat_acl_module()

    class BrokenConn:
        def __init__(self) -> None:
            self.closed = False

        def execute(self, *_args, **_kwargs) -> NoReturn:
            msg = "stale connection"
            raise RuntimeError(msg)

        def close(self) -> None:
            self.closed = True

    db = webcat_acl._Db()
    broken = BrokenConn()
    db._conn = broken

    assert db._lookup_categories_remote("example.com") == set()
    assert broken.closed is True
    assert db._conn is None


def test_webcat_acl_discards_stale_remote_connection_after_metadata_error() -> None:
    webcat_acl = _webcat_acl_module()

    class BrokenConn:
        def __init__(self) -> None:
            self.closed = False

        def execute(self, *_args, **_kwargs) -> NoReturn:
            msg = "stale connection"
            raise RuntimeError(msg)

        def close(self) -> None:
            self.closed = True

    db = webcat_acl._Db()
    broken = BrokenConn()
    db._conn = broken

    assert db._load_remote_built_ts() == 0
    assert broken.closed is True
    assert db._conn is None


def test_webcat_acl_clears_cached_remote_connection_after_metadata_lookup() -> None:
    webcat_acl = _webcat_acl_module()

    class Result:
        def fetchone(self):
            return ("123",)

    class CachedConn:
        def __init__(self) -> None:
            self.closed = False

        def execute(self, *_args, **_kwargs):
            return Result()

        def close(self) -> None:
            self.closed = True

    db = webcat_acl._Db()
    conn = CachedConn()
    db._conn = conn

    assert db._load_remote_built_ts() == 123
    assert conn.closed is True
    assert db._conn is None


def test_webcat_acl_clears_cached_remote_connection_after_category_lookup() -> None:
    webcat_acl = _webcat_acl_module()

    class Result:
        def fetchone(self):
            return ("adult|malware",)

    class CachedConn:
        def __init__(self) -> None:
            self.closed = False

        def execute(self, *_args, **_kwargs):
            return Result()

        def close(self) -> None:
            self.closed = True

    db = webcat_acl._Db()
    conn = CachedConn()
    db._conn = conn

    assert db._lookup_categories_remote("cdn.example.com") == {"adult", "malware"}
    assert conn.closed is True
    assert db._conn is None


def test_webcat_acl_clears_cached_remote_connection_after_snapshot_build(
    tmp_path, monkeypatch
) -> None:
    webcat_acl = _webcat_acl_module()
    snapshot_dir = tmp_path / "snapshot"
    monkeypatch.setenv("WEBFILTER_SNAPSHOT_DIR", str(snapshot_dir))

    class FakeCursor:
        def execute(self, *_args, **_kwargs) -> None:
            return None

        def fetchmany(self, _size):
            return []

        def close(self) -> None:
            return None

    class FakeNative:
        def cursor(self):
            return FakeCursor()

    class CachedConn:
        native = FakeNative()

        def __init__(self) -> None:
            self.closed = False

        def execute(self, sql, _params=None):
            class Result:
                def fetchone(self):
                    return ("123",)

            return Result()

        def commit(self) -> None:
            return None

        def rollback(self) -> None:
            return None

        def close(self) -> None:
            self.closed = True

    db = webcat_acl._Db()
    conn = CachedConn()
    db._conn = conn

    assert db._build_snapshot_from_db(expected_built_ts=123) is True
    assert conn.closed is True
    assert db._conn is None


def test_blocked_log_db_closes_connection_when_schema_init_fails(monkeypatch) -> None:
    _webcat_acl_module()

    closed: list[bool] = []

    class FakeConn:
        def execute(self, *_args, **_kwargs):
            msg = "ddl failed"
            raise RuntimeError(msg)

        def close(self):
            closed.append(True)

    monkeypatch.setattr(blocked_log_runtime, "connect", FakeConn)
    monkeypatch.setattr(
        schema_lifecycle,
        "runtime_schema_ready_for_lazy_store",
        lambda _conn: False,
    )

    db = blocked_log_runtime.BlockedLogDb(max_rows=10)

    assert db._connect() is None
    assert closed == [True]
    assert db._conn is None


def test_blocked_log_db_keeps_block_when_source_ip_unavailable(monkeypatch) -> None:
    _webcat_acl_module()

    db = blocked_log_runtime.BlockedLogDb(max_rows=10)
    monkeypatch.setattr(db, "_start_locked", lambda: None)
    monkeypatch.setattr(db, "_proxy_id", lambda: "default")

    db.insert(ts=123, src_ip="", url="http://blocked.example/", category="adult")

    assert db._queue.get_nowait() == (
        123,
        "unknown",
        "http://blocked.example/",
        "adult",
    )


def test_blocked_log_db_sanitizes_untrusted_log_fields(monkeypatch) -> None:
    _webcat_acl_module()

    db = blocked_log_runtime.BlockedLogDb(max_rows=10)
    monkeypatch.setattr(db, "_start_locked", lambda: None)
    monkeypatch.setattr(blocked_log_runtime, "_now", lambda: 999)

    db.insert(
        ts=-1,
        src_ip="not-an-ip\r\nX-Injected: yes",
        url="https://user:secret@example.test/path?token=clear&ok=1#fragment",
        category=" Adult<script> ",
    )

    ts, src_ip, url, category = db._queue.get_nowait()
    assert ts == 999
    assert src_ip == "unknown"
    assert "user:secret" not in url
    assert "token=clear" not in url
    assert "fragment" not in url
    assert url == "https://example.test/path?token=[redacted]&ok=1"
    assert category == "adultscript"


def test_blocked_log_db_sanitizes_url_edge_cases(monkeypatch) -> None:
    _webcat_acl_module()

    db = blocked_log_runtime.BlockedLogDb(max_rows=10)
    monkeypatch.setattr(db, "_start_locked", lambda: None)

    cases = [
        (
            "http://user:pass@[2001:db8::1]:8080/a?password=abc&x=1#f",
            "http://[2001:db8::1]:8080/a?password=[redacted]&x=1",
        ),
        (
            "http://[::1]/path?api_key=abc#frag",
            "http://[::1]/path?api_key=[redacted]",
        ),
        (
            "http://[::1:8080/path?token=abc#frag",
            "http://[::1:8080/path?token=[redacted]",
        ),
        (
            "http://example.test/path?access_token=&token",
            "http://example.test/path?access_token=[redacted]&token=[redacted]",
        ),
        (
            "http://example.test/path?token=abc;api_key=def&ok=1#frag",
            "http://example.test/path?token=[redacted];api_key=[redacted]&ok=1",
        ),
        (
            "not a url token=secret#frag",
            "not a url token=[redacted]",
        ),
        (
            "https://user:pass@[vbad]/path?token=abc#frag",
            "https://[vbad]/path?token=[redacted]",
        ),
    ]

    for raw_url, expected in cases:
        db.insert(ts=123, src_ip="192.0.2.10", url=raw_url, category="adult")
        assert db._queue.get_nowait()[2] == expected


def test_blocked_log_db_close_flushes_accepted_events_and_closes_connection(
    monkeypatch,
) -> None:
    _webcat_acl_module()

    flushed = []

    class FakeConn:
        def __init__(self) -> None:
            self.closed = 0

        def close(self) -> None:
            self.closed += 1

    conn = FakeConn()
    db = blocked_log_runtime.BlockedLogDb(max_rows=10)

    def fake_connect():
        db._conn = conn
        return conn

    monkeypatch.setattr(db, "_connect", fake_connect)
    monkeypatch.setattr(db, "_flush", lambda _conn, batch: flushed.extend(batch))

    db.insert(
        ts=123,
        src_ip="192.0.2.10",
        url="http://blocked.example/",
        category="adult",
    )

    assert db.close(timeout=1.0) is True
    assert flushed == [(123, "192.0.2.10", "http://blocked.example/", "adult")]
    assert conn.closed == 1
    assert db._conn is None
    assert db._writer_thread is not None
    assert db._writer_thread.is_alive() is False

    db.insert(
        ts=124,
        src_ip="192.0.2.11",
        url="http://late.example/",
        category="adult",
    )
    assert db._queue.empty()


def test_blocked_log_db_close_terminates_when_connection_unavailable(
    monkeypatch,
) -> None:
    webcat_acl = _webcat_acl_module()

    attempted = webcat_acl.threading.Event()
    db = blocked_log_runtime.BlockedLogDb(max_rows=10)
    db._batch_size = 1

    def unavailable():
        attempted.set()

    monkeypatch.setattr(db, "_connect", unavailable)
    db.insert(
        ts=123,
        src_ip="192.0.2.10",
        url="http://blocked.example/",
        category="adult",
    )

    assert attempted.wait(timeout=1.0)
    assert db.close(timeout=1.0) is True
    assert db._writer_thread is not None
    assert db._writer_thread.is_alive() is False


def test_blocked_log_db_close_has_bounded_join_and_writer_owns_connection_close(
    monkeypatch,
) -> None:
    webcat_acl = _webcat_acl_module()

    entered = webcat_acl.threading.Event()
    release = webcat_acl.threading.Event()

    class FakeConn:
        def __init__(self) -> None:
            self.closed = 0

        def close(self) -> None:
            self.closed += 1

    conn = FakeConn()
    db = blocked_log_runtime.BlockedLogDb(max_rows=10)
    db._batch_size = 1

    def fake_connect():
        db._conn = conn
        return conn

    def blocked_flush(_conn, _batch) -> None:
        entered.set()
        assert release.wait(timeout=5.0)

    monkeypatch.setattr(db, "_connect", fake_connect)
    monkeypatch.setattr(db, "_flush", blocked_flush)
    db.insert(
        ts=123,
        src_ip="192.0.2.10",
        url="http://blocked.example/",
        category="adult",
    )
    assert entered.wait(timeout=1.0)

    assert db.close(timeout=0.0) is False
    assert conn.closed == 0

    release.set()
    assert db.close(timeout=1.0) is True
    assert conn.closed == 1


def test_blocked_log_db_preserves_batch_when_connection_unavailable(
    monkeypatch,
) -> None:
    _webcat_acl_module()

    db = blocked_log_runtime.BlockedLogDb(max_rows=10)
    batch = [(123, "192.0.2.10", "http://blocked.example/", "adult")]
    monkeypatch.setattr(db, "_connect", lambda: None)

    conn, flushed = db._flush_batch_if_possible(None, batch)

    assert conn is None
    assert flushed is False
    assert batch == [(123, "192.0.2.10", "http://blocked.example/", "adult")]


def test_blocked_log_db_preserves_batch_after_flush_error() -> None:
    _webcat_acl_module()

    closed: list[bool] = []
    rolled_back: list[bool] = []

    class FakeConn:
        def rollback(self) -> None:
            rolled_back.append(True)

        def close(self) -> None:
            closed.append(True)

    class BrokenBlockedLogDb(blocked_log_runtime.BlockedLogDb):
        def _flush(self, conn, batch) -> None:
            msg = "insert failed"
            raise RuntimeError(msg)

    db = BrokenBlockedLogDb(max_rows=10)
    batch = [(123, "192.0.2.10", "http://blocked.example/", "adult")]
    conn = FakeConn()
    db._conn = conn

    conn, flushed = db._flush_batch_if_possible(conn, batch)

    assert conn is None
    assert flushed is False
    assert db._conn is None
    assert rolled_back == [True]
    assert closed == [True]
    assert batch == [(123, "192.0.2.10", "http://blocked.example/", "adult")]


def test_blocked_log_db_does_not_retry_committed_batch_after_prune_error(
    monkeypatch,
) -> None:
    _webcat_acl_module()

    class FakeConn:
        def __init__(self) -> None:
            self.commits = 0
            self.rollbacks = 0

        def executemany(self, *_args, **_kwargs) -> None:
            pass

        def commit(self) -> None:
            self.commits += 1

        def rollback(self) -> None:
            self.rollbacks += 1

    def fake_guarded_rows(_conn, _proxy_id, rows, row_factory, **_kwargs):
        return type(
            "Guarded",
            (),
            {
                "proxy_id": "default",
                "rows": tuple(row_factory("default", row) for row in rows),
            },
        )()

    def fail_prune(*_args, **_kwargs) -> NoReturn:
        msg = "prune failed after insert commit"
        raise RuntimeError(msg)

    monkeypatch.setattr(blocked_log_runtime, "guarded_proxy_rows", fake_guarded_rows)
    db = blocked_log_runtime.BlockedLogDb(max_rows=10)
    db._inserts = 999
    monkeypatch.setattr(db, "_prune_old_rows", fail_prune)
    conn = FakeConn()
    batch = [(123, "192.0.2.10", "http://blocked.example/", "adult")]

    returned_conn, flushed = db._flush_batch_if_possible(conn, batch)

    assert returned_conn is conn
    assert flushed is True
    assert conn.commits == 1
    assert conn.rollbacks == 0


def test_blocked_log_db_uses_proxy_write_guard_canonical_proxy(monkeypatch) -> None:
    _webcat_acl_module()

    class Result:
        rowcount = 1

    class FakeConn:
        def __init__(self) -> None:
            self.executed = []
            self.commits = 0

        def executemany(self, sql, params):
            self.executed.append((" ".join(str(sql).split()), tuple(params)))
            return Result()

        def commit(self):
            self.commits += 1

    def fake_guarded_rows(_conn, proxy_id, rows, row_factory, **_kwargs):
        assert proxy_id == "edge-old"
        return type(
            "Guarded",
            (),
            {
                "proxy_id": "edge-new",
                "rows": tuple(row_factory("edge-new", row) for row in rows),
            },
        )()

    monkeypatch.setenv("PROXY_INSTANCE_ID", "edge-old")
    monkeypatch.setattr(blocked_log_runtime, "guarded_proxy_rows", fake_guarded_rows)
    db = blocked_log_runtime.BlockedLogDb(max_rows=10)
    conn = FakeConn()

    db._flush(conn, [(123, "192.0.2.10", "http://blocked.example/", "adult")])

    assert conn.executed[0][1][0][1] == "edge-new"


def test_blocked_log_db_drops_lifecycle_blocked_batches(monkeypatch) -> None:
    _webcat_acl_module()
    from services.proxy_write_guard import ProxyLifecycleWriteError  # type: ignore

    class FakeConn:
        def __init__(self) -> None:
            self.rollbacks = 0
            self.executemany_calls = 0

        def rollback(self) -> None:
            self.rollbacks += 1

        def executemany(self, *_args, **_kwargs) -> None:
            self.executemany_calls += 1

    def reject_rows(*_args, **_kwargs):
        msg = "Proxy 'edge-old' has been removed"
        raise ProxyLifecycleWriteError(msg)

    monkeypatch.setattr(blocked_log_runtime, "guarded_proxy_rows", reject_rows)
    db = blocked_log_runtime.BlockedLogDb(max_rows=10)
    conn = FakeConn()
    batch = [(123, "192.0.2.10", "http://blocked.example/", "adult")]

    returned_conn, flushed = db._flush_batch_if_possible(conn, batch)

    assert returned_conn is conn
    assert flushed is True
    assert conn.rollbacks == 1
    assert conn.executemany_calls == 0


def test_blocked_log_db_drops_reloaded_lifecycle_blocked_batches(monkeypatch) -> None:
    _webcat_acl_module()
    from services import proxy_write_guard  # type: ignore

    class FakeConn:
        def __init__(self) -> None:
            self.closed = 0
            self.rollbacks = 0
            self.executemany_calls = 0

        def rollback(self) -> None:
            self.rollbacks += 1

        def close(self) -> None:
            self.closed += 1

        def executemany(self, *_args, **_kwargs) -> None:
            self.executemany_calls += 1

    reloaded_guard = importlib.reload(proxy_write_guard)

    def reject_rows(*_args, **_kwargs):
        msg = "Proxy 'edge-old' has been removed"
        raise reloaded_guard.ProxyLifecycleWriteError(msg)

    monkeypatch.setattr(blocked_log_runtime, "guarded_proxy_rows", reject_rows)
    db = blocked_log_runtime.BlockedLogDb(max_rows=10)
    conn = FakeConn()
    batch = [(123, "192.0.2.10", "http://blocked.example/", "adult")]

    returned_conn, flushed = db._flush_batch_if_possible(conn, batch)

    assert returned_conn is conn
    assert flushed is True
    assert conn.rollbacks == 1
    assert conn.closed == 0
    assert conn.executemany_calls == 0


def test_blocked_log_prune_uses_bounded_ordered_delete(monkeypatch) -> None:
    _webcat_acl_module()

    class Result:
        def __init__(self, rows=(), rowcount=0) -> None:
            self._rows = list(rows)
            self.rowcount = rowcount

        def fetchall(self):
            return self._rows

    class FakeConn:
        def __init__(self) -> None:
            self.executed = []
            self.commits = 0

        def execute(self, sql, params=None):
            normalized = " ".join(str(sql).split())
            self.executed.append((normalized, tuple(params or ())))
            if normalized.startswith("SELECT ts, id"):
                return Result(rows=[(300, 3), (200, 2), (100, 1)])
            if normalized.startswith("DELETE FROM"):
                return Result(rowcount=1)
            return Result()

        def executemany(self, sql, params):
            self.executed.append((" ".join(str(sql).split()), tuple(params)))
            return Result(rowcount=len(params))

        def commit(self):
            self.commits += 1

    monkeypatch.setenv("WEBFILTER_LOG_PRUNE_CHUNK_SIZE", "2")
    monkeypatch.setenv("WEBFILTER_LOG_PRUNE_MAX_ROWS", "2")
    db = blocked_log_runtime.BlockedLogDb(max_rows=3)
    conn = FakeConn()

    db._prune_old_rows(conn, "webfilter_blocked_log", "edge-a")

    delete_sql, delete_params = next(
        (sql, params) for sql, params in conn.executed if sql.startswith("DELETE FROM")
    )
    assert "ORDER BY ts ASC, id ASC LIMIT" in delete_sql
    assert "NOT IN" not in delete_sql
    assert delete_params == ("edge-a", 100, 100, 1, 2)
    assert conn.commits == 1


def test_webcat_helper_closes_blocked_log_writer_at_eof(monkeypatch) -> None:
    webcat_acl = _webcat_acl_module()

    lifecycle = []
    inserted = []

    class FakeDb:
        def lookup_categories(self, domain):
            assert domain == "blocked.example"
            return {"adult"}

    class FakeLogDb:
        def __init__(self, *, max_rows) -> None:
            assert max_rows == 5000

        def start(self) -> None:
            lifecycle.append("start")

        def insert(self, **kwargs) -> None:
            inserted.append(kwargs)

        def close(self) -> bool:
            lifecycle.append("close")
            return True

    outputs = []
    monkeypatch.setattr(webcat_acl, "_Db", FakeDb)
    monkeypatch.setattr(webcat_acl, "_BlockedLogDb", FakeLogDb)
    monkeypatch.setattr(
        webcat_acl.sys,
        "stdin",
        [("192.0.2.10 blocked.example http://blocked.example/path adult\n")],
    )
    monkeypatch.setattr(webcat_acl.sys.stdout, "write", outputs.append)
    monkeypatch.setattr(webcat_acl.sys.stdout, "flush", lambda: None)

    assert webcat_acl.main([]) == 0
    assert lifecycle == ["start", "close"]
    assert len(inserted) == 1
    assert inserted[0]["src_ip"] == "192.0.2.10"
    assert inserted[0]["url"] == "http://blocked.example/path"
    assert inserted[0]["category"] == "adult"
    assert outputs == ["OK message=category=adult\n"]


def test_webfilter_store_list_blocked_log_clamps_orders_and_redacts(
    monkeypatch,
) -> None:
    from services import webfilter_store  # type: ignore

    class Result:
        def fetchall(self):
            return [
                (
                    123,
                    "192.0.2.10",
                    "https://user:secret@example.test/path?access_token=&token#fragment",
                    "adult",
                ),
            ]

    class FakeConn:
        def __init__(self) -> None:
            self.calls = []

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def execute(self, sql, params=None):
            self.calls.append((" ".join(str(sql).split()), tuple(params or ())))
            return Result()

    conn = FakeConn()
    store = webfilter_store.WebFilterStore()
    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "_connect", lambda: conn)
    monkeypatch.setattr(webfilter_store, "get_proxy_id", lambda: "edge-a")

    rows = store.list_blocked_log(limit=999999)

    assert "ORDER BY ts DESC, id DESC LIMIT" in conn.calls[0][0]
    assert conn.calls[0][1] == ("edge-a", 1000)
    assert (
        rows[0]["url"]
        == "https://example.test/path?access_token=[redacted]&token=[redacted]"
    )
