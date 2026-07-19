import os
import pathlib
import sys
from typing import NoReturn

from .mysql_test_utils import configure_test_mysql_env


def _add_web_to_path() -> None:
    web_dir = pathlib.Path(os.path.join(pathlib.Path(__file__).parent, "..")).resolve()
    if web_dir not in sys.path:
        sys.path.insert(0, web_dir)


def _webcat_acl_module():
    _add_web_to_path()
    from tools import webcat_acl  # type: ignore

    return webcat_acl


def test_webcat_acl_uses_local_snapshot_for_parent_domain_lookups(
    tmp_path, monkeypatch
) -> None:
    _add_web_to_path()
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
    _add_web_to_path()
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
    _add_web_to_path()
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

        def close(self) -> None:
            return None

    refresh_calls = []
    monkeypatch.setattr(db, "_connect", FakeConn)
    monkeypatch.setattr(db, "_load_remote_built_ts", lambda: 123)
    monkeypatch.setattr(db, "_refresh_snapshot_lock", refresh_calls.append)

    assert db._build_snapshot_from_db(expected_built_ts=123) is True
    assert len(refresh_calls) >= 2
    assert all(fd is not None for fd in refresh_calls)


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


def test_blocked_log_db_closes_connection_when_schema_init_fails(monkeypatch) -> None:
    webcat_acl = _webcat_acl_module()

    closed: list[bool] = []

    class FakeConn:
        def execute(self, *_args, **_kwargs):
            msg = "ddl failed"
            raise RuntimeError(msg)

        def close(self):
            closed.append(True)

    monkeypatch.setattr(webcat_acl, "connect", FakeConn)

    db = webcat_acl._BlockedLogDb(max_rows=10)

    assert db._connect() is None
    assert closed == [True]
    assert db._conn is None


def test_blocked_log_db_keeps_block_when_source_ip_unavailable(monkeypatch) -> None:
    webcat_acl = _webcat_acl_module()

    db = webcat_acl._BlockedLogDb(max_rows=10)
    monkeypatch.setattr(db, "start", lambda: None)
    monkeypatch.setattr(db, "_proxy_id", lambda: "default")

    db.insert(ts=123, src_ip="", url="http://blocked.example/", category="adult")

    assert db._queue.get_nowait() == (
        123,
        "default",
        "unknown",
        "http://blocked.example/",
        "adult",
    )


def test_blocked_log_db_preserves_batch_when_connection_unavailable(
    monkeypatch,
) -> None:
    webcat_acl = _webcat_acl_module()

    db = webcat_acl._BlockedLogDb(max_rows=10)
    batch = [(123, "default", "192.0.2.10", "http://blocked.example/", "adult")]
    monkeypatch.setattr(db, "_connect", lambda: None)

    conn, flushed = db._flush_batch_if_possible(None, batch)

    assert conn is None
    assert flushed is False
    assert batch == [(123, "default", "192.0.2.10", "http://blocked.example/", "adult")]


def test_blocked_log_db_preserves_batch_after_flush_error() -> None:
    webcat_acl = _webcat_acl_module()

    closed: list[bool] = []
    rolled_back: list[bool] = []

    class FakeConn:
        def rollback(self) -> None:
            rolled_back.append(True)

        def close(self) -> None:
            closed.append(True)

    class BrokenBlockedLogDb(webcat_acl._BlockedLogDb):
        def _flush(self, conn, batch) -> None:
            msg = "insert failed"
            raise RuntimeError(msg)

    db = BrokenBlockedLogDb(max_rows=10)
    batch = [(123, "default", "192.0.2.10", "http://blocked.example/", "adult")]
    conn = FakeConn()
    db._conn = conn

    conn, flushed = db._flush_batch_if_possible(conn, batch)

    assert conn is None
    assert flushed is False
    assert db._conn is None
    assert rolled_back == [True]
    assert closed == [True]
    assert batch == [(123, "default", "192.0.2.10", "http://blocked.example/", "adult")]


def test_blocked_log_prune_uses_bounded_ordered_delete(monkeypatch) -> None:
    webcat_acl = _webcat_acl_module()

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
    db = webcat_acl._BlockedLogDb(max_rows=3)
    conn = FakeConn()

    db._prune_old_rows(conn, "webfilter_blocked_log")

    delete_sql, delete_params = next(
        (sql, params) for sql, params in conn.executed if sql.startswith("DELETE FROM")
    )
    assert "ORDER BY ts ASC, id ASC LIMIT" in delete_sql
    assert "NOT IN" not in delete_sql
    assert delete_params == (100, 100, 1, 2)
    assert conn.commits == 1
