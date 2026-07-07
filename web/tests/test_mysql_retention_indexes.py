from __future__ import annotations

import pathlib
import sys
from contextlib import contextmanager

WEB_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(WEB_DIR) not in sys.path:
    sys.path.insert(0, str(WEB_DIR))

from services.adblock_store import AdblockStore  # noqa: E402
from services.diagnostic_store import DiagnosticStore  # noqa: E402
from services.live_stats import LiveStatsStore  # noqa: E402
from services.safe_browsing_v5 import SafeBrowsingStore  # noqa: E402
from services.webfilter_store import WebFilterStore  # noqa: E402
from tools.webcat_acl import _BlockedLogDb  # noqa: E402


class _Result:
    def __init__(self, row=None):
        self._row = row

    def fetchone(self):
        return self._row

    def fetchall(self):
        return []


class _FakeConn:
    def __init__(self):
        self.sql: list[str] = []
        self.params: list[object] = []

    def execute(self, sql: str, params=None):
        self.sql.append(" ".join(sql.split()))
        self.params.append(params)
        upper = sql.upper()
        if "GET_LOCK" in upper:
            return _Result({"acquired": 1})
        if "RELEASE_LOCK" in upper:
            return _Result({"released": 1})
        if "INFORMATION_SCHEMA.STATISTICS" in upper:
            return _Result(None)
        if "SELECT V FROM" in upper or "SELECT 1 FROM" in upper:
            return _Result(None)
        return _Result(None)

    def executemany(self, sql: str, params=None):
        self.sql.append(" ".join(sql.split()))
        self.params.append(params)
        return _Result(None)

    def commit(self):
        return None

    def close(self):
        return None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None


@contextmanager
def _fake_connect(conn: _FakeConn):
    yield conn


def _joined(conn: _FakeConn) -> str:
    return "\n".join(conn.sql)


def test_safe_browsing_negative_cache_expiry_index_bootstrap():
    conn = _FakeConn()

    SafeBrowsingStore.init_schema(conn)

    sql = _joined(conn)
    assert "KEY idx_safe_browsing_negative_expiry(expires_ts)" in sql
    assert "ALTER TABLE safe_browsing_negative_cache ADD INDEX idx_safe_browsing_negative_expiry (expires_ts)" in sql


def test_adblock_retention_indexes_bootstrap():
    conn = _FakeConn()
    store = AdblockStore(lists_dir="/tmp/docker-proxy-test-adblock-lists")

    store._init_schema(conn)

    sql = _joined(conn)
    assert "KEY idx_adblock_counts_day (day)" in sql
    assert "KEY idx_adblock_events_ts_id (ts, id)" in sql
    assert "ALTER TABLE adblock_counts ADD INDEX idx_adblock_counts_day (day)" in sql
    assert "ALTER TABLE adblock_events ADD INDEX idx_adblock_events_ts_id (ts, id)" in sql
    for key in (
        "cache_flush_requested",
        "cache_last_flush",
        "cache_current_size",
        "cicap_access_pos",
        "cicap_access_inode",
    ):
        assert ("default", key) in conn.params


def test_diagnostic_global_retention_indexes_bootstrap(monkeypatch):
    conn = _FakeConn()
    store = DiagnosticStore()
    monkeypatch.setattr(store, "_connect", lambda: _fake_connect(conn))

    store.init_db()

    sql = _joined(conn)
    assert "KEY idx_diagnostic_requests_ts_id (ts, id)" in sql
    assert "KEY idx_diagnostic_icap_ts_id (ts, id)" in sql
    assert "ALTER TABLE diagnostic_requests ADD INDEX idx_diagnostic_requests_ts_id (ts, id)" in sql
    assert "ALTER TABLE diagnostic_icap_events ADD INDEX idx_diagnostic_icap_ts_id (ts, id)" in sql


def test_live_stats_global_last_seen_indexes_bootstrap(monkeypatch):
    conn = _FakeConn()
    store = LiveStatsStore()
    monkeypatch.setattr(store, "_connect", lambda: _fake_connect(conn))

    store.init_db()

    sql = _joined(conn)
    assert "KEY idx_live_stats_domains_last_seen (last_seen, domain)" in sql
    assert "KEY idx_live_stats_clients_last_seen (last_seen, ip)" in sql
    assert "KEY idx_live_stats_client_domains_last_seen (last_seen, ip, domain)" in sql
    assert "KEY idx_live_stats_client_domain_nocache_last_seen (last_seen, row_key)" in sql
    assert "ALTER TABLE live_stats_domains ADD INDEX idx_live_stats_domains_last_seen (last_seen, domain)" in sql
    assert "ALTER TABLE live_stats_clients ADD INDEX idx_live_stats_clients_last_seen (last_seen, ip)" in sql
    assert "ALTER TABLE live_stats_client_domains ADD INDEX idx_live_stats_client_domains_last_seen (last_seen, ip, domain)" in sql
    assert "ALTER TABLE live_stats_client_domain_nocache ADD INDEX idx_live_stats_client_domain_nocache_last_seen (last_seen, row_key)" in sql


def test_webfilter_blocked_log_retention_index_bootstrap():
    conn = _FakeConn()
    store = WebFilterStore()

    store._init_extra_schema(conn)

    sql = _joined(conn)
    assert "KEY idx_webfilter_blocked_log_ts_id (ts, id)" in sql
    assert "ALTER TABLE webfilter_blocked_log ADD INDEX idx_webfilter_blocked_log_ts_id (ts, id)" in sql


def test_webcat_acl_blocked_log_writer_retention_index_bootstrap():
    conn = _FakeConn()
    writer = _BlockedLogDb(max_rows=100)

    writer._ensure_index(
        conn,
        "webfilter_blocked_log",
        "idx_webfilter_blocked_log_ts_id",
        "ALTER TABLE webfilter_blocked_log ADD INDEX idx_webfilter_blocked_log_ts_id (ts, id)",
    )

    sql = _joined(conn)
    assert "ALTER TABLE webfilter_blocked_log ADD INDEX idx_webfilter_blocked_log_ts_id (ts, id)" in sql
