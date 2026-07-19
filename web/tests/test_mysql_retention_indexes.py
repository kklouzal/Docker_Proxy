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


def test_safe_browsing_cache_expiry_indexes_bootstrap():
    conn = _FakeConn()

    SafeBrowsingStore.init_schema(conn)

    sql = _joined(conn)
    assert "KEY idx_safe_browsing_cache_expiry(expires_ts)" in sql
    assert "KEY idx_safe_browsing_negative_expiry(expires_ts)" in sql
    assert "ALTER TABLE safe_browsing_hash_prefixes ADD COLUMN generation BIGINT NOT NULL DEFAULT 0" in sql
    assert "idx_safe_browsing_list_generation (list_name, generation)" in sql
    assert "ALTER TABLE safe_browsing_full_hash_cache ADD INDEX idx_safe_browsing_cache_expiry (expires_ts)" in sql
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
    assert "KEY idx_diagnostic_policy_tags_ts_only(ts, proxy_id, request_id)" in sql
    assert "ALTER TABLE diagnostic_policy_tags ADD INDEX idx_diagnostic_policy_tags_ts_only (ts, proxy_id, request_id)" in sql


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


def test_control_plane_retention_index_manifest_matches_prune_queries():
    from services.control_plane_maintenance import CONTROL_PLANE_RETENTION_INDEXES

    expected = {
        "proxy_config_revisions": "idx_proxy_config_revisions_proxy_created_id (proxy_id, created_ts, id)",
        "certificate_bundle_revisions": "idx_certificate_bundle_revisions_created_id (created_ts, id)",
        "proxy_config_applications": "idx_proxy_config_applications_proxy_applied_id (proxy_id, applied_ts, id)",
        "proxy_certificate_applications": "idx_proxy_certificate_applications_proxy_applied_id (proxy_id, applied_ts, id)",
        "proxy_adblock_artifact_applications": "idx_proxy_adblock_artifact_apply_proxy_applied_id (proxy_id, applied_ts, id)",
        "proxy_operations": "idx_proxy_operations_proxy_updated_id (proxy_id, updated_ts, id)",
        "policy_requests": "idx_policy_requests_proxy_updated_id (proxy_id, updated_ts, id)",
        "policy_exceptions": "idx_policy_exceptions_proxy_updated_id (proxy_id, updated_ts, id)",
        "observability_maintenance_runs": "idx_observability_maintenance_runs_started_id (started_ts, id)",
    }

    for table, fragment in expected.items():
        ddl = "\n".join(
            index_ddl
            for _name, index_ddl in CONTROL_PLANE_RETENTION_INDEXES[table]
        )
        assert fragment in ddl
    policy_exception_ddl = "\n".join(
        index_ddl
        for _name, index_ddl in CONTROL_PLANE_RETENTION_INDEXES["policy_exceptions"]
    )
    assert (
        "idx_policy_exceptions_status_expires (status, expires_ts, id)"
        in policy_exception_ddl
    )


def test_operation_ledger_schema_bootstraps_bounded_progress_indexes(monkeypatch):
    from services.operation_ledger import OperationLedger

    conn = _FakeConn()
    ledger = OperationLedger()
    monkeypatch.setattr(ledger, "_connect", lambda: conn)
    monkeypatch.setattr(ledger, "_column_exists", lambda *_args: True)
    monkeypatch.setattr("services.operation_ledger.time.time", lambda: 123)

    ledger.init_db()

    sql = _joined(conn)
    assert "KEY idx_proxy_operations_proxy_status (proxy_id, status, created_ts)" in sql
    assert (
        "ALTER TABLE proxy_operations ADD INDEX "
        "idx_proxy_operations_proxy_status_created_id "
        "(proxy_id, status, created_ts, id)"
    ) in sql
    assert (
        "ALTER TABLE proxy_operations ADD INDEX "
        "idx_proxy_operations_proxy_started_id (proxy_id, started_ts, id)"
    ) in sql
    assert (
        "ALTER TABLE proxy_operations ADD INDEX "
        "idx_proxy_operations_proxy_updated_id (proxy_id, updated_ts, id)"
    ) in sql
