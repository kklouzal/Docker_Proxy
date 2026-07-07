from __future__ import annotations

import pathlib
import sys

WEB_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(WEB_DIR) not in sys.path:
    sys.path.insert(0, str(WEB_DIR))

from services.ssl_errors_store import SslErrorsStore
from services.db import CompatRow


class _Result:
    def __init__(self, row=None):
        self._row = row

    def fetchone(self):
        return self._row


class _LookupConn:
    def __init__(self, rows):
        self.rows = list(rows)
        self.calls: list[tuple[str, object]] = []

    def execute(self, sql, params=None):
        self.calls.append((" ".join(sql.split()), params))
        row = self.rows.pop(0) if self.rows else None
        return _Result(row)


def test_ssl_context_lookup_uses_indexed_bounded_derived_range(monkeypatch):
    monkeypatch.delenv("SSL_ERRORS_CONTEXT_LOOKUP_WINDOW_SECONDS", raising=False)
    monkeypatch.setattr("services.ssl_errors_store.get_proxy_id", lambda: "proxy-a")
    conn = _LookupConn(rows=[("example.com", "", "", "")])
    store = SslErrorsStore()

    assert store._lookup_domain_for_master_xaction(conn, "tx-1", 1000) == "example.com"

    assert len(conn.calls) == 1
    sql, params = conn.calls[0]
    assert "FROM ( SELECT id, ts, domain, sni, host, url FROM diagnostic_requests FORCE INDEX (idx_diagnostic_requests_proxy_tx)" in sql
    assert "ts BETWEEN %s AND %s" in sql
    assert "ORDER BY ABS(candidates.ts - %s) ASC, candidates.id DESC" in sql
    assert params == ("proxy-a", "tx-1", 995, 1005, 1000)


def test_ssl_context_lookup_widens_bounded_ranges_until_match(monkeypatch):
    monkeypatch.setenv("SSL_ERRORS_CONTEXT_LOOKUP_WINDOW_SECONDS", "20")
    monkeypatch.setattr("services.ssl_errors_store.get_proxy_id", lambda: "proxy-a")
    conn = _LookupConn(rows=[None, ("", "fallback.example", "", "")])
    store = SslErrorsStore()

    assert store._lookup_domain_for_master_xaction(conn, "tx-2", 2000) == "fallback.example"

    assert len(conn.calls) == 2
    assert conn.calls[0][1] == ("proxy-a", "tx-2", 1995, 2005, 2000)
    assert conn.calls[1][1] == ("proxy-a", "tx-2", 1980, 2020, 2000)


def test_ssl_context_lookup_reads_mapping_row_values(monkeypatch):
    monkeypatch.delenv("SSL_ERRORS_CONTEXT_LOOKUP_WINDOW_SECONDS", raising=False)
    monkeypatch.setattr("services.ssl_errors_store.get_proxy_id", lambda: "proxy-a")
    conn = _LookupConn(
        rows=[CompatRow(("domain", "sni", "host", "url"), ("mapped.example", "", "", ""))],
    )
    store = SslErrorsStore()

    assert store._lookup_domain_for_master_xaction(conn, "tx-3", 3000) == "mapped.example"
