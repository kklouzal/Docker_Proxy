from __future__ import annotations

import pathlib
import sys

WEB_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(WEB_DIR) not in sys.path:
    sys.path.insert(0, str(WEB_DIR))

from services.db import CompatRow  # noqa: E402
from services.ssl_errors_store import SslErrorsStore  # noqa: E402


class _Result:
    def __init__(self, row=None):
        self._row = row

    def fetchone(self):
        return self._row

    def fetchall(self):
        if self._row is None:
            return []
        if isinstance(self._row, list):
            return self._row
        return [self._row]


class _LookupConn:
    def __init__(self, rows):
        self.rows = list(rows)
        self.calls: list[tuple[str, object]] = []

    def execute(self, sql, params=None):
        self.calls.append((" ".join(sql.split()), params))
        row = self.rows.pop(0) if self.rows else None
        return _Result(row)


def test_ssl_context_lookup_uses_indexed_bounded_ranges(monkeypatch):
    monkeypatch.delenv("SSL_ERRORS_CONTEXT_LOOKUP_WINDOW_SECONDS", raising=False)
    monkeypatch.setattr("services.ssl_errors_store.get_proxy_id", lambda: "proxy-a")
    conn = _LookupConn(rows=[[("example.com", "", "", "", 1000, 7)], []])
    store = SslErrorsStore()

    assert store._lookup_domain_for_master_xaction(conn, "tx-1", 1000) == "example.com"

    assert len(conn.calls) == 2
    sql, params = conn.calls[0]
    assert "FROM diagnostic_requests FORCE INDEX (idx_diagnostic_requests_proxy_tx)" in sql
    assert "ts BETWEEN %s AND %s" in sql
    assert "ORDER BY ts DESC, id DESC" in sql
    assert params == ("proxy-a", "tx-1", 995, 1000)
    assert conn.calls[1][1] == ("proxy-a", "tx-1", 1000, 1005)


def test_ssl_context_lookup_widens_bounded_ranges_until_match(monkeypatch):
    monkeypatch.setenv("SSL_ERRORS_CONTEXT_LOOKUP_WINDOW_SECONDS", "20")
    monkeypatch.setattr("services.ssl_errors_store.get_proxy_id", lambda: "proxy-a")
    conn = _LookupConn(rows=[[], [], [("", "fallback.example", "", "", 1987, 9)], []])
    store = SslErrorsStore()

    assert store._lookup_domain_for_master_xaction(conn, "tx-2", 2000) == "fallback.example"

    assert len(conn.calls) == 4
    assert conn.calls[0][1] == ("proxy-a", "tx-2", 1995, 2000)
    assert conn.calls[1][1] == ("proxy-a", "tx-2", 2000, 2005)
    assert conn.calls[2][1] == ("proxy-a", "tx-2", 1980, 2000)
    assert conn.calls[3][1] == ("proxy-a", "tx-2", 2000, 2020)


def test_ssl_context_lookup_reads_mapping_row_values(monkeypatch):
    monkeypatch.delenv("SSL_ERRORS_CONTEXT_LOOKUP_WINDOW_SECONDS", raising=False)
    monkeypatch.setattr("services.ssl_errors_store.get_proxy_id", lambda: "proxy-a")
    conn = _LookupConn(
        rows=[
            [
                CompatRow(
                    ("domain", "sni", "host", "url", "ts", "id"),
                    ("mapped.example", "", "", "", 3000, 1),
                ),
            ],
            [],
        ],
    )
    store = SslErrorsStore()

    assert store._lookup_domain_for_master_xaction(conn, "tx-3", 3000) == "mapped.example"
