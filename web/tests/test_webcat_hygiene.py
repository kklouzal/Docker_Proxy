from __future__ import annotations

from services import webcat_hygiene
from services.db import CompatRow


class _Rows:
    def __init__(self, rows) -> None:
        self._rows = rows
        self.rowcount = 0

    def fetchall(self):
        return list(self._rows)


class _Connection:
    def __init__(self, tables) -> None:
        self.tables = list(tables)
        self.queries: list[tuple[str, tuple[object, ...]]] = []
        self.commits = 0

    def execute(self, sql, params=()):
        text = str(sql)
        compact = " ".join(text.split())
        params = tuple(params or ())
        self.queries.append((text, params))
        if "information_schema.TABLES" in compact:
            return _Rows(self.tables)
        return _Rows([])

    def commit(self) -> None:
        self.commits += 1


def _drop_queries(conn: _Connection) -> list[str]:
    return [query for query, _params in conn.queries if query.startswith("DROP TABLE")]


def test_list_webcat_build_tables_uses_valid_mysql_escape_literal() -> None:
    conn = _Connection(
        [
            ("webcat_domains_stage_111_1000",),
            ("webcat_domains",),
            ("webcat_domains_stage_111_1000_extra",),
        ],
    )

    tables = webcat_hygiene.list_webcat_build_tables(conn)

    assert tables == ["webcat_domains_stage_111_1000"]
    assert conn.queries == [
        (
            (
                "SELECT TABLE_NAME FROM information_schema.TABLES "
                "WHERE TABLE_SCHEMA = DATABASE() "
                "AND TABLE_NAME LIKE 'webcat\\\\_%' ESCAPE '\\\\'"
            ),
            (),
        ),
    ]


def test_list_webcat_build_tables_reads_application_compat_rows() -> None:
    conn = _Connection(
        [CompatRow(("TABLE_NAME",), ("webcat_domains_stage_111_1000",))],
    )

    tables = webcat_hygiene.list_webcat_build_tables(conn)

    assert tables == ["webcat_domains_stage_111_1000"]


def test_webcat_build_table_matching_is_strict() -> None:
    assert (
        webcat_hygiene.webcat_build_table_suffix(
            "webcat_domains_stage_123_456",
        )
        == "123_456"
    )
    assert (
        webcat_hygiene.webcat_build_table_suffix(
            "webcat_pairs_old_123_456",
        )
        == "123_456"
    )
    assert (
        webcat_hygiene.webcat_build_table_suffix("webcat_domain_stage_123_456") is None
    )
    assert webcat_hygiene.webcat_build_table_suffix("webcat_domains_stage_123") is None
    assert (
        webcat_hygiene.webcat_build_table_suffix("webcat_domains_stage_123_456_tmp")
        is None
    )
    assert webcat_hygiene.webcat_build_table_suffix("webcat_live_domains") is None


def test_cleanup_drops_only_strict_stale_tables_and_preserves_current_suffix() -> None:
    conn = _Connection(
        [
            {"TABLE_NAME": "webcat_domains_stage_111_1000"},
            {"TABLE_NAME": "webcat_pairs_old_111_1000"},
            {"TABLE_NAME": "webcat_meta_stage_222_4900"},
            {"TABLE_NAME": "webcat_aliases_stage_333_1000"},
            {"TABLE_NAME": "webcat_domains_stage_123"},
            {"TABLE_NAME": "webcat_domains"},
            {"TABLE_NAME": "other_webcat_domains_stage_111_1000"},
        ],
    )

    result = webcat_hygiene.cleanup_stale_webcat_build_tables(
        conn,
        current_suffix="333_1000",
        now_ts=5000,
        ttl_seconds=3600,
    )

    assert result.dropped_tables == (
        "webcat_domains_stage_111_1000",
        "webcat_pairs_old_111_1000",
    )
    assert result.discovered_tables == 4
    assert result.stale_tables == 2
    assert _drop_queries(conn) == [
        "DROP TABLE IF EXISTS `webcat_domains_stage_111_1000`",
        "DROP TABLE IF EXISTS `webcat_pairs_old_111_1000`",
    ]
    assert conn.commits == 1


def test_cleanup_noop_for_missing_or_non_stale_tables() -> None:
    conn = _Connection(
        [
            ("webcat_domains_stage_111_4900",),
            ("webcat_pairs_old_111_5000",),
            ("webcat_meta_stage_222_1000_extra",),
        ],
    )

    result = webcat_hygiene.cleanup_stale_webcat_build_tables(
        conn,
        now_ts=5000,
        ttl_seconds=3600,
    )

    assert result.dropped_tables == ()
    assert result.discovered_tables == 2
    assert result.stale_tables == 0
    assert _drop_queries(conn) == []
    assert conn.commits == 0


def test_cleanup_can_be_disabled_by_negative_ttl(monkeypatch) -> None:
    conn = _Connection([("webcat_domains_stage_111_1000",)])
    monkeypatch.setenv("WEBCAT_STALE_STAGE_TTL_SECONDS", "-1")

    result = webcat_hygiene.cleanup_stale_webcat_build_tables(conn, now_ts=5000)

    assert result.detail == "disabled"
    assert result.dropped_tables == ()
    assert conn.queries == []
    assert conn.commits == 0
