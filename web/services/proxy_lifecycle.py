from __future__ import annotations

# ruff: noqa: S608
import hashlib
import os
from dataclasses import dataclass, field
from typing import Any, Literal

from services.bounded_delete import default_chunk_size, default_max_rows
from services.db import DATABASE_ERRORS, mysql_error_code, table_exists
from services.sql_identifiers import quote_mysql_identifier

LifecycleAction = Literal["rename", "remove"]


@dataclass(frozen=True)
class ProxyLifecycleTable:
    table: str
    proxy_column: str = "proxy_id"
    order_columns: tuple[str, ...] = ()
    remove: bool = True
    rename: bool = True
    owner_table: str = ""
    owner_pk: str = ""
    child_fk: str = ""
    note: str = ""

    @property
    def is_indirect_child(self) -> bool:
        return bool(self.owner_table and self.owner_pk and self.child_fk)


@dataclass(frozen=True)
class ProxyLifecycleStepResult:
    table: str
    action: LifecycleAction
    affected_rows: int = 0
    iterations: int = 0
    truncated: bool = False
    discovered: bool = False
    skipped: bool = False
    detail: str = ""


@dataclass(frozen=True)
class ProxyLifecycleRunResult:
    action: LifecycleAction
    proxy_id: str
    target_proxy_id: str = ""
    complete: bool = True
    affected_rows: int = 0
    iterations: int = 0
    table_counts: dict[str, int] = field(default_factory=dict)
    table_results: tuple[ProxyLifecycleStepResult, ...] = ()
    discovered_tables: tuple[str, ...] = ()
    truncated_tables: tuple[str, ...] = ()


class ProxyLifecycleIncompleteError(RuntimeError):
    def __init__(self, message: str, result: ProxyLifecycleRunResult) -> None:
        super().__init__(message)
        self.result = result


# Deterministic registry of every application-owned MySQL table known to carry
# proxy-scoped rows, plus child tables whose ownership is through a scoped parent.
# Information-schema discovery is still used as a safety net, but it is not the
# sole source of lifecycle coverage.
PROXY_LIFECYCLE_TABLES: tuple[ProxyLifecycleTable, ...] = (
    # PAC profile children must be deleted before pac_profiles on removal.
    ProxyLifecycleTable(
        "pac_direct_domains",
        remove=True,
        rename=False,
        owner_table="pac_profiles",
        owner_pk="id",
        child_fk="profile_id",
        note="owned through pac_profiles.id",
    ),
    ProxyLifecycleTable(
        "pac_direct_dst_nets",
        remove=True,
        rename=False,
        owner_table="pac_profiles",
        owner_pk="id",
        child_fk="profile_id",
        note="owned through pac_profiles.id",
    ),
    ProxyLifecycleTable("adblock_cache_stats", order_columns=("proxy_id", "k")),
    ProxyLifecycleTable("adblock_counts", order_columns=("proxy_id", "day", "list_key")),
    ProxyLifecycleTable("adblock_events", order_columns=("proxy_id", "ts", "id")),
    ProxyLifecycleTable("adblock_proxy_meta", order_columns=("proxy_id", "k")),
    ProxyLifecycleTable("audit_events", order_columns=("proxy_id", "ts", "id")),
    ProxyLifecycleTable("diagnostic_requests", order_columns=("proxy_id", "ts", "id")),
    ProxyLifecycleTable("diagnostic_policy_tags", order_columns=("proxy_id", "request_id", "tag")),
    ProxyLifecycleTable("diagnostic_icap_events", order_columns=("proxy_id", "ts", "id")),
    ProxyLifecycleTable("live_stats_domains", order_columns=("proxy_id", "domain")),
    ProxyLifecycleTable("live_stats_clients", order_columns=("proxy_id", "ip")),
    ProxyLifecycleTable("live_stats_client_domains", order_columns=("proxy_id", "ip", "domain")),
    ProxyLifecycleTable("live_stats_client_domain_nocache", order_columns=("proxy_id", "last_seen", "row_key")),
    ProxyLifecycleTable("observability_report_schedules", order_columns=("proxy_id", "updated_ts", "id")),
    ProxyLifecycleTable("pac_backup_proxies", order_columns=("proxy_id", "position", "id")),
    ProxyLifecycleTable("pac_proxy_chain_settings", order_columns=("proxy_id",)),
    ProxyLifecycleTable("pac_profiles", order_columns=("proxy_id", "id")),
    ProxyLifecycleTable("policy_requests", order_columns=("proxy_id", "updated_ts", "id")),
    ProxyLifecycleTable("policy_exceptions", order_columns=("proxy_id", "updated_ts", "id")),
    ProxyLifecycleTable("proxy_adblock_artifact_applications", order_columns=("proxy_id", "applied_ts", "id")),
    ProxyLifecycleTable("proxy_certificate_applications", order_columns=("proxy_id", "applied_ts", "id")),
    ProxyLifecycleTable("proxy_config_applications", order_columns=("proxy_id", "applied_ts", "id")),
    ProxyLifecycleTable("proxy_config_revisions", order_columns=("proxy_id", "created_ts", "id")),
    ProxyLifecycleTable("proxy_operations", order_columns=("proxy_id", "updated_ts", "id")),
    ProxyLifecycleTable("ssl_errors", order_columns=("proxy_id", "last_seen", "row_key")),
    ProxyLifecycleTable("sslfilter_domains", order_columns=("proxy_id", "policy", "domain")),
    ProxyLifecycleTable("sslfilter_src_nets", order_columns=("proxy_id", "policy", "cidr")),
    ProxyLifecycleTable("sslfilter_settings", order_columns=("proxy_id", "key")),
    ProxyLifecycleTable("ts_1s", order_columns=("proxy_id", "ts")),
    ProxyLifecycleTable("ts_1m", order_columns=("proxy_id", "ts")),
    ProxyLifecycleTable("ts_1h", order_columns=("proxy_id", "ts")),
    ProxyLifecycleTable("ts_1d", order_columns=("proxy_id", "ts")),
    ProxyLifecycleTable("ts_1w", order_columns=("proxy_id", "ts")),
    ProxyLifecycleTable("ts_1mo", order_columns=("proxy_id", "ts")),
    ProxyLifecycleTable("ts_1y", order_columns=("proxy_id", "ts")),
    ProxyLifecycleTable("webfilter_blocked_log", order_columns=("proxy_id", "ts", "id")),
    ProxyLifecycleTable("webfilter_settings", order_columns=("proxy_id", "k")),
    ProxyLifecycleTable("webfilter_whitelist", order_columns=("proxy_id", "pattern")),
)

_SPECIAL_TABLES = {"proxy_instances", "proxy_id_aliases", "proxy_lifecycle_tombstones"}


def lifecycle_chunk_size() -> int:
    raw = os.environ.get("MYSQL_PROXY_LIFECYCLE_CHUNK_SIZE")
    if raw is None or not raw.strip():
        return default_chunk_size()
    try:
        return max(1, min(10_000, int(raw.strip())))
    except Exception:
        return default_chunk_size()


def lifecycle_max_rows_per_table() -> int:
    raw = os.environ.get("MYSQL_PROXY_LIFECYCLE_MAX_ROWS_PER_TABLE")
    if raw is None or not raw.strip():
        return default_max_rows()
    try:
        return max(0, min(1_000_000, int(raw.strip())))
    except Exception:
        return default_max_rows()


def ensure_lifecycle_schema(conn: Any) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS proxy_lifecycle_tombstones (
            proxy_id VARCHAR(64) PRIMARY KEY,
            action VARCHAR(16) NOT NULL,
            target_proxy_id VARCHAR(64) NOT NULL DEFAULT '',
            detail VARCHAR(512) NOT NULL DEFAULT '',
            created_ts BIGINT NOT NULL,
            updated_ts BIGINT NOT NULL,
            KEY idx_proxy_lifecycle_tombstones_updated (updated_ts)
        )
        """,
    )


def _columns(conn: Any, table_name: str) -> set[str]:
    rows = conn.execute(
        """
        SELECT column_name AS column_name
        FROM information_schema.columns
        WHERE table_schema = DATABASE() AND table_name = %s
        """,
        (table_name,),
    ).fetchall()
    return {str(row["column_name"] or "") for row in rows}


def _table_exists(conn: Any, table_name: str) -> bool:
    return table_exists(conn, table_name)


def _index_with_leftmost_column_exists(conn: Any, table_name: str, column_name: str) -> bool:
    row = conn.execute(
        """
        SELECT 1
        FROM information_schema.statistics
        WHERE table_schema = DATABASE()
          AND table_name = %s
          AND column_name = %s
          AND seq_in_index = 1
        LIMIT 1
        """,
        (table_name, column_name),
    ).fetchone()
    return row is not None


def _safe_index_name(table_name: str, suffix: str) -> str:
    base = f"idx_{table_name}_{suffix}"
    cleaned = "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in base)
    if len(cleaned) <= 64:
        return cleaned
    digest = hashlib.sha256(cleaned.encode("utf-8", errors="replace")).hexdigest()[:10]
    return f"{cleaned[:53]}_{digest}"[:64]


def ensure_proxy_lifecycle_index(conn: Any, table: ProxyLifecycleTable) -> None:
    if table.is_indirect_child:
        if not _table_exists(conn, table.table):
            return
        if _index_with_leftmost_column_exists(conn, table.table, table.child_fk):
            return
        index_name = _safe_index_name(table.table, f"{table.child_fk}_lifecycle")
        try:
            conn.execute(
                f"ALTER TABLE {quote_mysql_identifier(table.table)} "
                f"ADD INDEX {quote_mysql_identifier(index_name)} ({quote_mysql_identifier(table.child_fk)})",
            )
        except DATABASE_ERRORS as exc:
            if mysql_error_code(exc) != 1061:
                raise
        return

    if not _table_exists(conn, table.table):
        return
    if _index_with_leftmost_column_exists(conn, table.table, table.proxy_column):
        return
    index_name = _safe_index_name(table.table, f"{table.proxy_column}_lifecycle")
    try:
        conn.execute(
            f"ALTER TABLE {quote_mysql_identifier(table.table)} "
            f"ADD INDEX {quote_mysql_identifier(index_name)} ({quote_mysql_identifier(table.proxy_column)})",
        )
    except DATABASE_ERRORS as exc:
        if mysql_error_code(exc) != 1061:
            raise


def discover_proxy_id_tables(conn: Any) -> tuple[str, ...]:
    rows = conn.execute(
        """
        SELECT c.table_name AS table_name
        FROM information_schema.columns c
        JOIN information_schema.tables t
          ON t.table_schema = c.table_schema AND t.table_name = c.table_name
        WHERE c.table_schema = DATABASE()
          AND c.column_name = 'proxy_id'
          AND t.table_type = 'BASE TABLE'
        ORDER BY c.table_name ASC
        """,
    ).fetchall()
    return tuple(str(row["table_name"] or "") for row in rows if row["table_name"])


def lifecycle_inventory(conn: Any) -> tuple[ProxyLifecycleTable, ...]:
    known_by_name = {table.table: table for table in PROXY_LIFECYCLE_TABLES}
    inventory: list[ProxyLifecycleTable] = [
        table
        for table in PROXY_LIFECYCLE_TABLES
        if table.is_indirect_child or _table_exists(conn, table.table)
    ]
    for table_name in discover_proxy_id_tables(conn):
        if table_name in known_by_name or table_name in _SPECIAL_TABLES:
            continue
        inventory.append(
            ProxyLifecycleTable(
                table_name,
                order_columns=("proxy_id",),
                note="discovered from information_schema.columns",
            ),
        )
    return tuple(inventory)


def _order_sql(conn: Any, table: ProxyLifecycleTable) -> str:
    cols = _columns(conn, table.table)
    usable = [column for column in table.order_columns if column in cols]
    if not usable and table.proxy_column in cols:
        usable = [table.proxy_column]
    if not usable:
        return ""
    return " ORDER BY " + ", ".join(quote_mysql_identifier(column) for column in usable)


def _bounded_update_proxy_id(
    conn: Any,
    table: ProxyLifecycleTable,
    *,
    old_proxy_id: str,
    new_proxy_id: str,
) -> ProxyLifecycleStepResult:
    if not table.rename or table.is_indirect_child:
        return ProxyLifecycleStepResult(table.table, "rename", skipped=True)
    if not _table_exists(conn, table.table):
        return ProxyLifecycleStepResult(table.table, "rename", skipped=True, detail="missing")
    ensure_proxy_lifecycle_index(conn, table)
    per_chunk = lifecycle_chunk_size()
    per_table = lifecycle_max_rows_per_table()
    if per_table <= 0:
        return ProxyLifecycleStepResult(table.table, "rename", truncated=True, detail="max_rows=0")
    safe_table = quote_mysql_identifier(table.table)
    proxy_col = quote_mysql_identifier(table.proxy_column)
    order_sql = _order_sql(conn, table)
    total = 0
    iterations = 0
    while total < per_table:
        limit = min(per_chunk, per_table - total)
        result = conn.execute(
            f"UPDATE {safe_table} SET {proxy_col}=%s WHERE {proxy_col}=%s{order_sql} LIMIT %s",
            (new_proxy_id, old_proxy_id, int(limit)),
        )
        changed = max(0, int(getattr(result, "rowcount", 0) or 0))
        total += changed
        iterations += 1
        conn.commit()
        if changed < limit:
            break
    return ProxyLifecycleStepResult(
        table.table,
        "rename",
        affected_rows=total,
        iterations=iterations,
        truncated=total >= per_table,
        discovered=table.note.startswith("discovered"),
    )


def _bounded_delete_proxy_id(
    conn: Any,
    table: ProxyLifecycleTable,
    *,
    proxy_id: str,
) -> ProxyLifecycleStepResult:
    if not table.remove:
        return ProxyLifecycleStepResult(table.table, "remove", skipped=True)
    if not _table_exists(conn, table.table):
        return ProxyLifecycleStepResult(table.table, "remove", skipped=True, detail="missing")
    per_chunk = lifecycle_chunk_size()
    per_table = lifecycle_max_rows_per_table()
    if per_table <= 0:
        return ProxyLifecycleStepResult(table.table, "remove", truncated=True, detail="max_rows=0")
    total = 0
    iterations = 0

    if table.is_indirect_child:
        if not _table_exists(conn, table.owner_table):
            return ProxyLifecycleStepResult(table.table, "remove", skipped=True, detail="owner_missing")
        ensure_proxy_lifecycle_index(conn, table)
        ensure_proxy_lifecycle_index(
            conn,
            ProxyLifecycleTable(table.owner_table, order_columns=("proxy_id", table.owner_pk)),
        )
        safe_table = quote_mysql_identifier(table.table)
        child_fk = quote_mysql_identifier(table.child_fk)
        safe_owner = quote_mysql_identifier(table.owner_table)
        owner_pk = quote_mysql_identifier(table.owner_pk)
        owner_proxy_col = quote_mysql_identifier(table.proxy_column)
        while total < per_table:
            limit = min(per_chunk, per_table - total)
            result = conn.execute(
                f"""
                DELETE FROM {safe_table}
                WHERE {child_fk} IN (
                    SELECT {owner_pk}
                    FROM {safe_owner}
                    WHERE {owner_proxy_col}=%s
                )
                ORDER BY {child_fk} ASC
                LIMIT %s
                """,
                (proxy_id, int(limit)),
            )
            deleted = max(0, int(getattr(result, "rowcount", 0) or 0))
            total += deleted
            iterations += 1
            conn.commit()
            if deleted < limit:
                break
        return ProxyLifecycleStepResult(
            table.table,
            "remove",
            affected_rows=total,
            iterations=iterations,
            truncated=total >= per_table,
        )

    ensure_proxy_lifecycle_index(conn, table)
    safe_table = quote_mysql_identifier(table.table)
    proxy_col = quote_mysql_identifier(table.proxy_column)
    order_sql = _order_sql(conn, table)
    while total < per_table:
        limit = min(per_chunk, per_table - total)
        result = conn.execute(
            f"DELETE FROM {safe_table} WHERE {proxy_col}=%s{order_sql} LIMIT %s",
            (proxy_id, int(limit)),
        )
        deleted = max(0, int(getattr(result, "rowcount", 0) or 0))
        total += deleted
        iterations += 1
        conn.commit()
        if deleted < limit:
            break
    return ProxyLifecycleStepResult(
        table.table,
        "remove",
        affected_rows=total,
        iterations=iterations,
        truncated=total >= per_table,
        discovered=table.note.startswith("discovered"),
    )


def rename_proxy_scoped_rows(
    conn: Any,
    *,
    old_proxy_id: str,
    new_proxy_id: str,
) -> ProxyLifecycleRunResult:
    table_results: list[ProxyLifecycleStepResult] = []
    for table in lifecycle_inventory(conn):
        result = _bounded_update_proxy_id(
            conn,
            table,
            old_proxy_id=old_proxy_id,
            new_proxy_id=new_proxy_id,
        )
        table_results.append(result)
        if result.truncated:
            break
    table_counts = {
        result.table: result.affected_rows
        for result in table_results
        if result.affected_rows > 0
    }
    truncated = tuple(result.table for result in table_results if result.truncated)
    discovered = tuple(result.table for result in table_results if result.discovered)
    return ProxyLifecycleRunResult(
        action="rename",
        proxy_id=old_proxy_id,
        target_proxy_id=new_proxy_id,
        complete=not truncated,
        affected_rows=sum(table_counts.values()),
        iterations=sum(result.iterations for result in table_results),
        table_counts=dict(sorted(table_counts.items())),
        table_results=tuple(table_results),
        discovered_tables=discovered,
        truncated_tables=truncated,
    )


def remove_proxy_scoped_rows(conn: Any, *, proxy_id: str) -> ProxyLifecycleRunResult:
    table_results: list[ProxyLifecycleStepResult] = []
    for table in lifecycle_inventory(conn):
        result = _bounded_delete_proxy_id(conn, table, proxy_id=proxy_id)
        table_results.append(result)
        if result.truncated:
            break
    table_counts = {
        result.table: result.affected_rows
        for result in table_results
        if result.affected_rows > 0
    }
    truncated = tuple(result.table for result in table_results if result.truncated)
    discovered = tuple(result.table for result in table_results if result.discovered)
    return ProxyLifecycleRunResult(
        action="remove",
        proxy_id=proxy_id,
        complete=not truncated,
        affected_rows=sum(table_counts.values()),
        iterations=sum(result.iterations for result in table_results),
        table_counts=dict(sorted(table_counts.items())),
        table_results=tuple(table_results),
        discovered_tables=discovered,
        truncated_tables=truncated,
    )
