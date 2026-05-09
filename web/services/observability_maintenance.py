from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from services.db import DATABASE_ERRORS, connect, table_exists


OBSERVABILITY_LOG_TABLES: tuple[str, ...] = (
    "diagnostic_requests",
    "diagnostic_icap_events",
    "ssl_errors",
    "adblock_events",
    "adblock_counts",
    "adblock_cache_stats",
    "webfilter_blocked_log",
    "ts_1s",
    "ts_1m",
    "ts_1h",
    "ts_1d",
    "ts_1w",
    "ts_1mo",
    "ts_1y",
)


@dataclass(frozen=True)
class ObservabilityLogTableResult:
    table: str
    status: str
    deleted_rows: int = 0
    maintenance: str = ""
    detail: str = ""


def _quote_identifier(identifier: str) -> str:
    value = (identifier or "").strip()
    if not value or not value.replace("_", "").isalnum():
        raise ValueError(f"Unsafe MySQL identifier: {identifier!r}")
    return f"`{value}`"


def _best_effort_table_maintenance(conn: Any, table: str, *, optimize: bool) -> str:
    quoted = _quote_identifier(table)
    operations: List[str] = []
    try:
        conn.execute(f"ALTER TABLE {quoted} AUTO_INCREMENT = 1")
        operations.append("auto_increment_reset")
    except DATABASE_ERRORS:
        operations.append("auto_increment_reset_skipped")
    except Exception:
        operations.append("auto_increment_reset_skipped")

    if optimize:
        try:
            conn.execute(f"OPTIMIZE TABLE {quoted}")
            operations.append("optimized")
        except DATABASE_ERRORS:
            operations.append("optimize_skipped")
        except Exception:
            operations.append("optimize_skipped")
    return ",".join(operations)


def clear_observability_logs(*, optimize: bool = True) -> Dict[str, Any]:
    """Wipe stored MySQL observability/log history across the whole fleet.

    This intentionally does not take a proxy_id. The Observability overview
    action is fleet-wide by design: it clears historical request/security/
    performance records for every proxy while leaving proxy configuration,
    policy settings, credentials, audit history, and registry state intact.
    """
    table_results: List[ObservabilityLogTableResult] = []
    total_deleted = 0

    with connect() as conn:
        for table in OBSERVABILITY_LOG_TABLES:
            if not table_exists(conn, table):
                table_results.append(ObservabilityLogTableResult(table=table, status="missing"))
                continue

            quoted = _quote_identifier(table)
            result = conn.execute(f"DELETE FROM {quoted}")
            deleted = max(0, int(getattr(result, "rowcount", 0) or 0))
            total_deleted += deleted
            maintenance = _best_effort_table_maintenance(conn, table, optimize=optimize)
            table_results.append(
                ObservabilityLogTableResult(
                    table=table,
                    status="cleared",
                    deleted_rows=deleted,
                    maintenance=maintenance,
                )
            )

    return {
        "ok": True,
        "deleted_rows": total_deleted,
        "tables": [r.__dict__.copy() for r in table_results],
    }
