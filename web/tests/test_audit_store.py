from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

WEB_DIR = Path(__file__).resolve().parents[1]
if str(WEB_DIR) not in sys.path:
    sys.path.insert(0, str(WEB_DIR))

from services.audit_store import AuditStore  # type: ignore  # noqa: E402


class _FakeResult:
    def __init__(self, rows: Iterable[object] = (), rowcount: int = 0) -> None:
        self._rows = list(rows)
        self.rowcount = rowcount

    def fetchall(self) -> list[object]:
        return list(self._rows)


class _FakeAuditConnection:
    def __init__(self, rows: list[dict[str, object]]) -> None:
        self.rows = rows

    def __enter__(self):
        return self

    def __exit__(self, *_exc: object) -> bool:
        return False

    def execute(self, sql: str, params: tuple[object, ...] | None = None) -> _FakeResult:
        compact_sql = " ".join(str(sql).split())
        params = tuple(params or ())
        if compact_sql.startswith("SELECT DISTINCT proxy_id FROM audit_events"):
            return _FakeResult(
                {"proxy_id": proxy_id}
                for proxy_id in sorted({str(row["proxy_id"]) for row in self.rows})
            )
        if compact_sql.startswith("SELECT ts, id FROM audit_events WHERE proxy_id=%s"):
            proxy_id = str(params[0])
            limit = int(params[1])
            matching = [row for row in self.rows if row["proxy_id"] == proxy_id]
            matching.sort(key=lambda row: (int(row["ts"]), int(row["id"])), reverse=True)
            return _FakeResult(dict(row) for row in matching[:limit])
        if compact_sql.startswith("DELETE FROM `audit_events` WHERE proxy_id = %s"):
            proxy_id = str(params[0])
            boundary_ts = int(params[1])
            tie_ts = int(params[2])
            boundary_id = int(params[3])
            limit = int(params[4])
            delete_indexes = [
                index
                for index, row in enumerate(self.rows)
                if row["proxy_id"] == proxy_id
                and (
                    int(row["ts"]) < boundary_ts
                    or (int(row["ts"]) == tie_ts and int(row["id"]) < boundary_id)
                )
            ]
            delete_indexes.sort(key=lambda index: (self.rows[index]["proxy_id"], int(self.rows[index]["ts"]), int(self.rows[index]["id"])))
            delete_indexes = delete_indexes[:limit]
            for index in reversed(delete_indexes):
                self.rows.pop(index)
            return _FakeResult(rowcount=len(delete_indexes))
        msg = f"Unexpected SQL: {compact_sql!r} params={params!r}"
        raise AssertionError(msg)


def _store_with_rows(rows: list[dict[str, object]]) -> AuditStore:
    store = AuditStore.__new__(AuditStore)
    store._schema_ready = True
    store._connect = lambda: _FakeAuditConnection(rows)  # type: ignore[method-assign]
    return store


def test_prune_to_last_events_preserves_quiet_proxy_when_another_proxy_is_noisy() -> None:
    rows = [
        {"id": 1, "proxy_id": "quiet", "ts": 10, "kind": "config_apply_manual"},
        {"id": 2, "proxy_id": "quiet", "ts": 20, "kind": "config_apply_manual"},
        {"id": 10, "proxy_id": "noisy", "ts": 100, "kind": "probe"},
        {"id": 11, "proxy_id": "noisy", "ts": 110, "kind": "probe"},
        {"id": 12, "proxy_id": "noisy", "ts": 120, "kind": "probe"},
        {"id": 13, "proxy_id": "noisy", "ts": 130, "kind": "probe"},
    ]
    store = _store_with_rows(rows)

    deleted = store._prune_to_last_events(max_events=3, max_rows=50)

    assert deleted == 1
    assert [row["id"] for row in rows if row["proxy_id"] == "quiet"] == [1, 2]
    assert [row["id"] for row in rows if row["proxy_id"] == "noisy"] == [11, 12, 13]


def test_prune_to_last_events_bounds_old_events_within_same_proxy() -> None:
    rows = [
        {"id": 1, "proxy_id": "quiet", "ts": 10, "kind": "config_apply_manual"},
        {"id": 2, "proxy_id": "quiet", "ts": 20, "kind": "config_apply_manual"},
        {"id": 3, "proxy_id": "quiet", "ts": 30, "kind": "config_apply_manual"},
        {"id": 4, "proxy_id": "quiet", "ts": 40, "kind": "config_apply_manual"},
        {"id": 10, "proxy_id": "noisy", "ts": 100, "kind": "probe"},
        {"id": 11, "proxy_id": "noisy", "ts": 110, "kind": "probe"},
        {"id": 12, "proxy_id": "noisy", "ts": 120, "kind": "probe"},
    ]
    store = _store_with_rows(rows)

    deleted = store._prune_to_last_events(max_events=2, max_rows=50)

    assert deleted == 3
    assert [row["id"] for row in rows if row["proxy_id"] == "quiet"] == [3, 4]
    assert [row["id"] for row in rows if row["proxy_id"] == "noisy"] == [11, 12]
