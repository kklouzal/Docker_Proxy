from __future__ import annotations

import hashlib
import json
import os
from typing import TYPE_CHECKING, Any

import pytest
from services import proxy_recovery  # type: ignore
from services import proxy_recovery_db as recovery_db  # type: ignore

if TYPE_CHECKING:
    from pathlib import Path

_CONTROL_PLANE_ID = "123e4567-e89b-42d3-a456-426614174000"
_BLOB = b"PK\x03\x04" + os.urandom(4096)


def _sql(sql: str) -> str:
    return " ".join(str(sql).split())


class _Result:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def __iter__(self):
        return iter(self._rows)


class _Conn:
    """MySQL stand-in serving export, fingerprint and identity queries."""

    def __init__(self, state: dict[str, list[dict[str, Any]]]) -> None:
        self.state = state
        self.queries: list[str] = []
        self.blob_bytes_sent = 0

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql: str, params=()):
        text = _sql(sql)
        self.queries.append(text)
        if text.startswith(("START TRANSACTION", "SELECT control_plane_id")):
            return _Result([{"control_plane_id": _CONTROL_PLANE_ID}])
        for plan in recovery_db.recovery_export_query_plans():
            rows = self.state.get(plan.table_name, [])
            if text == _sql(plan.sql):
                for row in rows:
                    for column in plan.blob_columns:
                        self.blob_bytes_sent += len(row[column] or b"")
                return _Result([dict(row) for row in rows])
            if plan.fingerprint_sql and text == _sql(plan.fingerprint_sql):
                derived = []
                for row in rows:
                    item = {k: v for k, v in row.items() if k not in plan.blob_columns}
                    for column in plan.blob_columns:
                        blob = row[column]
                        item[f"{column}_sha256"] = (
                            None if blob is None else hashlib.sha256(blob).hexdigest()
                        )
                        item[f"{column}_length"] = None if blob is None else len(blob)
                    derived.append(item)
                return _Result(derived)
        msg = f"unexpected SQL: {text}"
        raise AssertionError(msg)

    def commit(self) -> None:
        return None

    def rollback(self) -> None:
        return None


def _state(
    blob: bytes = _BLOB, lists_enabled: int = 1
) -> dict[str, list[dict[str, Any]]]:
    return {
        "adblock_lists": [
            {
                "key": "easylist",
                "url": "https://example.test/l",
                "enabled": lists_enabled,
            }
        ],
        "adblock_artifact_revisions": [
            {
                "artifact_sha256": "a" * 64,
                "archive_blob": blob,
                "report_json": "{}",
                "settings_version": 3,
                "enabled_lists_json": '["easylist"]',
            }
        ],
    }


def _capture(conn: _Conn, tmp_path: Path) -> recovery_db.RecoveryBundleWrite:
    return recovery_db.capture_and_write_recovery_bundle(
        lambda: conn, "edge-01", recovery_dir=tmp_path
    )


def _blob_queries(conn: _Conn) -> list[str]:
    plan = next(p for p in recovery_db.recovery_export_query_plans() if p.blob_columns)
    return [q for q in conn.queries if q == _sql(plan.sql)]


def test_fingerprint_of_full_capture_equals_blob_free_fingerprint() -> None:
    conn = _Conn(_state())
    captured = recovery_db.capture_recovery_state(conn, "edge-01")

    assert recovery_db.captured_state_fingerprint(
        captured
    ) == recovery_db.current_state_fingerprint(conn, "edge-01")
    changed = _Conn(_state(blob=_BLOB + b"x"))
    assert recovery_db.current_state_fingerprint(
        changed, "edge-01"
    ) != recovery_db.captured_state_fingerprint(captured)


def test_unchanged_capture_reads_no_blob_and_keeps_the_bundle(tmp_path: Path) -> None:
    conn = _Conn(_state())
    first = _capture(conn, tmp_path)
    assert first.written is True
    assert conn.blob_bytes_sent == len(_BLOB)
    before = first.path.stat()
    bundle_bytes = first.path.read_bytes()

    conn.queries.clear()
    second = _capture(conn, tmp_path)

    assert second == recovery_db.RecoveryBundleWrite(first.path, written=False)
    assert _blob_queries(conn) == []
    assert conn.blob_bytes_sent == len(_BLOB)
    after = first.path.stat()
    assert (after.st_ino, after.st_mtime_ns) == (before.st_ino, before.st_mtime_ns)
    assert first.path.read_bytes() == bundle_bytes
    # The kept bundle still verifies and holds the full blob.
    bundle = proxy_recovery.read_recovery_bundle("edge-01", recovery_dir=tmp_path)
    tables = {table.name: table.rows for table in bundle.tables}
    assert tables["adblock_artifact_revisions"][0]["archive_blob"] == _BLOB


@pytest.mark.parametrize("change", ["blob", "small_table"])
def test_changed_state_is_captured_in_full(tmp_path: Path, change: str) -> None:
    _capture(_Conn(_state()), tmp_path)
    new_state = (
        _state(blob=_BLOB + b"new") if change == "blob" else _state(lists_enabled=0)
    )
    conn = _Conn(new_state)

    result = _capture(conn, tmp_path)

    assert result.written is True
    bundle = proxy_recovery.read_recovery_bundle("edge-01", recovery_dir=tmp_path)
    tables = {table.name: table.rows for table in bundle.tables}
    assert (
        tables["adblock_artifact_revisions"][0]["archive_blob"]
        == (new_state["adblock_artifact_revisions"][0]["archive_blob"])
    )
    assert (
        tables["adblock_lists"][0]["enabled"]
        == new_state["adblock_lists"][0]["enabled"]
    )
    # And the next unchanged capture is cheap again.
    assert _capture(conn, tmp_path).written is False


def _record_path(tmp_path: Path) -> Path:
    return tmp_path / ".edge-01.bundle.json.fingerprint"


@pytest.mark.parametrize(
    "tamper", ["record_mac", "bundle_replaced", "record_expired", "record_missing"]
)
def test_unverifiable_fingerprint_record_forces_full_capture(
    tmp_path: Path, monkeypatch, tamper: str
) -> None:
    conn = _Conn(_state())
    first = _capture(conn, tmp_path)
    record = _record_path(tmp_path)
    if tamper == "record_mac":
        envelope = json.loads(record.read_text())
        envelope["mac"] = "0" * 64
        record.write_text(json.dumps(envelope))
    elif tamper == "bundle_replaced":
        data = first.path.read_bytes()
        first.path.unlink()
        first.path.write_bytes(data)
        first.path.chmod(0o600)
    elif tamper == "record_expired":
        real_time = recovery_db.time.time
        monkeypatch.setattr(recovery_db.time, "time", lambda: real_time() + 25 * 3600)
    else:
        record.unlink()

    conn.blob_bytes_sent = 0
    result = _capture(conn, tmp_path)

    assert result.written is True
    assert conn.blob_bytes_sent == len(_BLOB)


@pytest.mark.integration
@pytest.mark.mysql
def test_mysql_server_side_blob_digest_matches_capture_fingerprint(tmp_path) -> None:
    from unittest import SkipTest

    from .mysql_test_utils import configure_test_mysql_env

    try:
        configure_test_mysql_env(tmp_path, secret_path=tmp_path / "flask_secret.key")
    except SkipTest as exc:
        pytest.skip(str(exc))
    from services import proxy_recovery_db as live_recovery_db  # type: ignore
    from services import schema_lifecycle  # type: ignore
    from services.adblock_artifacts import get_adblock_artifacts  # type: ignore
    from services.db import connect  # type: ignore

    schema_lifecycle.migrate_schema(require_privileges=False)
    blob = os.urandom(300_000)
    get_adblock_artifacts().create_revision(
        archive_blob=blob,
        artifact_sha256=hashlib.sha256(b"files").hexdigest(),
        report_json="{}",
        settings_version=1,
        enabled_lists=["easylist"],
    )

    with connect() as conn:
        captured = live_recovery_db.capture_recovery_state(conn, "edge-01")
    with connect() as conn:
        cheap = live_recovery_db.current_state_fingerprint(conn, "edge-01")

    artifact_rows = next(
        table.rows
        for table in captured.tables
        if table.name == "adblock_artifact_revisions"
    )
    assert artifact_rows[0]["archive_blob"] == blob
    assert cheap == live_recovery_db.captured_state_fingerprint(captured)
