from __future__ import annotations

# ruff: noqa: I001

import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

WEB_ROOT = Path(__file__).resolve().parents[1]
if str(WEB_ROOT) not in sys.path:
    sys.path.insert(0, str(WEB_ROOT))

from services import proxy_recovery  # type: ignore  # noqa: E402
from services import proxy_recovery_db as recovery_db  # type: ignore  # noqa: E402


_SOURCE_CONTROL_PLANE_ID = "123e4567-e89b-42d3-a456-426614174000"


class _Result:
    def __init__(self, rows: list[Any] | None = None) -> None:
        self._rows = rows or []

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)

    def __iter__(self):
        return iter(self._rows)


class _StrictExportConn:
    def __init__(
        self,
        rows_by_table: dict[str, list[Any]] | None = None,
        *,
        fail_table: str | None = None,
        expected_now_ts: int | None = None,
    ) -> None:
        self.rows_by_table = rows_by_table or {}
        self.fail_table = fail_table
        self.expected_now_ts = expected_now_ts
        self.ops: list[tuple[str, tuple[Any, ...]]] = []
        self.commits = 0
        self.rollbacks = 0
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.closed = True
        return False

    def execute(self, sql: str, params=()):
        text = _sql(sql)
        params = tuple(params or ())
        self.ops.append((text, params))
        if text == "START TRANSACTION READ ONLY, WITH CONSISTENT SNAPSHOT":
            assert params == ()
            return _Result()
        if text.startswith("SELECT control_plane_id FROM control_plane_identity"):
            assert params == ()
            return _Result([{"control_plane_id": _SOURCE_CONTROL_PLANE_ID}])
        for plan in recovery_db.recovery_export_query_plans():
            if text == _sql(plan.sql):
                if self.fail_table == plan.table_name:
                    msg = f"simulated {plan.table_name} failure"
                    raise RuntimeError(msg)
                if self.expected_now_ts is None and plan.param_mode == "proxy_now":
                    assert params[0] == "edge-01"
                    assert isinstance(params[1], int)
                else:
                    assert params == _expected_params(
                        plan,
                        "edge-01",
                        self.expected_now_ts or 987654321,
                    )
                return _Result(self.rows_by_table.get(plan.table_name, []))
        msg = f"unexpected SQL: {text}"
        raise AssertionError(msg)

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1


def _sql(sql: str) -> str:
    return " ".join(str(sql).split())


def _expected_params(
    plan: recovery_db.RecoveryExportQueryPlan,
    proxy_id: str,
    now_ts: int,
) -> tuple[Any, ...]:
    if plan.param_mode == "none":
        return ()
    if plan.param_mode == "proxy":
        return (proxy_id,)
    if plan.param_mode == "proxy_now":
        return (proxy_id, now_ts)
    raise AssertionError(plan.param_mode)


def test_export_query_plan_coverage_is_exact_static_and_excludes_unsafe_columns() -> (
    None
):
    registry_tables = tuple(
        spec.table_name for spec in proxy_recovery.recovery_registry()
    )
    plan_tables = tuple(
        plan.table_name for plan in recovery_db.recovery_export_query_plans()
    )

    assert plan_tables == registry_tables
    recovery_db.validate_export_query_plan_coverage()

    forbidden_columns = {
        "last_success",
        "last_attempt",
        "last_error",
        "bytes",
        "rules",
        "active_global_slot",
        "active_proxy_id",
        "created_ts",
        "updated_ts",
        "applied_ts",
        "last_run_ts",
        "last_status",
        "source_request_id",
        "revoked_ts",
        "revoked_by",
    }
    for plan in recovery_db.recovery_export_query_plans():
        lowered = _sql(plan.sql).lower()
        assert "select *" not in lowered
        assert "{" not in plan.sql
        assert "}" not in plan.sql
        assert plan.table_name in lowered
        assert forbidden_columns.isdisjoint(plan.columns)
    assert recovery_db.recovery_export_query_plans()[0].table_name == "adblock_lists"
    assert recovery_db.recovery_export_query_plans()[-1].table_name == (
        "observability_report_schedules"
    )
    report_schedule_plan = recovery_db.recovery_export_query_plans()[-1]
    assert report_schedule_plan.columns == (
        "proxy_id",
        "enabled",
        "name",
        "cadence",
        "recipients",
        "pane",
        "report_format",
        "privacy",
        "window_seconds",
    )


def test_capture_recovery_state_uses_snapshot_identity_exact_queries_and_normalizes_rows() -> (
    None
):
    rows_by_table = {
        "adblock_lists": [
            {
                "key": "easylist",
                "url": "https://example.invalid/list.txt",
                "enabled": 1,
                "last_success": 123,
                "bytes": 456,
                "rules": 789,
            },
        ],
        "adblock_artifact_revisions": [
            {
                "artifact_sha256": "a" * 64,
                "archive_blob": bytearray(b"archive"),
                "report_json": "{}",
                "settings_version": 7,
                "enabled_lists_json": "[]",
                "id": 99,
                "created_ts": 1,
            },
        ],
        "pac_profiles": [
            {
                "source_profile_id": 42,
                "proxy_id": "edge-01",
                "name": "default",
                "client_cidr": "10.0.0.0/24",
                "created_ts": 99,
            },
        ],
        "pac_direct_domains": [
            {"source_profile_id": 42, "domain": "example.com", "profile_id": 42},
        ],
        "policy_exceptions": [
            {
                "proxy_id": "edge-01",
                "block_type": "webfilter",
                "client_ip": "10.0.0.10",
                "domain": "allowed.example",
                "category": "work",
                "method": "POST",
                "admin_note": "temporary",
                "expires_ts": 987654999,
                "source_request_id": 123,
                "revoked_ts": 0,
            },
        ],
        "adblock_proxy_meta": [
            {"proxy_id": "edge-01", "k": "enabled", "v": "1"},
        ],
    }
    conn = _StrictExportConn(rows_by_table, expected_now_ts=987654321)

    captured = recovery_db.capture_recovery_state(conn, "EDGE-01", now_ts=987654321)

    assert captured.proxy_id == "edge-01"
    assert captured.source_control_plane_id == _SOURCE_CONTROL_PLANE_ID
    assert [table.name for table in captured.tables] == [
        spec.table_name for spec in proxy_recovery.recovery_registry()
    ]
    assert conn.ops[0] == (
        "START TRANSACTION READ ONLY, WITH CONSISTENT SNAPSHOT",
        (),
    )
    assert conn.commits == 1
    assert conn.rollbacks == 0

    by_table = {table.name: table for table in captured.tables}
    assert by_table["adblock_lists"].rows == (
        {
            "key": "easylist",
            "url": "https://example.invalid/list.txt",
            "enabled": 1,
        },
    )
    assert by_table["adblock_artifact_revisions"].rows[0]["archive_blob"] == b"archive"
    assert set(by_table["adblock_artifact_revisions"].rows[0]) == {
        "artifact_sha256",
        "archive_blob",
        "report_json",
        "settings_version",
        "enabled_lists_json",
    }
    assert by_table["pac_profiles"].rows == (
        {
            "source_profile_id": 42,
            "proxy_id": "edge-01",
            "name": "default",
            "client_cidr": "10.0.0.0/24",
        },
    )
    assert by_table["pac_direct_domains"].rows == (
        {"source_profile_id": 42, "domain": "example.com"},
    )
    assert by_table["policy_exceptions"].rows == (
        {
            "proxy_id": "edge-01",
            "block_type": "webfilter",
            "client_ip": "10.0.0.10",
            "domain": "allowed.example",
            "category": "work",
            "method": "POST",
            "admin_note": "temporary",
            "expires_ts": 987654999,
        },
    )
    assert by_table["adblock_proxy_meta"].rows == (
        {"proxy_id": "edge-01", "k": "enabled", "v": "1"},
    )

    executed_sql = [sql for sql, _params in conn.ops]
    assert any(
        "FROM pac_direct_domains d INNER JOIN pac_profiles p ON p.id=d.profile_id"
        in sql
        and "WHERE p.proxy_id=%s" in sql
        for sql in executed_sql
    )
    assert any(
        "FROM policy_exceptions" in sql
        and "status='active'" in sql
        and "expires_ts>%s" in sql
        for sql in executed_sql
    )
    assert any(
        "FROM webfilter_settings" in sql
        and "k IN ('enabled','blocked_categories')" in sql
        for sql in executed_sql
    )


def test_concurrent_capture_serializes_snapshot_before_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_snapshot_started = threading.Event()
    release_first_snapshot = threading.Event()
    second_snapshot_started = threading.Event()
    writes: list[str] = []

    def capture_state(_conn, proxy_id, **_kwargs):
        name = threading.current_thread().name
        if name == "older-capture":
            first_snapshot_started.set()
            assert release_first_snapshot.wait(timeout=2)
        else:
            second_snapshot_started.set()
        return SimpleNamespace(
            proxy_id=proxy_id,
            source_control_plane_id=_SOURCE_CONTROL_PLANE_ID,
            created_ts="2026-08-14T05:07:00Z",
            tables=((name,),),
        )

    def write_bundle(_proxy_id, tables, **_kwargs):
        writes.append(tables[0][0])
        return tmp_path / "edge-01.bundle.json"

    monkeypatch.setattr(recovery_db, "capture_recovery_state", capture_state)
    monkeypatch.setattr(proxy_recovery, "write_recovery_bundle", write_bundle)

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    first = threading.Thread(
        target=recovery_db.capture_and_write_recovery_bundle,
        name="older-capture",
        args=(Conn, "edge-01"),
        kwargs={"recovery_dir": tmp_path},
    )
    second = threading.Thread(
        target=recovery_db.capture_and_write_recovery_bundle,
        name="newer-capture",
        args=(Conn, "edge-01"),
        kwargs={"recovery_dir": tmp_path},
    )
    first.start()
    assert first_snapshot_started.wait(timeout=2)
    second.start()
    assert not second_snapshot_started.wait(timeout=0.1)
    release_first_snapshot.set()
    first.join(timeout=2)
    second.join(timeout=2)

    assert not first.is_alive()
    assert not second.is_alive()
    assert second_snapshot_started.is_set()
    assert writes == ["older-capture", "newer-capture"]


def test_capture_lock_preserves_oserror_from_protected_body(tmp_path: Path) -> None:
    expected = OSError("database snapshot failed")

    class FailingConn:
        def __enter__(self):
            raise expected

        def __exit__(self, *_args):
            return None

    with pytest.raises(OSError, match="database snapshot failed") as caught:
        recovery_db.capture_and_write_recovery_bundle(
            FailingConn,
            "edge-01",
            recovery_dir=tmp_path,
        )

    assert caught.value is expected


def test_capture_lock_rejects_symlink_without_following_it(tmp_path: Path) -> None:
    target = tmp_path / "attacker-controlled"
    target.write_text("unchanged", encoding="utf-8")
    lock_path = tmp_path / ".edge-01.bundle.json.capture.lock"
    lock_path.symlink_to(target)

    with pytest.raises(
        proxy_recovery.ProxyRecoveryError, match="must not be a symlink"
    ):
        with recovery_db._recovery_capture_lock("edge-01", tmp_path):
            pytest.fail("symlink lock must not be acquired")

    assert target.read_text(encoding="utf-8") == "unchanged"


def test_capture_lock_hardens_directory_and_lock_permissions(tmp_path: Path) -> None:
    tmp_path.chmod(0o750)

    with recovery_db._recovery_capture_lock("edge-01", tmp_path):
        lock_path = tmp_path / ".edge-01.bundle.json.capture.lock"
        assert lock_path.stat().st_mode & 0o777 == 0o600
        assert tmp_path.stat().st_mode & 0o777 == 0o700


def test_capture_and_write_is_all_or_nothing_and_does_not_fsync_inside_db_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    failed_conn = _StrictExportConn(fail_table="sslfilter_domains")
    writes: list[dict[str, Any]] = []

    def fake_write(*args, **kwargs):
        writes.append({"args": args, "kwargs": kwargs})
        return tmp_path / "edge-01.bundle.json"

    monkeypatch.setattr(proxy_recovery, "write_recovery_bundle", fake_write)
    with pytest.raises(RuntimeError, match="sslfilter_domains failure"):
        recovery_db.capture_and_write_recovery_bundle(
            lambda: failed_conn,
            "edge-01",
            recovery_dir=tmp_path,
        )
    assert writes == []
    assert failed_conn.rollbacks == 1

    good_conn = _StrictExportConn()

    def assert_closed_then_write(*args, **kwargs):
        assert good_conn.closed is True
        writes.append({"args": args, "kwargs": kwargs})
        return tmp_path / "edge-01.bundle.json"

    monkeypatch.setattr(
        proxy_recovery, "write_recovery_bundle", assert_closed_then_write
    )
    path = recovery_db.capture_and_write_recovery_bundle(
        lambda: good_conn,
        "edge-01",
        recovery_dir=tmp_path,
    )

    assert path == tmp_path / "edge-01.bundle.json"
    assert writes[-1]["args"][0] == "edge-01"
    assert writes[-1]["kwargs"]["source_control_plane_id"] == _SOURCE_CONTROL_PLANE_ID
    assert good_conn.commits == 1
    assert good_conn.closed is True


def test_capture_budget_stops_streaming_wide_bytes_and_rolls_back() -> None:
    from services.db import CompatResult  # type: ignore

    consumed = 0

    class StreamingCursor:
        description = (("key",), ("url",), ("enabled",))
        rowcount = 10_000
        lastrowid = None
        rownumber = 0

        def fetchone(self):
            nonlocal consumed
            index = self.rownumber
            self.rownumber += 1
            consumed += 1
            return (f"list-{index}", b"x" * 700, 1)

        def fetchall(self):
            pytest.fail("capture must not materialize the complete result set")

        def close(self) -> None:
            pass

    class StreamingConn(_StrictExportConn):
        def execute(self, sql: str, params=()):
            if _sql(sql) == _sql(recovery_db.recovery_export_query_plans()[0].sql):
                return CompatResult(StreamingCursor())
            return super().execute(sql, params)

    conn = StreamingConn(expected_now_ts=987654321)
    with pytest.raises(
        proxy_recovery.ProxyRecoveryError,
        match="exceeds maximum size during database capture",
    ):
        recovery_db.capture_recovery_state(
            conn,
            "edge-01",
            now_ts=987654321,
            max_bundle_bytes=4096,
        )

    assert consumed < 10
    assert conn.commits == 0
    assert conn.rollbacks == 1


def test_capture_budget_matches_successful_canonical_bundle_size(
    tmp_path: Path,
) -> None:
    conn = _StrictExportConn(
        {
            "adblock_artifact_revisions": [
                {
                    "artifact_sha256": "a" * 64,
                    "archive_blob": b"binary\x00payload",
                    "report_json": "{}",
                    "settings_version": 1,
                    "enabled_lists_json": "[]",
                }
            ]
        },
        expected_now_ts=987654321,
    )
    captured = recovery_db.capture_recovery_state(
        conn,
        "edge-01",
        now_ts=987654321,
        max_bundle_bytes=16_384,
    )
    bundle = proxy_recovery.create_recovery_bundle(
        captured.proxy_id,
        captured.tables,
        source_control_plane_id=captured.source_control_plane_id,
        created_ts=captured.created_ts,
        recovery_dir=tmp_path,
        max_bundle_bytes=16_384,
    )

    assert len(proxy_recovery.serialize_recovery_bundle(bundle)) <= 16_384
    restored = proxy_recovery.parse_recovery_bundle(
        proxy_recovery.serialize_recovery_bundle(bundle),
        expected_proxy_id="edge-01",
        expected_source_control_plane_id=_SOURCE_CONTROL_PLANE_ID,
        key=proxy_recovery.read_signing_key("edge-01", tmp_path),
        max_bundle_bytes=16_384,
    )
    by_table = {table.name: table for table in restored.tables}
    assert by_table["adblock_artifact_revisions"].rows[0]["archive_blob"] == (
        b"binary\x00payload"
    )
