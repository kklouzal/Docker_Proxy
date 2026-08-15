from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

WEB_ROOT = Path(__file__).resolve().parents[1]
if str(WEB_ROOT) not in sys.path:
    sys.path.insert(0, str(WEB_ROOT))

from services import proxy_recovery  # type: ignore  # noqa: E402
from services import proxy_recovery_restore as restore  # type: ignore  # noqa: E402

SOURCE_ID = "123e4567-e89b-42d3-a456-426614174000"
TARGET_ID = "223e4567-e89b-42d3-a456-426614174000"
SECOND_TARGET_ID = "323e4567-e89b-42d3-a456-426614174000"
NOW = 1_700_000_000


class _Result:
    def __init__(self, rows: list[Any] | None = None) -> None:
        self._rows = rows or []
        self.lastrowid = 0
        self.rowcount = len(self._rows)

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)

    def __iter__(self):
        return iter(self._rows)


class _CompatRestoreConn:
    def __init__(
        self,
        adblock_settings: dict[str, str],
        *,
        control_plane_id: str = TARGET_ID,
    ) -> None:
        self.adblock_settings = adblock_settings
        self.adblock_proxy_meta: dict[tuple[str, str], str] = {}
        self.control_plane_id = control_plane_id
        self.ops: list[tuple[str, tuple[Any, ...]]] = []
        self.commits = 0
        self.rollbacks = 0

    def execute(self, sql: str, params=()):
        text = " ".join(str(sql).split())
        bound = tuple(params or ())
        self.ops.append((text, bound))
        if text.startswith("SELECT control_plane_id FROM control_plane_identity"):
            return _Result([{"control_plane_id": self.control_plane_id}])
        if "FROM proxy_recovery_adoptions" in text:
            return _Result()
        if text.startswith("SELECT status FROM proxy_instances"):
            return _Result([{"status": "active"}])
        if text.startswith("SELECT GET_LOCK"):
            return _Result([{"acquired": 1}])
        if text.startswith("SELECT `key`, url, enabled FROM adblock_lists"):
            return _Result()
        if text.startswith("SELECT k, v FROM adblock_settings"):
            return _Result(
                [
                    {"k": key, "v": value}
                    for key, value in sorted(self.adblock_settings.items())
                ],
            )
        if text.startswith("SELECT proxy_id, k, v FROM adblock_proxy_meta"):
            proxy_id = str(bound[0])
            return _Result(
                [
                    {"proxy_id": row_proxy_id, "k": key, "v": value}
                    for (row_proxy_id, key), value in sorted(
                        self.adblock_proxy_meta.items()
                    )
                    if row_proxy_id == proxy_id and key == "enabled"
                ],
            )
        if text == "DELETE FROM adblock_settings":
            self.adblock_settings.clear()
        elif text.startswith("DELETE FROM adblock_proxy_meta WHERE proxy_id="):
            proxy_id = str(bound[0])
            self.adblock_proxy_meta = {
                key: value
                for key, value in self.adblock_proxy_meta.items()
                if key[0] != proxy_id
            }
        if text.startswith("SELECT COUNT(*) AS count"):
            return _Result([{"count": 0}])
        return _Result()

    def executemany(self, sql: str, seq_of_params) -> _Result:
        text = " ".join(str(sql).split())
        for params in seq_of_params:
            bound = tuple(params)
            self.ops.append((text, bound))
            if text.startswith("INSERT INTO adblock_settings"):
                self.adblock_settings[str(bound[0])] = str(bound[1])
            elif text.startswith("INSERT INTO adblock_proxy_meta"):
                self.adblock_proxy_meta[str(bound[0]), str(bound[1])] = str(bound[2])
        return _Result()

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1


@pytest.fixture(autouse=True)
def _metadata_tables_available(monkeypatch) -> None:
    monkeypatch.setattr(
        "services.proxy_write_guard.table_exists",
        lambda _conn, name: name in {"proxy_instances", "proxy_lifecycle_tombstones"},
    )


def _bundle(restored_enabled: str) -> proxy_recovery.RecoveryBundle:
    tables = tuple(
        proxy_recovery.RecoveryTablePayload(
            name,
            ({"k": "enabled", "v": restored_enabled},)
            if name == "adblock_settings"
            else (),
        )
        for name in restore._EXPECTED_TABLE_ORDER
    )
    return proxy_recovery.RecoveryBundle(
        format_version=proxy_recovery.FORMAT_VERSION,
        proxy_id="edge-01",
        source_control_plane_id=SOURCE_ID,
        created_ts="2026-01-01T00:00:00Z",
        schema_version=proxy_recovery.DATA_SCHEMA_VERSION,
        tables=tables,
        integrity=proxy_recovery.IntegrityMetadata(
            "a" * 64,
            proxy_recovery.MAC_ALGORITHM,
            "b" * 64,
        ),
    )


@pytest.mark.parametrize(
    ("target_enabled", "restored_enabled"),
    [("1", "0"), ("0", "1")],
)
def test_canonical_bootstrap_states_normalize_legacy_enabled_to_proxy_runtime(
    target_enabled: str,
    restored_enabled: str,
) -> None:
    target_settings = dict(restore._ADBLOCK_DEFAULT_SETTINGS)
    target_settings["enabled"] = target_enabled
    conn = _CompatRestoreConn(target_settings)

    result = restore.restore_recovery_bundle(
        conn,
        _bundle(restored_enabled),
        "edge-01",
        now_ts=NOW,
    )

    assert result.status == "adopted"
    assert not [
        params
        for sql, params in conn.ops
        if sql.startswith("INSERT INTO adblock_settings") and params[0] == "enabled"
    ]
    assert conn.adblock_proxy_meta["edge-01", "enabled"] == restored_enabled


def test_modified_bootstrap_settings_are_not_fresh() -> None:
    target_settings = dict(restore._ADBLOCK_DEFAULT_SETTINGS)
    target_settings["cache_ttl"] = "900"
    conn = _CompatRestoreConn(target_settings)

    result = restore.restore_recovery_bundle(
        conn,
        _bundle("1"),
        "edge-01",
        now_ts=NOW,
    )

    assert result.status == "not_eligible"
    assert result.reason == "adblock settings are not canonical schema defaults"
    assert not any(
        sql.startswith(("START TRANSACTION", "DELETE", "INSERT"))
        for sql, _params in conn.ops
    )


@pytest.mark.parametrize("legacy_enabled", ["0", "1"])
def test_legacy_restore_recapture_restore_preserves_explicit_enablement(
    legacy_enabled: str,
) -> None:
    from services import proxy_recovery_db

    first = _CompatRestoreConn(dict(restore._ADBLOCK_DEFAULT_SETTINGS))
    restored = restore.restore_recovery_bundle(
        first,
        _bundle(legacy_enabled),
        "edge-01",
        now_ts=NOW,
    )
    assert restored.status == "adopted"
    assert first.adblock_proxy_meta["edge-01", "enabled"] == legacy_enabled

    captured = proxy_recovery_db.capture_recovery_state(
        first,
        "edge-01",
        now_ts=NOW + 1,
    )
    captured_meta = next(
        table for table in captured.tables if table.name == "adblock_proxy_meta"
    )
    assert captured_meta.rows == (
        {"proxy_id": "edge-01", "k": "enabled", "v": legacy_enabled},
    )
    recaptured_bundle = proxy_recovery.RecoveryBundle(
        format_version=proxy_recovery.FORMAT_VERSION,
        proxy_id="edge-01",
        source_control_plane_id=TARGET_ID,
        created_ts=captured.created_ts,
        schema_version=proxy_recovery.DATA_SCHEMA_VERSION,
        tables=captured.tables,
        integrity=proxy_recovery.IntegrityMetadata(
            "c" * 64,
            proxy_recovery.MAC_ALGORITHM,
            "d" * 64,
        ),
    )
    second = _CompatRestoreConn(
        dict(restore._ADBLOCK_DEFAULT_SETTINGS),
        control_plane_id=SECOND_TARGET_ID,
    )
    rerestored = restore.restore_recovery_bundle(
        second,
        recaptured_bundle,
        "edge-01",
        now_ts=NOW + 2,
    )

    assert rerestored.status == "adopted"
    assert second.adblock_proxy_meta["edge-01", "enabled"] == legacy_enabled
