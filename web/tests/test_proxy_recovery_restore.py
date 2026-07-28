from __future__ import annotations

# ruff: noqa: I001

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
NOW = 1_700_000_000


class _Result:
    def __init__(self, rows: list[Any] | None = None, *, lastrowid: int = 0) -> None:
        self._rows = rows or []
        self.lastrowid = lastrowid
        self.rowcount = len(self._rows)

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)


class _StrictRestoreConn:
    def __init__(
        self,
        *,
        target_identity: str | None = TARGET_ID,
        adoption_marker: bool = False,
        adoption_marker_target: str | None = None,
        nonfresh_tables: set[str] | None = None,
        lifecycle_status: str | None = "active",
        lock_acquired: bool = True,
        fail_on_sql: str = "",
        schema_defaults: bool = False,
    ) -> None:
        self.target_identity = target_identity
        self.adoption_marker = adoption_marker
        self.adoption_marker_target = adoption_marker_target or target_identity
        self.nonfresh_tables = nonfresh_tables or set()
        self.lifecycle_status = lifecycle_status
        self.lock_acquired = lock_acquired
        self.fail_on_sql = fail_on_sql
        self.schema_defaults = schema_defaults
        self.ops: list[tuple[str, tuple[Any, ...]]] = []
        self.commits = 0
        self.rollbacks = 0
        self._next_id = 100

    def execute(self, sql: str, params=()):
        text = _sql(sql)
        params = tuple(params or ())
        self.ops.append((text, params))
        if self.fail_on_sql and self.fail_on_sql in text:
            msg = f"simulated failure for {self.fail_on_sql}"
            raise RuntimeError(msg)
        if text.startswith("CREATE TABLE IF NOT EXISTS proxy_lifecycle_tombstones"):
            return _Result()
        if text.startswith("SELECT control_plane_id FROM control_plane_identity"):
            if self.target_identity is None:
                return _Result()
            return _Result([{"control_plane_id": self.target_identity}])
        if text.startswith("SELECT source_control_plane_id, target_control_plane_id") and "FROM proxy_recovery_adoptions" in text:
            if not self.adoption_marker or params[1] != self.adoption_marker_target:
                return _Result()
            return _Result(
                [
                    {
                        "source_control_plane_id": SOURCE_ID,
                        "target_control_plane_id": self.adoption_marker_target,
                        "status": "adopted",
                    },
                ],
            )
        if text.startswith("SELECT target_control_plane_id FROM proxy_recovery_adoptions"):
            if not self.adoption_marker:
                return _Result()
            return _Result([{"target_control_plane_id": self.adoption_marker_target}])
        if text.startswith("SELECT action, target_proxy_id FROM proxy_lifecycle_tombstones"):
            return _Result()
        if text.startswith("SELECT status FROM proxy_instances"):
            if self.lifecycle_status is None:
                return _Result()
            return _Result([{"status": self.lifecycle_status}])
        if text.startswith("SELECT GET_LOCK"):
            return _Result([{"acquired": 1 if self.lock_acquired else 0}])
        if text.startswith("DO RELEASE_LOCK"):
            return _Result()
        if text.startswith("SELECT `key`, url, enabled FROM adblock_lists"):
            if "adblock_lists" in self.nonfresh_tables:
                return _Result([{"key": "custom", "url": "https://custom.invalid/list.txt", "enabled": 1}])
            if self.schema_defaults:
                return _Result(
                    [
                        {"key": key, "url": url, "enabled": 0}
                        for key, url in sorted(restore._ADBLOCK_DEFAULT_LISTS.items())
                    ],
                )
            return _Result()
        if text.startswith("SELECT k, v FROM adblock_settings"):
            if "adblock_settings" in self.nonfresh_tables:
                return _Result([{"k": "enabled", "v": "0"}])
            if self.schema_defaults:
                return _Result([{"k": key, "v": value} for key, value in sorted(restore._ADBLOCK_DEFAULT_SETTINGS.items())])
            return _Result()
        if text.startswith("SELECT enabled, certfile, keyfile, san_tokens FROM admin_ui_https_settings"):
            if "admin_ui_https_settings" in self.nonfresh_tables:
                return _Result([{"enabled": 1, "certfile": "/cert", "keyfile": "/key", "san_tokens": "dns:admin"}])
            if self.schema_defaults:
                return _Result([{"enabled": 0, "certfile": "", "keyfile": "", "san_tokens": ""}])
            return _Result()
        if text.startswith("SELECT retention_days FROM observability_settings"):
            if "observability_settings" in self.nonfresh_tables:
                return _Result([{"retention_days": 90}])
            if self.schema_defaults:
                return _Result([{"retention_days": restore._OBSERVABILITY_DEFAULT_RETENTION_DAYS}])
            return _Result()
        if text.startswith("SELECT provider, enabled, server_urls"):
            if self.schema_defaults and "FROM directory_auth_profiles" in text:
                return _Result(list(restore._DIRECTORY_DEFAULT_ROWS))
            return _Result()
        if text.startswith("SELECT provider, enabled, metadata_url"):
            if self.schema_defaults:
                return _Result([dict(restore._SAML_DEFAULT_ROW)])
            return _Result()
        if text.startswith("SELECT direct_enabled FROM pac_proxy_chain_settings"):
            if "pac_proxy_chain_settings" in self.nonfresh_tables:
                return _Result([{"direct_enabled": 0}])
            if self.schema_defaults:
                return _Result([{"direct_enabled": 1}])
            return _Result()
        if text.startswith("SELECT k, v FROM webfilter_settings"):
            if "webfilter_settings" in self.nonfresh_tables:
                return _Result([{"k": "enabled", "v": "1"}])
            if self.schema_defaults:
                return _Result([{"k": key, "v": value} for key, value in sorted(restore._WEBFILTER_DEFAULT_SETTINGS.items())])
            return _Result()
        if text.startswith("SELECT COUNT(*) AS count"):
            return _Result([{"count": 1 if _probe_table(text) in self.nonfresh_tables else 0}])
        if text == "START TRANSACTION":
            return _Result()
        if text.startswith("INSERT INTO pac_profiles"):
            self._next_id += 1
            return _Result(lastrowid=self._next_id)
        return _Result()

    def executemany(self, sql: str, seq_of_params):
        text = _sql(sql)
        if self.fail_on_sql and self.fail_on_sql in text:
            msg = f"simulated failure for {self.fail_on_sql}"
            raise RuntimeError(msg)
        for params in seq_of_params:
            self.ops.append((text, tuple(params)))
        return _Result()

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1


def _sql(sql: str) -> str:
    return " ".join(str(sql).split())


@pytest.fixture(autouse=True)
def _metadata_tables_available(monkeypatch) -> None:
    monkeypatch.setattr(
        "services.proxy_write_guard.table_exists",
        lambda _conn, name: name in {"proxy_instances", "proxy_lifecycle_tombstones"},
    )


def _probe_table(sql: str) -> str:
    for table in restore._EXPECTED_TABLE_ORDER:
        if f"FROM {table}" in sql or f"JOIN {table}" in sql:
            return table
    return ""


def _bundle(*, proxy_id: str = "edge-01", source_id: str = SOURCE_ID, overrides: dict[str, tuple[dict[str, Any], ...]] | None = None) -> proxy_recovery.RecoveryBundle:
    rows = _base_rows(proxy_id)
    for table, table_rows in (overrides or {}).items():
        rows[table] = table_rows
    tables = tuple(
        proxy_recovery.RecoveryTablePayload(name, rows[name])
        for name in restore._EXPECTED_TABLE_ORDER
    )
    return proxy_recovery.RecoveryBundle(
        format_version=proxy_recovery.FORMAT_VERSION,
        proxy_id=proxy_id,
        source_control_plane_id=source_id,
        created_ts="2026-01-01T00:00:00Z",
        schema_version=proxy_recovery.DATA_SCHEMA_VERSION,
        tables=tables,
        integrity=proxy_recovery.IntegrityMetadata("a" * 64, proxy_recovery.MAC_ALGORITHM, "b" * 64),
    )


def _base_rows(proxy_id: str) -> dict[str, tuple[dict[str, Any], ...]]:
    sha = "a" * 64
    cert_sha = "b" * 64
    cfg_sha = "c" * 64
    return {
        "adblock_lists": ({"key": "easylist", "url": "https://example.invalid/easy.txt", "enabled": 1},),
        "adblock_settings": ({"k": "enabled", "v": "1"},),
        "adblock_artifact_revisions": (
            {
                "artifact_sha256": sha,
                "archive_blob": b"\x00exact-archive-bytes\xff",
                "report_json": "{}",
                "settings_version": 2,
                "enabled_lists_json": "[\"easylist\"]",
            },
        ),
        "certificate_bundle_revisions": (
            {
                "bundle_sha256": sha,
                "cert_sha256": cert_sha,
                "cert_pem": "CERT",
                "key_pem": "KEY",
                "chain_pem": "CHAIN",
            },
        ),
        "admin_ui_https_settings": (
            {"enabled": 1, "certfile": "/cert.pem", "keyfile": "/key.pem", "san_tokens": "dns:proxy"},
        ),
        "observability_settings": ({"retention_days": 90},),
        "directory_auth_profiles": (
            {
                "provider": "ldap",
                "enabled": 1,
                "server_urls": "ldaps://ldap.example.invalid",
                "use_starttls": 0,
                "verify_tls": 1,
                "ca_bundle": "CA",
                "bind_dn": "cn=bind",
                "bind_password": "secret",
                "base_dn": "dc=example,dc=invalid",
                "user_search_base": "",
                "user_filter": "(uid={username})",
                "user_attribute": "uid",
                "group_search_base": "",
                "group_filter": "",
                "required_admin_group": "admins",
                "timeout_seconds": 5,
            },
        ),
        "saml_auth_profiles": (
            {
                "provider": "saml",
                "enabled": 1,
                "metadata_url": "https://idp.example.invalid/metadata",
                "require_https": 1,
                "verify_tls": 1,
                "ca_bundle": "CA",
                "timeout_seconds": 10,
                "max_metadata_bytes": 1024,
                "raw_metadata_xml": "<xml />",
                "public_base_url": "https://proxy.example.invalid",
                "username_attribute": "NameID",
                "groups_attribute": "groups",
                "required_group": "admins",
            },
        ),
        "proxy_config_revisions": (
            {"proxy_id": proxy_id, "config_sha256": cfg_sha, "config_text": "http_port 3128"},
        ),
        "pac_profiles": (
            {"source_profile_id": 42, "proxy_id": proxy_id, "name": "default", "client_cidr": "10.0.0.0/24"},
        ),
        "pac_direct_domains": ({"source_profile_id": 42, "domain": "direct.example"},),
        "pac_direct_dst_nets": ({"source_profile_id": 42, "cidr": "10.10.0.0/16"},),
        "pac_backup_proxies": ({"proxy_id": proxy_id, "proxy_host": "backup", "proxy_port": 3128, "position": 1},),
        "pac_proxy_chain_settings": ({"proxy_id": proxy_id, "direct_enabled": 1},),
        "policy_exceptions": (
            {
                "proxy_id": proxy_id,
                "block_type": "webfilter",
                "client_ip": "10.0.0.5",
                "domain": "allowed.example",
                "category": "work",
                "admin_note": "temporary",
                "expires_ts": NOW + 3600,
            },
        ),
        "sslfilter_domains": ({"proxy_id": proxy_id, "policy": "splice", "domain": "bank.example"},),
        "sslfilter_src_nets": ({"proxy_id": proxy_id, "policy": "bump", "cidr": "192.0.2.0/24"},),
        "sslfilter_settings": ({"proxy_id": proxy_id, "key": "inspection_enabled", "value": "1"},),
        "webfilter_settings": (
            {"proxy_id": proxy_id, "k": "enabled", "v": "1"},
            {"proxy_id": proxy_id, "k": "blocked_categories", "v": "ads"},
        ),
        "webfilter_whitelist": ({"proxy_id": proxy_id, "pattern": "*.trusted.example"},),
        "adblock_proxy_meta": (),
        "observability_report_schedules": (
            {
                "proxy_id": proxy_id,
                "enabled": 1,
                "name": "daily",
                "cadence": "daily",
                "recipients": "ops@example.invalid",
                "pane": "reports",
                "report_format": "csv",
                "privacy": 1,
                "window_seconds": 86400,
            },
        ),
    }


def test_successful_full_restore_order_remaps_pac_preserves_bytes_and_marks_adoption() -> None:
    conn = _StrictRestoreConn()

    result = restore.restore_recovery_bundle(conn, _bundle(), "EDGE-01", now_ts=NOW)

    assert result.status == "adopted"
    assert result.proxy_id == "edge-01"
    assert result.target_proxy_id == "edge-01"
    assert result.source_control_plane_id == SOURCE_ID
    assert result.target_control_plane_id == TARGET_ID
    assert result.bundle_content_sha256 == "a" * 64
    assert result.adopted_ts == NOW
    assert conn.rollbacks == 0
    assert conn.commits == 1

    sqls = [sql for sql, _params in conn.ops]
    assert "START TRANSACTION" in sqls
    start_index = sqls.index("START TRANSACTION")
    mutation_sqls = sqls[start_index + 1 :]
    assert mutation_sqls[0].startswith("SELECT control_plane_id FROM control_plane_identity")
    assert any(sql.startswith("DELETE FROM adblock_lists") for sql in mutation_sqls)
    assert any(sql.startswith("INSERT INTO adblock_artifact_revisions") for sql in mutation_sqls)
    assert any(sql.startswith("INSERT INTO proxy_recovery_adoptions") for sql in mutation_sqls)
    assert any(params and params[0] == 101 and params[1] == "direct.example" for _sql_text, params in conn.ops)
    assert any(b"\x00exact-archive-bytes\xff" in params for _sql_text, params in conn.ops)
    assert not any("UPDATE control_plane_identity" in sql for sql in sqls)
    assert sqls[-1].startswith("DO RELEASE_LOCK")


def test_identity_mismatch_same_identity_and_missing_identity_fail_closed() -> None:
    same = restore.restore_recovery_bundle(_StrictRestoreConn(target_identity=SOURCE_ID), _bundle(), "edge-01", now_ts=NOW)
    assert same.status == "same_control_plane"
    assert same.restored_rows == 0
    with pytest.raises(restore.ProxyRecoveryRestoreError, match="missing"):
        restore.restore_recovery_bundle(_StrictRestoreConn(target_identity=None), _bundle(), "edge-01", now_ts=NOW)
    with pytest.raises(restore.ProxyRecoveryRestoreError, match="invalid"):
        restore.restore_recovery_bundle(_StrictRestoreConn(target_identity="not-a-uuid"), _bundle(), "edge-01", now_ts=NOW)


def test_source_target_proxy_mismatch_rejects_before_database_access() -> None:
    conn = _StrictRestoreConn()
    with pytest.raises(restore.ProxyRecoveryRestoreError, match="proxy id"):
        restore.restore_recovery_bundle(conn, _bundle(proxy_id="other"), "edge-01", now_ts=NOW)
    assert conn.ops == []


def test_nonfresh_target_or_existing_adoption_marker_rejects_without_mutation() -> None:
    conn = _StrictRestoreConn(nonfresh_tables={"webfilter_settings"})
    result = restore.restore_recovery_bundle(conn, _bundle(), "edge-01", now_ts=NOW)
    assert result.status == "not_eligible"
    assert "webfilter" in result.reason
    assert not any(sql.startswith(("START TRANSACTION", "DELETE", "INSERT")) for sql, _params in conn.ops)

    marked = _StrictRestoreConn(adoption_marker=True, nonfresh_tables={"webfilter_settings"})
    marked_result = restore.restore_recovery_bundle(marked, _bundle(), "edge-01", now_ts=NOW)
    assert marked_result.status == "already_adopted"
    assert not any(sql.startswith(("START TRANSACTION", "DELETE", "INSERT")) for sql, _params in marked.ops)

    ambiguous = _StrictRestoreConn(adoption_marker=True, adoption_marker_target="323e4567-e89b-42d3-a456-426614174000")
    with pytest.raises(restore.ProxyRecoveryRestoreError, match="ambiguous"):
        restore.restore_recovery_bundle(ambiguous, _bundle(), "edge-01", now_ts=NOW)


def test_different_fresh_target_can_independently_adopt() -> None:
    target = _StrictRestoreConn(target_identity="323e4567-e89b-42d3-a456-426614174000")
    result = restore.restore_recovery_bundle(target, _bundle(), "edge-01", now_ts=NOW)
    assert result.status == "adopted"
    assert result.target_control_plane_id == "323e4567-e89b-42d3-a456-426614174000"


def test_known_schema_defaults_are_fresh_and_replaced() -> None:
    conn = _StrictRestoreConn(schema_defaults=True)
    result = restore.restore_recovery_bundle(conn, _bundle(), "edge-01", now_ts=NOW)
    assert result.status == "adopted"
    assert any(sql.startswith("DELETE FROM directory_auth_profiles") for sql, _params in conn.ops)
    assert any(sql.startswith("DELETE FROM saml_auth_profiles") for sql, _params in conn.ops)
    assert any(sql.startswith("DELETE FROM webfilter_settings") for sql, _params in conn.ops)


def test_lifecycle_rejection_and_lock_failure_fail_closed() -> None:
    removed = _StrictRestoreConn(lifecycle_status="removed")
    with pytest.raises(Exception, match=r"status.*removed"):
        restore.restore_recovery_bundle(removed, _bundle(), "edge-01", now_ts=NOW)
    assert not any(sql.startswith("START TRANSACTION") for sql, _params in removed.ops)

    locked = _StrictRestoreConn(lock_acquired=False)
    with pytest.raises(Exception, match="lock"):
        restore.restore_recovery_bundle(locked, _bundle(), "edge-01", now_ts=NOW)
    assert any(sql.startswith("SELECT GET_LOCK") for sql, _params in locked.ops)
    assert not any(sql.startswith("START TRANSACTION") for sql, _params in locked.ops)


def test_malformed_columns_types_duplicates_pac_orphans_and_active_cardinality_reject_before_writes() -> None:
    cases = [
        {"adblock_lists": ({"key": "easylist", "url": "u", "enabled": 1, "extra": "x"},)},
        {"adblock_lists": ({"key": "easylist", "url": "u", "enabled": "1"},)},
        {
            "webfilter_settings": (
                {"proxy_id": "edge-01", "k": "enabled", "v": "1"},
                {"proxy_id": "edge-01", "k": "enabled", "v": "0"},
            ),
        },
        {"pac_direct_domains": ({"source_profile_id": 99, "domain": "orphan.example"},)},
        {
            "proxy_config_revisions": (
                {"proxy_id": "edge-01", "config_sha256": "c" * 64, "config_text": "one"},
                {"proxy_id": "edge-01", "config_sha256": "d" * 64, "config_text": "two"},
            ),
        },
        {
            "policy_exceptions": (
                {
                    "proxy_id": "edge-01",
                    "block_type": "webfilter",
                    "client_ip": "10.0.0.5",
                    "domain": "allowed.example",
                    "category": "work",
                    "admin_note": "expired",
                    "expires_ts": NOW - 1,
                },
            ),
        },
        {"adblock_proxy_meta": ({"proxy_id": "edge-01", "k": "source-only", "v": "excluded"},)},
    ]
    for overrides in cases:
        conn = _StrictRestoreConn()
        with pytest.raises(restore.ProxyRecoveryRestoreError):
            restore.restore_recovery_bundle(conn, _bundle(overrides=overrides), "edge-01", now_ts=NOW)
        assert conn.ops == []


def test_rollback_on_mid_write_failure_and_release_lock() -> None:
    conn = _StrictRestoreConn(fail_on_sql="INSERT INTO policy_exceptions")

    with pytest.raises(RuntimeError, match="simulated failure"):
        restore.restore_recovery_bundle(conn, _bundle(), "edge-01", now_ts=NOW)

    assert conn.rollbacks == 1
    assert conn.commits == 0
    assert any(sql.startswith("START TRANSACTION") for sql, _params in conn.ops)
    assert conn.ops[-1][0].startswith("DO RELEASE_LOCK")


def test_restore_contract_has_no_select_star_or_bundle_derived_tables() -> None:
    restore.validate_restore_contract()
    module_sql_values = [
        restore._ADOPTION_MARKER_PAIR_SELECT_SQL,
        restore._ADOPTION_MARKER_PROXY_SELECT_SQL,
        restore._ADOPTION_MARKER_INSERT_SQL,
        *restore._DELETE_DEFAULTS_SQL,
        *restore._DELETE_PROXY_DEFAULTS_SQL,
    ]
    assert all("SELECT *" not in _sql(sql).upper() for sql in module_sql_values)
    assert tuple(restore._EXPECTED_TABLE_COLUMNS) == tuple(
        spec.table_name for spec in proxy_recovery.recovery_registry()
    )
