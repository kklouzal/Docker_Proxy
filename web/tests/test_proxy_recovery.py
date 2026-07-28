from __future__ import annotations

# ruff: noqa: E701,E702,PT018,RUF031,TRY003,EM102
import json
import os
import stat
import tempfile
from copy import deepcopy
from pathlib import Path

import pytest

from web.services import proxy_recovery as recovery

_SOURCE_CONTROL_PLANE_ID = "123e4567-e89b-42d3-a456-426614174000"
_OTHER_CONTROL_PLANE_ID = "123e4567-e89b-42d3-a456-426614174001"


def _write_recovery_bundle(*args, **kwargs):
    return recovery.write_recovery_bundle(
        *args,
        source_control_plane_id=_SOURCE_CONTROL_PLANE_ID,
        **kwargs,
    )


def _create_recovery_bundle(*args, **kwargs):
    return recovery.create_recovery_bundle(
        *args,
        source_control_plane_id=_SOURCE_CONTROL_PLANE_ID,
        **kwargs,
    )


def _rows() -> dict[str, list[dict[str, object]]]:
    return {
        "adblock_settings": [
            {
                "id": 1,
                "enabled": True,
                "marker": b"\x00proxy-bytes\xff",
                "nested": {"payload": bytearray(b"nested")},
            }
        ],
        "pac_profiles": [{"proxy_id": "edge-01", "name": "default"}],
    }


def test_registry_is_immutable_ordered_and_documents_exclusions() -> None:
    registry = recovery.recovery_registry()
    table_names = {spec.table_name for spec in registry}
    required = {
        "proxy_config_revisions",
        "pac_profiles",
        "pac_direct_domains",
        "pac_direct_dst_nets",
        "pac_backup_proxies",
        "pac_proxy_chain_settings",
        "policy_exceptions",
        "sslfilter_domains",
        "sslfilter_src_nets",
        "sslfilter_settings",
        "webfilter_settings",
        "webfilter_whitelist",
        "adblock_proxy_meta",
        "observability_report_schedules",
        "adblock_lists",
        "adblock_settings",
        "adblock_artifact_revisions",
        "certificate_bundle_revisions",
        "admin_ui_https_settings",
        "observability_settings",
        "directory_auth_profiles",
        "saml_auth_profiles",
    }
    excluded = {
        "users",
        "sessions",
        "proxy_registry",
        "schema_migrations",
        "operations",
        "audit_log",
        "diagnostic_events",
        "policy_request_history",
        "safe_browsing_cache",
        "webcat_cache",
    }

    assert registry is recovery.TABLE_SCOPE_REGISTRY
    assert table_names == required
    assert table_names.isdisjoint(excluded)
    assert tuple(spec.dependency_order for spec in registry) == tuple(
        sorted(spec.dependency_order for spec in registry)
    )
    assert len({spec.dependency_order for spec in registry}) == len(registry)
    assert recovery.EXCLUDED_RECOVERY_RATIONALE[
        "operations_audit_diagnostics_stats_events"
    ]
    assert (
        "revoked_or_expired_policy_exceptions" in recovery.EXCLUDED_RECOVERY_RATIONALE
    )
    assert any(spec.secrets_expected for spec in registry)
    assert any(spec.blobs_expected for spec in registry)

    with pytest.raises(TypeError):
        recovery.TABLE_SCOPE_REGISTRY[0] = registry[0]  # type: ignore[index]
    with pytest.raises(TypeError):
        recovery.EXCLUDED_RECOVERY_RATIONALE["new_scope"] = "nope"  # type: ignore[index]


def test_canonical_json_round_trip_includes_bytes_base64_and_hmac(
    tmp_path: Path,
) -> None:
    bundle_path = _write_recovery_bundle(
        " Edge-01 ",
        _rows(),
        created_ts="2026-07-28T19:27:00Z",
        recovery_dir=tmp_path,
    )

    key_path = recovery.key_path_for_proxy("edge-01", tmp_path)
    assert bundle_path == tmp_path / "edge-01.bundle.json"
    assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o700
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(bundle_path.stat().st_mode) == 0o600

    raw = bundle_path.read_bytes()
    assert raw.endswith(b"\n")
    assert raw == recovery.serialize_recovery_bundle(
        recovery.read_recovery_bundle("edge-01", recovery_dir=tmp_path)
    )

    envelope = json.loads(raw)
    assert list(envelope) == sorted(envelope)
    assert envelope["format_version"] == 2
    assert envelope["source_control_plane_id"] == _SOURCE_CONTROL_PLANE_ID
    marker = envelope["tables"][0]["rows"][0]["marker"]
    assert marker == {
        "__proxy_recovery_type__": "bytes/base64",
        "data": "AHByb3h5LWJ5dGVz/w==",
    }
    assert envelope["integrity"]["mac_alg"] == "HMAC-SHA256"

    bundle = recovery.read_recovery_bundle("edge-01", recovery_dir=tmp_path)
    assert [table.name for table in bundle.tables] == [
        "adblock_settings",
        "pac_profiles",
    ]
    assert bundle.tables[0].rows[0]["marker"] == b"\x00proxy-bytes\xff"
    assert bundle.tables[0].rows[0]["nested"] == {"payload": b"nested"}
    assert bundle.source_control_plane_id == _SOURCE_CONTROL_PLANE_ID

    with pytest.raises(recovery.ProxyRecoveryError, match="control plane identity"):
        recovery.read_recovery_bundle(
            "edge-01",
            recovery_dir=tmp_path,
            expected_source_control_plane_id=_OTHER_CONTROL_PLANE_ID,
        )


def test_bundle_validation_rejects_tamper_wrong_proxy_duplicates_and_reserved_keys(
    tmp_path: Path,
) -> None:
    path = _write_recovery_bundle(
        "edge-01",
        _rows(),
        created_ts="2026-07-28T19:27:00Z",
        recovery_dir=tmp_path,
    )
    raw = path.read_bytes()

    tampered = raw.replace(b"default", b"evil")
    with pytest.raises(
        recovery.ProxyRecoveryError, match=r"digest mismatch|MAC mismatch"
    ):
        recovery.parse_recovery_bundle(
            tampered,
            expected_proxy_id="edge-01",
            key=recovery.read_signing_key("edge-01", tmp_path),
        )

    with pytest.raises(recovery.ProxyRecoveryError, match="does not match"):
        recovery.parse_recovery_bundle(
            raw,
            expected_proxy_id="other-proxy",
            key=recovery.read_signing_key("edge-01", tmp_path),
        )

    wrong_source = json.loads(raw)
    wrong_source["source_control_plane_id"] = _OTHER_CONTROL_PLANE_ID
    wrong_source_raw = json.dumps(
        wrong_source,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    with pytest.raises(recovery.ProxyRecoveryError, match="control plane identity"):
        recovery.parse_recovery_bundle(
            wrong_source_raw,
            expected_proxy_id="edge-01",
            expected_source_control_plane_id=_SOURCE_CONTROL_PLANE_ID,
            key=recovery.read_signing_key("edge-01", tmp_path),
        )

    malformed_source = json.loads(raw)
    malformed_source["source_control_plane_id"] = "not-a-control-plane-id"
    malformed_source_raw = json.dumps(
        malformed_source,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    with pytest.raises(recovery.ProxyRecoveryError, match="control plane identity"):
        recovery.parse_recovery_bundle(
            malformed_source_raw,
            expected_proxy_id="edge-01",
            key=recovery.read_signing_key("edge-01", tmp_path),
        )

    missing_source = json.loads(raw)
    del missing_source["source_control_plane_id"]
    missing_source_raw = json.dumps(
        missing_source,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    with pytest.raises(recovery.ProxyRecoveryError, match="envelope"):
        recovery.parse_recovery_bundle(
            missing_source_raw,
            expected_proxy_id="edge-01",
            key=recovery.read_signing_key("edge-01", tmp_path),
        )

    duplicate_json = b'{"format_version":1,"format_version":1}'
    with pytest.raises(recovery.ProxyRecoveryError, match="duplicate JSON key"):
        recovery.parse_recovery_bundle(
            duplicate_json,
            expected_proxy_id="edge-01",
            key=b"0" * recovery.KEY_BYTES,
        )

    with pytest.raises(
        recovery.ProxyRecoveryError, match="reserved recovery encoding key"
    ):
        _create_recovery_bundle(
            "edge-01",
            {"adblock_settings": [{"__proxy_recovery_type__": "bytes/base64"}]},
            recovery_dir=tmp_path,
        )


def test_future_version_malformed_encoding_and_oversized_write_rejected(
    tmp_path: Path,
) -> None:
    path = _write_recovery_bundle(
        "edge-01",
        _rows(),
        created_ts="2026-07-28T19:27:00Z",
        recovery_dir=tmp_path,
    )
    envelope = json.loads(path.read_bytes())
    envelope["format_version"] = recovery.FORMAT_VERSION + 1
    future_raw = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(recovery.ProxyRecoveryError, match="future"):
        recovery.parse_recovery_bundle(
            future_raw,
            expected_proxy_id="edge-01",
            key=recovery.read_signing_key("edge-01", tmp_path),
        )

    envelope = json.loads(path.read_bytes())
    envelope["tables"][0]["rows"][0]["marker"] = {
        "__proxy_recovery_type__": "bytes/base64",
        "data": "not base64!",
    }
    malformed_raw = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(recovery.ProxyRecoveryError, match="base64"):
        recovery.parse_recovery_bundle(
            malformed_raw,
            expected_proxy_id="edge-01",
            key=recovery.read_signing_key("edge-01", tmp_path),
        )

    with pytest.raises(recovery.ProxyRecoveryError, match="exceeds maximum size"):
        _write_recovery_bundle(
            "edge-01",
            {"adblock_settings": [{"large": "x" * 200}]},
            recovery_dir=tmp_path,
            max_bundle_bytes=64,
        )


def test_scope_and_value_validation_errors(tmp_path: Path) -> None:
    with pytest.raises(recovery.ProxyRecoveryError, match="invalid proxy id"):
        _create_recovery_bundle("../bad", {}, recovery_dir=tmp_path)
    with pytest.raises(recovery.ProxyRecoveryError, match="not in recovery scope"):
        _create_recovery_bundle(
            "edge-01",
            {"audit_log": []},
            recovery_dir=tmp_path,
        )
    with pytest.raises(recovery.ProxyRecoveryError, match="duplicate recovery table"):
        _create_recovery_bundle(
            "edge-01",
            [
                recovery.RecoveryTablePayload("adblock_settings", ()),
                recovery.RecoveryTablePayload("adblock_settings", ()),
            ],
            recovery_dir=tmp_path,
        )
    with pytest.raises(
        recovery.ProxyRecoveryError, match="unsupported recovery value type"
    ):
        _create_recovery_bundle(
            "edge-01",
            {"adblock_settings": [{"bad": object()}]},
            recovery_dir=tmp_path,
        )


def test_private_storage_refuses_symlinks_non_regular_and_bound_reads(
    tmp_path: Path,
) -> None:
    key_path = recovery.key_path_for_proxy("edge-01", tmp_path)
    key_path.symlink_to(tmp_path / "elsewhere")
    with pytest.raises(recovery.ProxyRecoveryError, match="symlink"):
        _write_recovery_bundle("edge-01", _rows(), recovery_dir=tmp_path)
    key_path.unlink()

    _write_recovery_bundle("edge-01", _rows(), recovery_dir=tmp_path)
    bundle_path = recovery.bundle_path_for_proxy("edge-01", tmp_path)
    key_path = recovery.key_path_for_proxy("edge-01", tmp_path)

    with pytest.raises(recovery.ProxyRecoveryError, match="exceeds maximum size"):
        recovery.read_recovery_bundle(
            "edge-01",
            recovery_dir=tmp_path,
            max_bundle_bytes=bundle_path.stat().st_size - 1,
        )

    bundle_path.unlink()
    bundle_path.symlink_to(key_path)
    with pytest.raises(recovery.ProxyRecoveryError, match="symlink"):
        recovery.read_recovery_bundle("edge-01", recovery_dir=tmp_path)

    bundle_path.unlink()
    bundle_path.mkdir()
    with pytest.raises(recovery.ProxyRecoveryError, match="regular file"):
        recovery.read_recovery_bundle("edge-01", recovery_dir=tmp_path)


def test_atomic_replacement_preserves_previous_bundle_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_recovery_bundle(
        "edge-01",
        {"adblock_settings": [{"enabled": True}]},
        recovery_dir=tmp_path,
    )
    original = path.read_bytes()

    def fail_replace(_self: Path, _dst: Path) -> Path:
        msg = "simulated replace failure"
        raise OSError(msg)

    monkeypatch.setattr(recovery.Path, "replace", fail_replace)
    with pytest.raises(OSError, match="simulated replace failure"):
        _write_recovery_bundle(
            "edge-01",
            {"adblock_settings": [{"enabled": False}]},
            recovery_dir=tmp_path,
        )

    assert path.read_bytes() == original
    assert not list(tmp_path.glob("*.tmp"))


def test_recovery_dir_env_and_private_dir_symlink_refusal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configured = tmp_path / "configured"
    monkeypatch.setenv(recovery.RECOVERY_DIR_ENV, str(configured))
    _write_recovery_bundle("edge-01", {"adblock_settings": []})
    assert (configured / "edge-01.bundle.json").is_file()

    target = tmp_path / "target"
    target.mkdir()
    symlink_root = tmp_path / "symlink-root"
    symlink_root.symlink_to(target, target_is_directory=True)
    with pytest.raises(recovery.ProxyRecoveryError, match="private directory"):
        _write_recovery_bundle(
            "edge-01",
            {"adblock_settings": []},
            recovery_dir=symlink_root,
        )


def test_safe_path_names_and_key_creation_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert recovery.bundle_path_for_proxy("EDGE.Proxy_01", tmp_path) == (
        tmp_path / "edge.proxy_01.bundle.json"
    )
    assert recovery.key_path_for_proxy("EDGE.Proxy_01", tmp_path) == (
        tmp_path / "edge.proxy_01.hmac.key"
    )
    for bad_id in ("../edge", "edge/one", "", ".hidden", "edge..one", "edge one"):
        with pytest.raises(recovery.ProxyRecoveryError):
            recovery.bundle_path_for_proxy(bad_id, tmp_path)

    root = tmp_path
    existing = b"k" * recovery.KEY_BYTES
    key_path = recovery.key_path_for_proxy("edge-01", root)
    root.mkdir(exist_ok=True)

    real_link = os.link

    def fake_link(src: Path, dst: Path) -> None:
        key_path.write_bytes(existing)
        raise FileExistsError

    monkeypatch.setattr(os, "link", fake_link)
    try:
        assert recovery.get_or_create_signing_key("edge-01", root) == existing
    finally:
        monkeypatch.setattr(os, "link", real_link)


def _full_restore_rows(proxy_id: str = "edge-01") -> dict[str, list[dict[str, object]]]:
    return {
        "adblock_lists": [{"key": "easylist", "url": "https://source.invalid/easy.txt", "enabled": 1}],
        "adblock_settings": [{"k": "enabled", "v": "0"}],
        "adblock_artifact_revisions": [{"artifact_sha256": "a" * 64, "archive_blob": b"artifact-bytes\x00", "report_json": '{"ok":true}', "settings_version": 7, "enabled_lists_json": '["easylist"]'}],
        "certificate_bundle_revisions": [{"bundle_sha256": "b" * 64, "cert_sha256": "c" * 64, "cert_pem": "CERT", "key_pem": "KEY", "chain_pem": "CHAIN"}],
        "admin_ui_https_settings": [{"enabled": 1, "certfile": "/cert", "keyfile": "/key", "san_tokens": "dns:admin"}],
        "observability_settings": [{"retention_days": 45}],
        "directory_auth_profiles": [{"provider": "ldap", "enabled": 1, "server_urls": "ldaps://ldap.internal:636", "use_starttls": 0, "verify_tls": 1, "ca_bundle": "CA", "bind_dn": "cn=bind", "bind_password": "secret", "base_dn": "dc=example", "user_search_base": "ou=people", "user_filter": "(uid={username})", "user_attribute": "uid", "group_search_base": "ou=groups", "group_filter": "(member={user_dn})", "required_admin_group": "cn=admins", "timeout_seconds": 9}],
        "saml_auth_profiles": [{"provider": "saml", "enabled": 1, "metadata_url": "https://idp.invalid/metadata", "require_https": 1, "verify_tls": 1, "ca_bundle": "CA", "timeout_seconds": 11, "max_metadata_bytes": 2048, "raw_metadata_xml": "<xml/>", "public_base_url": "https://proxy.invalid", "username_attribute": "email", "groups_attribute": "groups", "required_group": "admins"}],
        "proxy_config_revisions": [{"proxy_id": proxy_id, "config_sha256": "d" * 64, "config_text": "http_port 3128\n"}],
        "pac_profiles": [{"source_profile_id": 10, "proxy_id": proxy_id, "name": "lan", "client_cidr": "10.0.0.0/24"}, {"source_profile_id": 20, "proxy_id": proxy_id, "name": "guest", "client_cidr": "10.1.0.0/24"}],
        "pac_direct_domains": [{"source_profile_id": 10, "domain": "direct.example"}],
        "pac_direct_dst_nets": [{"source_profile_id": 20, "cidr": "192.0.2.0/24"}],
        "pac_backup_proxies": [{"proxy_id": proxy_id, "proxy_host": "backup.invalid", "proxy_port": 3129, "position": 1}],
        "pac_proxy_chain_settings": [{"proxy_id": proxy_id, "direct_enabled": 0}],
        "policy_exceptions": [{"proxy_id": proxy_id, "block_type": "webfilter", "client_ip": "10.0.0.7", "domain": "allow.example", "category": "work", "admin_note": "temporary", "expires_ts": 2000}],
        "sslfilter_domains": [{"proxy_id": proxy_id, "policy": "bypass", "domain": "tls.example"}],
        "sslfilter_src_nets": [{"proxy_id": proxy_id, "policy": "inspect", "cidr": "10.0.0.0/8"}],
        "sslfilter_settings": [{"proxy_id": proxy_id, "key": "inspection_enabled", "value": "1"}],
        "webfilter_settings": [{"proxy_id": proxy_id, "k": "enabled", "v": "1"}],
        "webfilter_whitelist": [{"proxy_id": proxy_id, "pattern": "*.trusted.example"}],
        "adblock_proxy_meta": [],
        "observability_report_schedules": [{"proxy_id": proxy_id, "enabled": 1, "name": "daily", "cadence": "daily", "recipients": "ops@example.invalid", "pane": "overview", "report_format": "html", "privacy": 1, "window_seconds": 86400}],
    }


class _RestoreResult:
    def __init__(self, rows=None, *, rowcount: int = 0, lastrowid: int = 0) -> None:
        self._rows = list(rows or [])
        self.rowcount = rowcount
        self.lastrowid = lastrowid

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)


class _RestoreConn:
    def __init__(self, *, target_cp: str = _OTHER_CONTROL_PLANE_ID) -> None:
        self.native = object()
        self.target_cp = target_cp
        self.instances = {"edge-01": "healthy"}
        self.tombstones: dict[str, dict[str, object]] = {}
        self.adoptions: dict[tuple[str, str], dict[str, object]] = {}
        self.rows = self._fresh_rows()
        self.ops: list[tuple[str, tuple[object, ...]]] = []
        self.commits = 0
        self.rollbacks = 0
        self._next_id = 100
        self.fail_on_insert_table = ""
        self._snapshot: tuple[
            dict[str, list[dict[str, object]]],
            dict[tuple[str, str], dict[str, object]],
        ] | None = None

    def _fresh_rows(self) -> dict[str, list[dict[str, object]]]:
        return {
            "adblock_lists": [{"key": "cookiemonster", "url": "https://secure.fanboy.co.nz/fanboy-cookiemonster.txt", "enabled": 0}, {"key": "easylist", "url": "https://easylist.to/easylist/easylist.txt", "enabled": 0}, {"key": "easyprivacy", "url": "https://easylist.to/easylist/easyprivacy.txt", "enabled": 0}],
            "adblock_settings": [{"k": "cache_max", "v": "200000"}, {"k": "cache_ttl", "v": "3600"}, {"k": "enabled", "v": "1"}],
            "admin_ui_https_settings": [{"enabled": 0, "certfile": "", "keyfile": "", "san_tokens": ""}],
            "observability_settings": [{"retention_days": 30}],
            "directory_auth_profiles": [], "saml_auth_profiles": [], "pac_proxy_chain_settings": [], "webfilter_settings": [],
            "adblock_artifact_revisions": [], "certificate_bundle_revisions": [], "proxy_config_revisions": [], "pac_profiles": [], "pac_direct_domains": [], "pac_direct_dst_nets": [], "pac_backup_proxies": [], "policy_exceptions": [], "sslfilter_domains": [], "sslfilter_src_nets": [], "sslfilter_settings": [], "webfilter_whitelist": [], "adblock_proxy_meta": [], "observability_report_schedules": [],
        }

    def execute(self, sql: str, params=()):
        text = " ".join(str(sql).split())
        params = tuple(params or ())
        self.ops.append((text, params))
        if "CREATE TABLE IF NOT EXISTS proxy_lifecycle_tombstones" in text:
            return _RestoreResult()
        if "GET_LOCK" in text:
            return _RestoreResult([{"acquired": 1}])
        if "RELEASE_LOCK" in text:
            return _RestoreResult()
        if "FROM proxy_lifecycle_tombstones" in text:
            return _RestoreResult([self.tombstones[str(params[0])]] if str(params[0]) in self.tombstones else [])
        if "FROM proxy_id_aliases" in text:
            return _RestoreResult([])
        if "FROM proxy_instances" in text:
            status = self.instances.get(str(params[0]))
            return _RestoreResult([{"status": status}] if status else [])
        if text == "START TRANSACTION":
            self._snapshot = (deepcopy(self.rows), deepcopy(self.adoptions))
            return _RestoreResult()
        if text.startswith("SELECT control_plane_id FROM control_plane_identity"):
            return _RestoreResult([{"control_plane_id": self.target_cp}] if self.target_cp else [])
        if text.startswith("SELECT status FROM proxy_recovery_adoptions"):
            marker = self.adoptions.get((str(params[0]), str(params[1])))
            return _RestoreResult([marker] if marker else [])
        if text.startswith("INSERT INTO proxy_recovery_adoptions"):
            self.adoptions[(str(params[0]), str(params[1]))] = {"status": params[4], "source_control_plane_id": params[2], "bundle_content_sha256": params[3], "adopted_ts": params[5]}
            return _RestoreResult(rowcount=1)
        if text.startswith("SELECT COUNT(*) AS n FROM"):
            table = text.split(" FROM ", 1)[1].split(" ", 1)[0]
            rows = self.rows[table]
            if "WHERE is_active=1" in text:
                n = sum(1 for row in rows if int(row.get("is_active", 0) or 0) == 1)
            elif "WHERE proxy_id=%s" in text:
                n = sum(1 for row in rows if row.get("proxy_id") == params[0])
            else:
                n = len(rows)
            return _RestoreResult([{"n": n}])
        if text.startswith("SELECT `key`, url, enabled FROM adblock_lists"):
            return _RestoreResult(sorted(self.rows["adblock_lists"], key=lambda r: str(r["key"])))
        if text.startswith("SELECT k, v FROM adblock_settings"):
            return _RestoreResult(sorted(self.rows["adblock_settings"], key=lambda r: str(r["k"])))
        if text.startswith("SELECT enabled, certfile, keyfile, san_tokens FROM admin_ui_https_settings"):
            return _RestoreResult(self.rows["admin_ui_https_settings"])
        if text.startswith("SELECT retention_days FROM observability_settings"):
            return _RestoreResult(self.rows["observability_settings"])
        if text.startswith("SELECT provider, enabled, server_urls"):
            return _RestoreResult(sorted(self.rows["directory_auth_profiles"], key=lambda r: str(r["provider"])))
        if text.startswith("SELECT provider, enabled, metadata_url"):
            return _RestoreResult(sorted(self.rows["saml_auth_profiles"], key=lambda r: str(r["provider"])))
        if text.startswith("SELECT direct_enabled FROM pac_proxy_chain_settings"):
            return _RestoreResult([r for r in self.rows["pac_proxy_chain_settings"] if r["proxy_id"] == params[0]])
        if text.startswith("SELECT k, v FROM webfilter_settings"):
            return _RestoreResult([r for r in self.rows["webfilter_settings"] if r["proxy_id"] == params[0]])
        if text.startswith("DELETE FROM"):
            self._delete(text, params)
            return _RestoreResult(rowcount=1)
        if text.startswith("INSERT INTO"):
            return self._insert(text, params)
        if text.startswith("SELECT LAST_INSERT_ID()"):
            return _RestoreResult([{"id": self._next_id - 1}])
        msg = f"unexpected SQL: {text}"
        raise AssertionError(msg)

    def _delete(self, text: str, params: tuple[object, ...]) -> None:
        if text == "DELETE FROM adblock_lists": self.rows["adblock_lists"] = []
        elif text == "DELETE FROM adblock_settings": self.rows["adblock_settings"] = []
        elif text.startswith("DELETE FROM admin_ui_https_settings"): self.rows["admin_ui_https_settings"] = []
        elif text.startswith("DELETE FROM observability_settings"): self.rows["observability_settings"] = []
        elif text == "DELETE FROM directory_auth_profiles": self.rows["directory_auth_profiles"] = []
        elif text == "DELETE FROM saml_auth_profiles": self.rows["saml_auth_profiles"] = []
        elif text.startswith("DELETE FROM pac_proxy_chain_settings"): self.rows["pac_proxy_chain_settings"] = [r for r in self.rows["pac_proxy_chain_settings"] if r["proxy_id"] != params[0]]
        elif text.startswith("DELETE FROM webfilter_settings"): self.rows["webfilter_settings"] = [r for r in self.rows["webfilter_settings"] if not (r["proxy_id"] == params[0] and r["k"] in {"enabled", "blocked_categories"})]
        else: raise AssertionError(text)

    def _insert(self, text: str, params: tuple[object, ...]) -> _RestoreResult:
        table = text.split(" ", 3)[2].split("(", 1)[0]
        if self.fail_on_insert_table and self.fail_on_insert_table in text:
            raise RuntimeError(f"simulated insert failure {self.fail_on_insert_table}")
        if table == "adblock_lists": self.rows[table].append({"key": params[0], "url": params[1], "enabled": params[2]})
        elif table == "adblock_settings": self.rows[table].append({"k": params[0], "v": params[1]})
        elif table == "adblock_artifact_revisions": self.rows[table].append({"artifact_sha256": params[0], "archive_blob": params[1], "is_active": 1})
        elif table == "certificate_bundle_revisions": self.rows[table].append({"bundle_sha256": params[0], "key_pem": params[3], "is_active": 1})
        elif table == "admin_ui_https_settings": self.rows[table].append({"enabled": params[0], "certfile": params[1], "keyfile": params[2], "san_tokens": params[3]})
        elif table == "observability_settings": self.rows[table].append({"retention_days": params[0]})
        elif table == "directory_auth_profiles": self.rows[table].append({"provider": params[0], "bind_password": params[7]})
        elif table == "saml_auth_profiles": self.rows[table].append({"provider": params[0], "raw_metadata_xml": params[8]})
        elif table == "proxy_config_revisions": self.rows[table].append({"proxy_id": params[0], "config_sha256": params[1], "config_text": params[2], "is_active": 1})
        elif table == "pac_profiles":
            row_id = self._next_id; self._next_id += 1
            self.rows[table].append({"id": row_id, "proxy_id": params[0], "name": params[1], "client_cidr": params[2]})
            return _RestoreResult(lastrowid=row_id)
        elif table == "pac_direct_domains": self.rows[table].append({"profile_id": params[0], "domain": params[1]})
        elif table == "pac_direct_dst_nets": self.rows[table].append({"profile_id": params[0], "cidr": params[1]})
        elif table == "pac_backup_proxies": self.rows[table].append({"proxy_id": params[0], "proxy_host": params[1], "proxy_port": params[2], "position": params[3]})
        elif table == "pac_proxy_chain_settings": self.rows[table].append({"proxy_id": params[0], "direct_enabled": params[1]})
        elif table == "policy_exceptions": self.rows[table].append({"proxy_id": params[0], "block_type": params[1], "domain": params[3], "admin_note": params[7], "expires_ts": params[8]})
        elif table == "sslfilter_domains": self.rows[table].append({"proxy_id": params[0], "policy": params[1], "domain": params[2]})
        elif table == "sslfilter_src_nets": self.rows[table].append({"proxy_id": params[0], "policy": params[1], "cidr": params[2]})
        elif table == "sslfilter_settings": self.rows[table].append({"proxy_id": params[0], "key": params[1], "value": params[2]})
        elif table == "webfilter_settings": self.rows[table].append({"proxy_id": params[0], "k": params[1], "v": params[2]})
        elif table == "webfilter_whitelist": self.rows[table].append({"proxy_id": params[0], "pattern": params[1]})
        elif table == "adblock_proxy_meta": self.rows[table].append({"proxy_id": params[0], "k": params[1], "v": params[2]})
        elif table == "observability_report_schedules": self.rows[table].append({"proxy_id": params[0], "name": params[2], "cadence": params[3], "pane": params[5]})
        else: raise AssertionError(table)
        return _RestoreResult(rowcount=1)

    def commit(self) -> None:
        self.commits += 1
        self._snapshot = None

    def rollback(self) -> None:
        self.rollbacks += 1
        if self._snapshot is not None:
            self.rows, self.adoptions = deepcopy(self._snapshot)
            self._snapshot = None


def _restore_bundle(rows: dict[str, list[dict[str, object]]] | None = None) -> recovery.RecoveryBundle:
    with tempfile.TemporaryDirectory() as tmp:
        return _create_recovery_bundle(
            "edge-01",
            rows or _full_restore_rows(),
            created_ts="2026-07-28T20:00:00Z",
            recovery_dir=Path(tmp),
        )


def test_restore_plan_preflight_exact_contract_and_rejects_malformed_bundle() -> None:
    bundle = _restore_bundle()
    plan = recovery.build_restore_plan(bundle, "edge-01", now_ts=1000)
    with tempfile.TemporaryDirectory() as tmp:
        recovery.write_recovery_bundle(
            "edge-01",
            _full_restore_rows(),
            source_control_plane_id=_SOURCE_CONTROL_PLANE_ID,
            created_ts="2026-07-28T20:00:00Z",
            recovery_dir=Path(tmp),
        )
        round_tripped = recovery.read_recovery_bundle("edge-01", recovery_dir=Path(tmp))
    round_trip_plan = recovery.build_restore_plan(round_tripped, "edge-01", now_ts=1000)
    assert plan.target_proxy_id == "edge-01"
    assert round_trip_plan.tables[0].rows == plan.tables[0].rows
    assert plan.bundle_content_sha256 == bundle.integrity.content_sha256
    assert [table.table_name for table in plan.tables] == [spec.table_name for spec in recovery.recovery_registry()]
    assert [p.table_name for p in recovery.restore_sql_plans()] == [spec.table_name for spec in recovery.recovery_registry()]
    assert all("SELECT *" not in p.insert_sql.upper() for p in recovery.restore_sql_plans())

    bad = deepcopy(_full_restore_rows()); bad["pac_profiles"][0].pop("client_cidr")
    with pytest.raises(recovery.ProxyRecoveryError, match="columns"):
        recovery.build_restore_plan(_restore_bundle(bad), "edge-01", now_ts=1000)
    bad = deepcopy(_full_restore_rows()); bad["pac_profiles"].append(dict(bad["pac_profiles"][0]))
    with pytest.raises(recovery.ProxyRecoveryError, match="duplicate"):
        recovery.build_restore_plan(_restore_bundle(bad), "edge-01", now_ts=1000)
    bad = deepcopy(_full_restore_rows()); bad["pac_direct_domains"][0]["source_profile_id"] = 999
    with pytest.raises(recovery.ProxyRecoveryError, match="orphan"):
        recovery.build_restore_plan(_restore_bundle(bad), "edge-01", now_ts=1000)
    bad = deepcopy(_full_restore_rows()); bad["policy_exceptions"][0]["expires_ts"] = 999
    with pytest.raises(recovery.ProxyRecoveryError, match="expired"):
        recovery.build_restore_plan(_restore_bundle(bad), "edge-01", now_ts=1000)
    bad = deepcopy(_full_restore_rows()); bad["proxy_config_revisions"][0]["proxy_id"] = "other"
    with pytest.raises(recovery.ProxyRecoveryError, match="proxy id"):
        recovery.build_restore_plan(_restore_bundle(bad), "edge-01", now_ts=1000)


def test_restore_success_is_atomic_locked_marks_adopted_remaps_pac_and_preserves_identity_and_bytes(monkeypatch) -> None:
    monkeypatch.setattr("services.proxy_write_guard.table_exists", lambda _conn, name: name in {"proxy_instances", "proxy_id_aliases"})
    conn = _RestoreConn(); bundle = _restore_bundle()
    result = recovery.restore_recovery_bundle(conn, bundle, "edge-01", now_ts=1000)
    assert result.status == "adopted"
    assert result.target_control_plane_id == _OTHER_CONTROL_PLANE_ID
    assert conn.target_cp == _OTHER_CONTROL_PLANE_ID
    assert conn.commits == 1 and conn.rollbacks == 0
    assert conn.adoptions[("edge-01", _OTHER_CONTROL_PLANE_ID)]["bundle_content_sha256"] == bundle.integrity.content_sha256
    assert conn.rows["adblock_artifact_revisions"][0]["archive_blob"] == b"artifact-bytes\x00"
    assert conn.rows["pac_profiles"] == [{"id": 100, "proxy_id": "edge-01", "name": "lan", "client_cidr": "10.0.0.0/24"}, {"id": 101, "proxy_id": "edge-01", "name": "guest", "client_cidr": "10.1.0.0/24"}]
    assert conn.rows["pac_direct_domains"] == [{"profile_id": 100, "domain": "direct.example"}]
    assert conn.rows["pac_direct_dst_nets"] == [{"profile_id": 101, "cidr": "192.0.2.0/24"}]
    start_idx = [sql for sql, _ in conn.ops].index("START TRANSACTION")
    marker_idx = next(i for i, (sql, _) in enumerate(conn.ops) if sql.startswith("INSERT INTO proxy_recovery_adoptions"))
    assert marker_idx > start_idx
    assert any("GET_LOCK" in sql for sql, _ in conn.ops)
    assert any("RELEASE_LOCK" in sql for sql, _ in conn.ops)


def test_restore_exactly_once_and_same_or_new_control_plane_semantics(monkeypatch) -> None:
    monkeypatch.setattr("services.proxy_write_guard.table_exists", lambda _conn, name: name in {"proxy_instances", "proxy_id_aliases"})
    bundle = _restore_bundle(); conn = _RestoreConn()
    assert recovery.restore_recovery_bundle(conn, bundle, "edge-01", now_ts=1000).status == "adopted"
    conn.rows["webfilter_settings"] = [{"proxy_id": "edge-01", "k": "enabled", "v": "0"}]
    again = recovery.restore_recovery_bundle(conn, bundle, "edge-01", now_ts=1001)
    assert again.status == "already_adopted"
    assert conn.rows["webfilter_settings"] == [{"proxy_id": "edge-01", "k": "enabled", "v": "0"}]
    same = _RestoreConn(target_cp=_SOURCE_CONTROL_PLANE_ID)
    assert recovery.restore_recovery_bundle(same, bundle, "edge-01", now_ts=1000).status == "same_control_plane"
    assert same.adoptions == {}
    new_target = _RestoreConn(target_cp="123e4567-e89b-42d3-a456-426614174002")
    assert recovery.restore_recovery_bundle(new_target, bundle, "edge-01", now_ts=1000).status == "adopted"


def test_restore_fails_closed_for_missing_invalid_identity_prior_marker_nonfresh_and_lifecycle(monkeypatch) -> None:
    monkeypatch.setattr("services.proxy_write_guard.table_exists", lambda _conn, name: name in {"proxy_instances", "proxy_id_aliases"})
    bundle = _restore_bundle()
    missing = _RestoreConn(target_cp="")
    with pytest.raises(recovery.ProxyRecoveryError, match="identity is missing"):
        recovery.restore_recovery_bundle(missing, bundle, "edge-01", now_ts=1000)
    prior = _RestoreConn(); prior.adoptions[("edge-01", _OTHER_CONTROL_PLANE_ID)] = {"status": "adopted"}
    assert recovery.restore_recovery_bundle(prior, bundle, "edge-01", now_ts=1000).status == "already_adopted"
    assert prior.commits == 0
    nonfresh = _RestoreConn(); nonfresh.rows["proxy_config_revisions"].append({"proxy_id": "edge-01", "is_active": 1})
    res = recovery.restore_recovery_bundle(nonfresh, bundle, "edge-01", now_ts=1000)
    assert res.status == "not_eligible" and "proxy config" in res.reason
    assert nonfresh.adoptions == {}
    tombstoned = _RestoreConn(); tombstoned.tombstones["edge-01"] = {"action": "removing", "target_proxy_id": ""}
    with pytest.raises(Exception, match=r"removed|removing"):
        recovery.restore_recovery_bundle(tombstoned, bundle, "edge-01", now_ts=1000)


def test_restore_rollback_mid_write_leaves_no_marker(monkeypatch) -> None:
    monkeypatch.setattr("services.proxy_write_guard.table_exists", lambda _conn, name: name in {"proxy_instances", "proxy_id_aliases"})
    conn = _RestoreConn(); conn.fail_on_insert_table = "webfilter_whitelist"
    with pytest.raises(RuntimeError, match="webfilter_whitelist"):
        recovery.restore_recovery_bundle(conn, _restore_bundle(), "edge-01", now_ts=1000)
    assert conn.rollbacks == 1 and conn.commits == 0
    assert conn.adoptions == {}
    assert conn.rows["adblock_lists"] == _RestoreConn().rows["adblock_lists"]
    assert not conn.rows["webfilter_whitelist"]
