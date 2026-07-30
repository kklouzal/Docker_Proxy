from __future__ import annotations

import json
import os
import stat
from typing import TYPE_CHECKING

import pytest

from web.services import proxy_recovery as recovery

if TYPE_CHECKING:
    from pathlib import Path


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


def test_max_bundle_bytes_defaults_and_operator_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(recovery.RECOVERY_MAX_BUNDLE_BYTES_ENV, raising=False)

    assert recovery.DEFAULT_MAX_BUNDLE_BYTES == 128 * 1024 * 1024
    assert recovery.DEFAULT_MAX_BUNDLE_BYTES > 88_659_553
    assert recovery.resolve_max_bundle_bytes() == recovery.DEFAULT_MAX_BUNDLE_BYTES

    configured = 96 * 1024 * 1024
    monkeypatch.setenv(recovery.RECOVERY_MAX_BUNDLE_BYTES_ENV, str(configured))

    assert recovery.recovery_bundle_size_config_from_env().max_bundle_bytes == configured
    assert recovery.resolve_max_bundle_bytes() == configured
    assert recovery.resolve_max_bundle_bytes(2 * 1024 * 1024) == 2 * 1024 * 1024
    assert recovery.resolve_max_bundle_bytes(64) == 64

    for value in (
        "",
        "64MiB",
        "1.5",
        "-1",
        "true",
        str(recovery.MIN_MAX_BUNDLE_BYTES - 1),
        str(recovery.HARD_MAX_BUNDLE_BYTES + 1),
    ):
        monkeypatch.setenv(recovery.RECOVERY_MAX_BUNDLE_BYTES_ENV, value)
        with pytest.raises(recovery.ProxyRecoveryError, match="bundle byte limit"):
            recovery.resolve_max_bundle_bytes()

    with pytest.raises(recovery.ProxyRecoveryError, match="bundle byte limit"):
        recovery.resolve_max_bundle_bytes(True)  # type: ignore[arg-type]


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


def test_env_max_bundle_bytes_enforces_create_write_read_and_parse_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rows = {"adblock_settings": [{"large": "x" * recovery.MIN_MAX_BUNDLE_BYTES}]}
    monkeypatch.setenv(
        recovery.RECOVERY_MAX_BUNDLE_BYTES_ENV,
        str(recovery.MIN_MAX_BUNDLE_BYTES),
    )

    with pytest.raises(recovery.ProxyRecoveryError, match="exceeds maximum size"):
        _create_recovery_bundle("edge-01", rows, recovery_dir=tmp_path)

    with pytest.raises(recovery.ProxyRecoveryError, match="exceeds maximum size"):
        _write_recovery_bundle(
            "edge-01",
            rows,
            recovery_dir=tmp_path,
        )

    path = _write_recovery_bundle(
        "edge-01",
        rows,
        recovery_dir=tmp_path,
        max_bundle_bytes=2 * recovery.MIN_MAX_BUNDLE_BYTES,
    )
    raw = path.read_bytes()

    with pytest.raises(recovery.ProxyRecoveryError, match="exceeds maximum size"):
        recovery.read_recovery_bundle("edge-01", recovery_dir=tmp_path)
    with pytest.raises(recovery.ProxyRecoveryError, match="exceeds maximum size"):
        recovery.parse_recovery_bundle(
            raw,
            expected_proxy_id="edge-01",
            key=recovery.read_signing_key("edge-01", tmp_path),
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
