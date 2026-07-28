from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Self

import pytest

WEB_ROOT = Path(__file__).resolve().parents[1]
if str(WEB_ROOT) not in sys.path:
    sys.path.insert(0, str(WEB_ROOT))

from services import proxy_recovery_startup as startup  # type: ignore  # noqa: E402


class _Registry:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    def ensure_proxy(self, proxy_id: str, **_kwargs: Any) -> SimpleNamespace:
        self.calls.append(f"register:{proxy_id}")
        return SimpleNamespace(proxy_id=proxy_id)


class _Conn:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    def __enter__(self) -> Self:
        self.calls.append("connect")
        return self

    def __exit__(self, *_args: object) -> None:
        self.calls.append("disconnect")


def _touch_bundle_and_key(tmp_path: Path, proxy_id: str = "edge-01") -> None:
    (tmp_path / f"{proxy_id}.bundle.json").write_text("{}", encoding="utf-8")
    (tmp_path / f"{proxy_id}.hmac.key").write_bytes(b"k" * 32)


def test_missing_bundle_skips_without_schema_or_registration(tmp_path: Path) -> None:
    calls: list[str] = []

    result = startup.run_startup_recovery(
        proxy_id="edge-01",
        registry=_Registry(calls),
        ensure_schema=lambda: calls.append("schema"),
        connect_factory=lambda: _Conn(calls),
        recovery_dir=tmp_path,
    )

    assert result.status == "missing_bundle"
    assert result.capture_required is True
    assert calls == []


def test_startup_adoption_order_is_before_normal_mutation(monkeypatch, tmp_path: Path) -> None:
    calls: list[str] = []
    bundle = object()
    _touch_bundle_and_key(tmp_path)

    monkeypatch.setattr(
        startup.proxy_recovery,
        "read_recovery_bundle",
        lambda *_args, **_kwargs: calls.append("read_bundle") or bundle,
    )

    def restore(conn, restored_bundle, proxy_id):
        assert isinstance(conn, _Conn)
        assert restored_bundle is bundle
        calls.append(f"restore:{proxy_id}")
        return SimpleNamespace(
            status="adopted",
            reason="",
            restored_rows=7,
        )

    monkeypatch.setattr(startup, "restore_recovery_bundle", restore)

    result = startup.run_startup_recovery(
        proxy_id="EDGE-01",
        registry=_Registry(calls),
        ensure_schema=lambda: calls.append("schema"),
        connect_factory=lambda: _Conn(calls),
        recovery_dir=tmp_path,
    )

    assert result.status == "adopted"
    assert calls == [
        "schema",
        "register:edge-01",
        "read_bundle",
        "connect",
        "restore:edge-01",
        "disconnect",
    ]


@pytest.mark.parametrize("status", ["adopted", "already_adopted", "same_control_plane"])
def test_successful_or_explicit_skip_statuses_continue(
    monkeypatch,
    tmp_path: Path,
    status: str,
) -> None:
    _touch_bundle_and_key(tmp_path)
    monkeypatch.setattr(startup.proxy_recovery, "read_recovery_bundle", lambda *_a, **_k: object())
    monkeypatch.setattr(
        startup,
        "restore_recovery_bundle",
        lambda *_a, **_k: SimpleNamespace(status=status, reason="", restored_rows=0),
    )

    result = startup.run_startup_recovery(
        proxy_id="edge-01",
        registry=_Registry([]),
        ensure_schema=lambda: None,
        connect_factory=lambda: _Conn([]),
        recovery_dir=tmp_path,
    )

    assert result.status == status


def test_not_eligible_fails_closed_after_restore_decision(monkeypatch, tmp_path: Path) -> None:
    calls: list[str] = []
    _touch_bundle_and_key(tmp_path)
    monkeypatch.setattr(startup.proxy_recovery, "read_recovery_bundle", lambda *_a, **_k: object())
    monkeypatch.setattr(
        startup,
        "restore_recovery_bundle",
        lambda *_a, **_k: SimpleNamespace(
            status="not_eligible",
            reason="proxy config revision already exists for target proxy",
            restored_rows=0,
        ),
    )

    with pytest.raises(startup.ProxyRecoveryStartupError, match="failed closed"):
        startup.run_startup_recovery(
            proxy_id="edge-01",
            registry=_Registry(calls),
            ensure_schema=lambda: calls.append("schema"),
            connect_factory=lambda: _Conn(calls),
            recovery_dir=tmp_path,
        )

    assert "register:edge-01" in calls
    assert not any(call.startswith("normal_") for call in calls)


def test_schema_failure_prevents_registration_and_bundle_read(monkeypatch, tmp_path: Path) -> None:
    calls: list[str] = []
    _touch_bundle_and_key(tmp_path)
    monkeypatch.setattr(
        startup.proxy_recovery,
        "read_recovery_bundle",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("should not read")),
    )

    def fail_schema() -> None:
        calls.append("schema")
        msg = "schema missing"
        raise RuntimeError(msg)

    with pytest.raises(startup.ProxyRecoveryStartupError, match="schema migration"):
        startup.run_startup_recovery(
            proxy_id="edge-01",
            registry=_Registry(calls),
            ensure_schema=fail_schema,
            connect_factory=lambda: _Conn(calls),
            recovery_dir=tmp_path,
        )

    assert calls == ["schema"]


def test_tampered_bundle_fails_closed_without_secret_logging(monkeypatch, tmp_path: Path, caplog) -> None:
    calls: list[str] = []
    _touch_bundle_and_key(tmp_path)

    def fail_read(*_args, **_kwargs):
        msg = "secret-token-value"
        raise RuntimeError(msg)

    monkeypatch.setattr(startup.proxy_recovery, "read_recovery_bundle", fail_read)

    with pytest.raises(startup.ProxyRecoveryStartupError, match="validation failed"):
        startup.run_startup_recovery(
            proxy_id="edge-01",
            registry=_Registry(calls),
            ensure_schema=lambda: calls.append("schema"),
            connect_factory=lambda: _Conn(calls),
            recovery_dir=tmp_path,
        )

    assert "secret-token-value" not in caplog.text
    assert "connect" not in calls


def test_optional_capture_interval_gate_requires_caller_state(monkeypatch, tmp_path: Path) -> None:
    calls: list[str] = []

    def capture(*_args, **_kwargs):
        calls.append("capture")
        return tmp_path / "edge-01.bundle.json"

    monkeypatch.setattr(startup, "capture_and_write_recovery_bundle", capture)

    skipped = startup.capture_recovery_bundle_after_authoritative_state(
        proxy_id="edge-01",
        reason="runtime_sync",
        recovery_dir=tmp_path,
        now_mono=110.0,
        last_capture_mono=100.0,
    )
    assert skipped.skipped is True
    assert calls == []

    changed = startup.capture_recovery_bundle_after_authoritative_state(
        proxy_id="edge-01",
        reason="runtime_sync",
        recovery_dir=tmp_path,
        now_mono=110.0,
        last_capture_mono=100.0,
        changed=True,
    )
    assert changed.ok is True
    assert changed.skipped is False
    assert calls == ["capture"]


def test_capture_failure_is_fatal_only_when_required(monkeypatch, tmp_path: Path) -> None:
    old_bundle = tmp_path / "edge-01.bundle.json"
    old_bundle.write_text("old", encoding="utf-8")

    def fail_capture(*_args, **_kwargs):
        msg = "disk full"
        raise RuntimeError(msg)

    monkeypatch.setattr(startup, "capture_and_write_recovery_bundle", fail_capture)

    nonfatal = startup.capture_recovery_bundle_after_authoritative_state(
        proxy_id="edge-01",
        reason="runtime_sync",
        recovery_dir=tmp_path,
    )
    assert nonfatal.ok is False
    assert old_bundle.read_text(encoding="utf-8") == "old"

    with pytest.raises(startup.ProxyRecoveryCaptureError, match="required recovery capture failed"):
        startup.capture_recovery_bundle_after_authoritative_state(
            proxy_id="edge-01",
            reason="startup_initial",
            required=True,
            recovery_dir=tmp_path,
        )
    assert old_bundle.read_text(encoding="utf-8") == "old"


def test_compose_recovery_dir_lives_on_proxy_durable_volume_only() -> None:
    compose = Path(__file__).resolve().parents[2] / "docker-compose.common.yml"
    text = compose.read_text(encoding="utf-8")

    assert "proxy_data:/var/lib/squid-flask-proxy" in text
    assert "DEFAULT_RECOVERY_DIR" not in text
    admin_section = text.split("  proxy:", 1)[0]
    assert "/var/lib/squid-flask-proxy" not in admin_section
