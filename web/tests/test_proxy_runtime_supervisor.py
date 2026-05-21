from __future__ import annotations

import hashlib
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import NoReturn

import pytest


def _add_repo_paths() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    web_root = repo_root / "web"
    for path in (repo_root, web_root):
        path_str = str(path)
        if path_str not in sys.path:
            sys.path.insert(0, path_str)


def _runtime_shell():
    _add_repo_paths()
    from proxy.runtime import ProxyRuntime  # type: ignore

    return ProxyRuntime.__new__(ProxyRuntime)


def _cp(returncode: int, stdout: str = "", stderr: str = ""):
    return SimpleNamespace(
        returncode=returncode,
        stdout=stdout.encode("utf-8"),
        stderr=stderr.encode("utf-8"),
    )


def test_supervisor_program_status_trusts_matching_running_line_with_nonzero_returncode(
    monkeypatch,
) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    monkeypatch.setattr(
        runtime_module.subprocess,
        "run",
        lambda *_args, **_kwargs: _cp(
            3, stdout="squid RUNNING pid 3769, uptime 0:00:29"
        ),
    )

    ok, detail = _runtime_shell()._supervisor_program_status("squid")

    assert ok is True
    assert "RUNNING" in detail


def test_test_control_supervisor_program_uses_squid_controller_restart() -> None:
    runtime = _runtime_shell()
    runtime.controller = SimpleNamespace(
        restart_squid=lambda: (True, "Squid HTTP listener is accepting connections.")
    )
    runtime._invalidate_health_cache = lambda: None
    runtime._restart_supervisor_program = lambda *_args, **_kwargs: (
        _ for _ in ()
    ).throw(
        AssertionError("squid restart should use the SquidController restart path"),
    )

    result = runtime.test_control_supervisor_program("squid", action="restart")

    assert result == {
        "ok": True,
        "proxy_id": "default",
        "program": "squid",
        "action": "restart",
        "detail": "Squid HTTP listener is accepting connections.",
    }


def test_forced_navigation_health_does_not_seed_cache() -> None:
    runtime = _runtime_shell()
    runtime.health_cache_ttl_seconds = 60.0
    runtime._health_cache_lock = threading.Lock()
    runtime._navigation_health_cache_ts = 0.0
    runtime._navigation_health_cache_value = None
    runtime._supervisor_programs_health = lambda: {
        "ok": True,
        "detail": "supervisor programs running",
        "programs": {},
    }

    class Controller:
        calls = 0

        def get_status(self):
            return b"Squid check ok.", b""

        def _http_listener_details(self):
            self.calls += 1
            listeners = [{"port": 3128, "mode": "explicit"}]
            if self.calls > 1:
                listeners.append({"port": 3129, "mode": "intercept"})
            return tuple(listeners)

        def _wait_for_http_listener(self, *, timeout: float = 0.5) -> bool:
            return True

    controller = Controller()
    runtime.controller = controller

    forced = runtime.collect_navigation_health(force=True)
    assert {item.get("mode") for item in forced["listener_details"]} == {"explicit"}

    refreshed = runtime.collect_navigation_health()
    assert {item.get("mode") for item in refreshed["listener_details"]} == {
        "explicit",
        "intercept",
    }

    cached = runtime.collect_navigation_health()
    assert cached is refreshed
    assert controller.calls == 2


def test_navigation_health_cache_refreshes_when_config_sha_changes() -> None:
    runtime = _runtime_shell()
    runtime.health_cache_ttl_seconds = 60.0
    runtime._health_cache_lock = threading.Lock()
    runtime._navigation_health_cache_ts = 0.0
    runtime._navigation_health_cache_value = None
    runtime._supervisor_programs_health = lambda: {
        "ok": True,
        "detail": "supervisor programs running",
        "programs": {},
    }

    state = {"config_text": "http_port 0.0.0.0:3128 ssl-bump\n"}

    class Controller:
        calls = 0

        def get_status(self):
            return b"Squid check ok.", b""

        def _http_listener_details(self):
            self.calls += 1
            listeners = [{"port": 3128, "mode": "explicit"}]
            if "3129 intercept" in state["config_text"]:
                listeners.append({"port": 3129, "mode": "intercept"})
            return tuple(listeners)

        def _wait_for_http_listener(self, *, timeout: float = 0.5) -> bool:
            return True

    controller = Controller()
    runtime.controller = controller
    runtime.services = SimpleNamespace(
        current_config_sha_reader=lambda: hashlib.sha256(
            state["config_text"].encode("utf-8"),
        ).hexdigest(),
    )

    first = runtime.collect_navigation_health()
    assert {item.get("mode") for item in first["listener_details"]} == {"explicit"}

    cached = runtime.collect_navigation_health()
    assert cached is first
    assert controller.calls == 1

    state["config_text"] = (
        "http_port 0.0.0.0:3128 ssl-bump\n"
        "http_port 0.0.0.0:3129 intercept\n"
    )

    refreshed = runtime.collect_navigation_health()
    assert refreshed is not first
    assert {item.get("mode") for item in refreshed["listener_details"]} == {
        "explicit",
        "intercept",
    }
    assert controller.calls == 2


def test_restart_supervisor_program_accepts_already_started_output(monkeypatch) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    calls: list[list[str]] = []
    results = [
        _cp(0, stdout="cicap_adblock: stopped"),
        _cp(0, stdout="cicap_adblock STOPPED May 11 03:54 AM"),
        _cp(1, stderr="cicap_adblock: ERROR (already started)"),
        _cp(0, stdout="cicap_adblock RUNNING pid 123, uptime 0:00:01"),
    ]

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        return results.pop(0)

    monkeypatch.setattr(runtime_module.subprocess, "run", fake_run)

    ok, detail = _runtime_shell()._restart_supervisor_program("cicap_adblock")

    assert ok is True
    assert calls == [
        ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "cicap_adblock"],
        ["supervisorctl", "-c", "/etc/supervisord.conf", "status", "cicap_adblock"],
        ["supervisorctl", "-c", "/etc/supervisord.conf", "start", "cicap_adblock"],
        ["supervisorctl", "-c", "/etc/supervisord.conf", "status", "cicap_adblock"],
    ]
    assert "already started" in detail


def test_restart_supervisor_program_trusts_running_status_after_failed_start(
    monkeypatch,
) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    monkeypatch.setattr(runtime_module.time, "sleep", lambda _seconds: None)
    results = [
        _cp(0, stdout="cicap_adblock: stopped"),
        _cp(0, stdout="cicap_adblock STOPPED May 11 03:54 AM"),
        _cp(1, stderr="cicap_adblock: ERROR (abnormal termination)"),
        _cp(0, stdout="cicap_adblock RUNNING pid 123, uptime 0:00:01"),
    ]

    monkeypatch.setattr(
        runtime_module.subprocess, "run", lambda *_args, **_kwargs: results.pop(0)
    )

    ok, detail = _runtime_shell()._restart_supervisor_program("cicap_adblock")

    assert ok is True
    assert "abnormal termination" in detail
    assert "RUNNING" in detail


def test_restart_supervisor_program_accepts_supervisor_auto_restart_after_stop(
    monkeypatch,
) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    results = [_cp(0, stdout="squid: stopped")]
    monkeypatch.setattr(
        runtime_module.subprocess, "run", lambda *_args, **_kwargs: results.pop(0)
    )
    runtime = _runtime_shell()
    runtime._wait_for_supervisor_program_stopped = (
        lambda _program, timeout_seconds=30.0: (
            False,
            "squid RUNNING pid 3769, uptime 0:00:29",
        )
    )
    runtime._supervisor_program_status = lambda _program, timeout_seconds=30: (
        True,
        "squid RUNNING pid 3769, uptime 0:00:29",
    )

    ok, detail = runtime._restart_supervisor_program("squid")

    assert ok is True
    assert "already restarted by supervisor" in detail
    assert "RUNNING" in detail


def test_restart_supervisor_program_returns_false_after_retries(monkeypatch) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    calls = {"count": 0}
    monkeypatch.setattr(runtime_module.time, "sleep", lambda _seconds: None)

    def fake_run(args, **_kwargs):
        calls["count"] += 1
        if "stop" in args:
            return _cp(0, stdout="service: stopped")
        if "status" in args:
            return _cp(3, stdout="service FATAL")
        return _cp(1, stderr="service: ERROR (abnormal termination)")

    monkeypatch.setattr(runtime_module.subprocess, "run", fake_run)

    ok, detail = _runtime_shell()._restart_supervisor_program("service")
    assert ok is False
    assert (
        calls["count"] == 12
    )  # stop + stopped-status wait + five start/status attempts
    assert "abnormal termination" in detail


def test_restart_adblock_service_uses_injected_restarter() -> None:
    runtime = _runtime_shell()
    runtime.services = SimpleNamespace(
        adblock_service_restarter=lambda: (True, "custom restarter")
    )

    assert runtime._restart_adblock_service() == (True, "custom restarter")


def test_restart_adblock_service_stops_program_after_restart_loop(monkeypatch) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    calls: list[list[str]] = []
    monkeypatch.setattr(runtime_module.time, "sleep", lambda _seconds: None)

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        if "status" in args:
            return _cp(3, stdout="cicap_adblock BACKOFF exited too quickly")
        if "start" in args:
            return _cp(0, stdout="cicap_adblock: started")
        return _cp(0, stdout="cicap_adblock: stopped")

    monkeypatch.setattr(runtime_module.subprocess, "run", fake_run)

    runtime = _runtime_shell()
    runtime.services = SimpleNamespace(adblock_service_restarter=None)

    ok, detail = runtime._restart_adblock_service()

    assert ok is False
    assert "BACKOFF" in detail
    assert calls[-1] == [
        "supervisorctl",
        "-c",
        "/etc/supervisord.conf",
        "stop",
        "cicap_adblock",
    ]


def test_heartbeat_uses_derived_management_url_when_override_unset(monkeypatch) -> None:
    runtime = _runtime_shell()
    monkeypatch.setenv("PROXY_INSTANCE_ID", "Proxy-IT")
    monkeypatch.delenv("PROXY_MANAGEMENT_URL", raising=False)
    monkeypatch.delenv("PROXY_MANAGEMENT_HOST", raising=False)
    monkeypatch.delenv("PROXY_PUBLIC_HOST", raising=False)
    captured: dict[str, object] = {}

    class Registry:
        def heartbeat(self, proxy_id, **kwargs) -> None:
            captured["proxy_id"] = proxy_id
            captured.update(kwargs)

    runtime.registry = Registry()
    runtime.self_heal_config_if_needed = lambda *, reason: None
    runtime.self_heal_runtime_services_if_needed = lambda *, reason: None
    runtime.collect_health = lambda: {
        "status": "healthy",
        "current_config_sha": "abc",
        "proxy_status": "Squid check ok.",
    }

    assert runtime.heartbeat()["status"] == "healthy"
    assert captured["proxy_id"] == "Proxy-IT"
    assert captured["management_url"] == "http://proxy-it:5000"


def test_sync_certificate_bundle_skips_current_bundle_even_when_forced() -> None:
    runtime = _runtime_shell()

    class Bundles:
        def get_active_bundle_metadata(self):
            return SimpleNamespace(revision_id=7, bundle_sha256="same-sha")

        def latest_apply(self, proxy_id):
            return SimpleNamespace(proxy_id=proxy_id, revision_id=7)

        def get_active_bundle(self) -> NoReturn:
            msg = "current certificate bundle should not be loaded"
            raise AssertionError(msg)

        def record_apply_result(self, *_args, **_kwargs) -> NoReturn:
            msg = "current certificate bundle should not be recorded as re-applied"
            raise AssertionError(msg)

    runtime.services = SimpleNamespace(
        current_certificate_sha_reader=lambda: "same-sha"
    )
    runtime.certificate_bundles = Bundles()

    result = runtime.sync_certificate_bundle(force=True)

    assert result["ok"] is True
    assert result["changed"] is False
    assert result["revision_id"] == 7
    assert result["detail"] == "Proxy is already using the active certificate bundle."


def test_sync_certificate_bundle_records_noop_apply_for_current_bundle_without_apply_record() -> (
    None
):
    runtime = _runtime_shell()
    recorded: list[tuple[object, int, bool, str]] = []

    class Bundles:
        def get_active_bundle_metadata(self):
            return SimpleNamespace(revision_id=8, bundle_sha256="same-sha")

        def latest_apply(self, _proxy_id) -> None:
            return None

        def record_apply_result(
            self, proxy_id, revision_id, *, ok, detail, applied_by, bundle_sha256
        ):
            recorded.append((proxy_id, revision_id, ok, bundle_sha256))
            assert detail == "Proxy is already using the active certificate bundle."
            assert applied_by == "proxy"
            return SimpleNamespace(application_id=123)

        def get_active_bundle(self) -> NoReturn:
            msg = "current certificate bundle should not be loaded"
            raise AssertionError(msg)

    runtime.services = SimpleNamespace(
        current_certificate_sha_reader=lambda: "same-sha"
    )
    runtime.certificate_bundles = Bundles()

    result = runtime.sync_certificate_bundle(force=True)

    assert result["ok"] is True
    assert result["changed"] is False
    assert result["application_id"] == 123
    assert recorded == [("default", 8, True, "same-sha")]


def test_runtime_validate_config_text_delegates_to_proxy_controller() -> None:
    runtime = _runtime_shell()

    class Controller:
        def normalize_config_text(self, text):
            return text.rstrip() + "\n"

        def validate_config_text(self, text):
            assert text == "workers 1\n"
            return True, "parse ok"

    runtime.controller = Controller()

    result = runtime.validate_config_text("workers 1")

    assert result["ok"] is True
    assert result["proxy_id"] == "default"
    assert result["detail"] == "parse ok"
    assert len(result["config_sha256"]) == 64


def test_runtime_self_heal_rolls_back_when_squid_status_fails() -> None:
    runtime = _runtime_shell()
    marked: list[tuple[bool, str, str]] = []

    class Controller:
        def get_status(self):
            return b"", b"squid broken"

        def _wait_for_http_listener(self, *, timeout) -> bool:
            return False

        def restore_last_known_good_config(self, *, reason):
            assert "squid broken" in reason
            return True, "rolled back"

    class Registry:
        def mark_apply_result(self, proxy_id, *, ok, detail, current_config_sha):
            marked.append((ok, detail, current_config_sha))
            return SimpleNamespace(proxy_id=proxy_id)

    runtime.controller = Controller()
    runtime.registry = Registry()
    runtime.services = SimpleNamespace(current_config_sha_reader=lambda: "good-sha")
    runtime._invalidate_health_cache = lambda: None

    result = runtime.self_heal_config_if_needed(reason="test")

    assert result["ok"] is True
    assert result["rolled_back"] is True
    assert marked == [(True, "rolled back", "good-sha")]


def test_runtime_service_self_heal_restarts_unhealthy_adblock(monkeypatch) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    runtime._supervisor_program_status = lambda program, timeout_seconds=5: (
        False,
        "cicap_adblock BACKOFF",
    )
    runtime._restart_adblock_service = lambda: (True, "cicap_adblock restarted")
    monkeypatch.setattr(
        runtime_module,
        "_check_icap_adblock",
        lambda **_kwargs: {"ok": False, "detail": "not listening"},
    )

    result = runtime.self_heal_runtime_services_if_needed(reason="test")

    assert result["ok"] is True
    assert result["changed"] is True
    assert "BACKOFF" in result["detail"]
    assert "not listening" in result["detail"]


def test_sync_from_db_quarantines_previously_failed_active_revision_without_retry() -> (
    None
):
    runtime = _runtime_shell()
    marked: list[tuple[bool, str, str]] = []

    class Revisions:
        def get_active_revision_metadata(self, _proxy_id):
            return SimpleNamespace(revision_id=9, config_sha256="desired-sha")

        def latest_apply(self, _proxy_id):
            return SimpleNamespace(revision_id=9, ok=False)

        def get_active_revision(self, _proxy_id) -> NoReturn:
            msg = "failed active revision should not be retried without force"
            raise AssertionError(msg)

    class Registry:
        def mark_apply_result(self, proxy_id, *, ok, detail, current_config_sha):
            marked.append((ok, detail, current_config_sha))
            return SimpleNamespace(proxy_id=proxy_id)

    runtime.revisions = Revisions()
    runtime.registry = Registry()
    runtime._invalidate_health_cache = lambda: None
    runtime.ensure_registered = lambda: None
    runtime.bootstrap_revision_if_missing = lambda: None
    runtime.sync_certificate_bundle = lambda force=False: {"ok": True, "changed": False}
    runtime.sync_policy_state = lambda force=False: {
        "ok": True,
        "changed": False,
        "reload_required": False,
    }
    runtime.sync_adblock_state = lambda force=False: {"ok": True, "changed": False}
    runtime.sync_pac_state = lambda force=False: {"ok": True, "changed": False}
    runtime._current_config_sha = lambda: "last-good-sha"

    result = runtime.sync_from_db(force=False)

    assert result["ok"] is False
    assert result["rollback_active"] is True
    assert result["config_changed"] is False
    assert "previously failed" in result["detail"]
    assert marked == [(False, result["detail"], "last-good-sha")]


def test_sync_from_db_reconfigures_squid_after_adblock_artifact_change() -> None:
    runtime = _runtime_shell()
    reloads: list[bool] = []
    marked: list[tuple[bool, str, str]] = []

    class Revisions:
        def get_active_revision_metadata(self, _proxy_id):
            return SimpleNamespace(revision_id=9, config_sha256="current-sha")

        def latest_apply(self, _proxy_id) -> NoReturn:
            msg = "matching current config should not inspect failed apply history"
            raise AssertionError(msg)

        def get_active_revision(
            self, _proxy_id
        ) -> NoReturn:  # pragma: no cover - should not be reached
            msg = "current config should not be reapplied"
            raise AssertionError(msg)

    class Registry:
        def mark_apply_result(self, proxy_id, *, ok, detail, current_config_sha):
            marked.append((ok, detail, current_config_sha))
            return SimpleNamespace(proxy_id=proxy_id)

    runtime.revisions = Revisions()
    runtime.registry = Registry()
    runtime._invalidate_health_cache = lambda: None
    runtime.ensure_registered = lambda: None
    runtime.bootstrap_revision_if_missing = lambda: None
    runtime.sync_certificate_bundle = lambda force=False: {"ok": True, "changed": False}
    runtime.sync_policy_state = lambda force=False: {
        "ok": True,
        "changed": False,
        "reload_required": False,
    }
    runtime.sync_adblock_state = lambda force=False: {
        "ok": True,
        "changed": True,
        "adblock_changed": True,
        "detail": "Adblock artifact applied.",
    }
    runtime.sync_pac_state = lambda force=False: {"ok": True, "changed": False}
    runtime._current_config_sha = lambda: "current-sha"
    runtime._reload_for_policy_update = lambda: (
        reloads.append(True)
        or (
            True,
            "Squid reconfigured for policy update.",
        )
    )

    result = runtime.sync_from_db(force=False)

    assert result["ok"] is True
    assert result["config_changed"] is False
    assert result["adblock_changed"] is True
    assert reloads == [True]
    assert "Squid reconfigured for policy update." in result["detail"]
    assert marked == []


def test_sync_from_db_reloads_policy_after_forced_config_apply() -> None:
    runtime = _runtime_shell()
    reloads: list[bool] = []
    applies: list[str] = []
    invalidations: list[bool] = []
    recorded: list[tuple[int, bool, str]] = []

    class Controller:
        def normalize_config_text(self, text):
            return text

        def apply_config_text(self, text):
            applies.append(text)
            return True, "Squid reconfigured."

    class Revisions:
        def get_active_revision_metadata(self, _proxy_id):
            return SimpleNamespace(revision_id=9, config_sha256="active-sha")

        def latest_apply(self, _proxy_id) -> None:
            return None

        def get_active_revision(self, _proxy_id):
            return SimpleNamespace(revision_id=9, config_text="http_port 3128\n")

        def record_apply_result(
            self, _proxy_id, revision_id, *, ok, detail, applied_by
        ):
            recorded.append((revision_id, ok, detail))
            return SimpleNamespace(application_id=44)

    class Registry:
        def mark_apply_result(self, *_args, **_kwargs):
            return SimpleNamespace()

    runtime.controller = Controller()
    runtime.revisions = Revisions()
    runtime.registry = Registry()
    runtime._invalidate_health_cache = lambda: invalidations.append(True)
    runtime.ensure_registered = lambda: None
    runtime.bootstrap_revision_if_missing = lambda: None
    runtime.sync_certificate_bundle = lambda force=False: {"ok": True, "changed": False}
    runtime.sync_policy_state = lambda force=False: {
        "ok": True,
        "changed": True,
        "reload_required": True,
        "detail": "Updated policy files.",
    }
    runtime.sync_adblock_state = lambda force=False: {"ok": True, "changed": False}
    runtime.sync_pac_state = lambda force=False: {"ok": True, "changed": False}
    runtime._current_config_sha = lambda: "current-sha"
    runtime._reload_for_policy_update = lambda: (
        reloads.append(True)
        or (
            True,
            "Squid reconfigured for policy update.",
        )
    )

    result = runtime.sync_from_db(force=True)

    assert result["ok"] is True
    assert result["config_changed"] is True
    assert result["policy_changed"] is True
    assert applies == ["http_port 3128\n"]
    assert len(invalidations) >= 2
    assert reloads == [True]
    assert recorded
    assert "Squid reconfigured for policy update." in recorded[0][2]


def test_reload_for_policy_update_waits_for_adblock_icap_health(monkeypatch) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    calls = {"icap": 0}
    sleeps: list[float] = []

    class Controller:
        def _run(self, args, **_kwargs):
            assert args == ["squid", "-k", "reconfigure"]
            return _cp(0, stdout="reconfigured")

        def _wait_for_http_listener(self, *, timeout) -> bool:
            assert timeout == pytest.approx(10.0)
            return True

    def fake_icap(**_kwargs):
        calls["icap"] += 1
        return {"ok": calls["icap"] >= 2, "detail": "icap ready"}

    runtime.controller = Controller()
    monkeypatch.setattr(runtime_module, "_check_icap_adblock", fake_icap)
    monkeypatch.setattr(runtime_module.time, "sleep", sleeps.append)

    ok, detail = runtime._reload_for_policy_update()

    assert ok is True
    assert "reconfigured" in detail
    assert "Squid reconfigured for policy update." in detail
    assert calls["icap"] == 2
    assert sleeps == [0.5]


def test_reload_for_policy_update_fails_when_adblock_icap_never_recovers(
    monkeypatch,
) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    now = {"value": 0.0}

    class Controller:
        def _run(self, args, **_kwargs):
            assert args == ["squid", "-k", "reconfigure"]
            return _cp(0, stdout="reconfigured")

        def _wait_for_http_listener(self, *, timeout) -> bool:
            assert timeout == pytest.approx(10.0)
            return True

    runtime.controller = Controller()
    monkeypatch.setattr(
        runtime_module,
        "_check_icap_adblock",
        lambda **_kwargs: {"ok": False, "detail": "icap not ready"},
    )
    monkeypatch.setattr(runtime_module.time, "time", lambda: now["value"])
    monkeypatch.setattr(
        runtime_module.time,
        "sleep",
        lambda seconds: now.__setitem__("value", now["value"] + seconds + 1.0),
    )

    ok, detail = runtime._reload_for_policy_update()

    assert ok is False
    assert "reconfigured" in detail
    assert "icap not ready" in detail


def test_squid_controller_rolls_back_to_persisted_config_after_reconfigure_timeout(
    tmp_path, monkeypatch
) -> None:
    _add_repo_paths()
    from services.squid_core import SquidController  # type: ignore

    squid_conf = tmp_path / "squid.conf"
    persisted_conf = tmp_path / "persisted.conf"
    squid_conf.write_text("workers 1\n# good\n", encoding="utf-8")
    persisted_conf.write_text("workers 1\n# good\n", encoding="utf-8")
    calls: list[list[str]] = []

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        if args[:3] == ["squid", "-k", "reconfigure"]:
            raise subprocess.TimeoutExpired(args, timeout=15)
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setenv("SQUID_ICAP_INCLUDE_PATH", str(tmp_path / "20-icap.conf"))
    monkeypatch.setenv("VIRUS_SCAN_CONFIG_PATH", str(tmp_path / "virus_scan.conf"))
    from services.squid_core import (
        _cached_icap_include_path,
        _cached_virus_scan_config_path,
    )

    _cached_icap_include_path.cache_clear()
    _cached_virus_scan_config_path.cache_clear()
    controller = SquidController(str(squid_conf), cmd_run=fake_run)
    controller.persisted_squid_conf_path = str(persisted_conf)
    monkeypatch.setattr(
        controller, "_wait_for_http_listener_absent", lambda *, timeout: True
    )
    monkeypatch.setattr(controller, "_wait_for_http_listener", lambda *, timeout: True)

    ok, detail = controller.apply_config_text("workers 1\n# bad-but-parseable\n")

    assert ok is False
    assert "timed out" in detail.lower()
    assert "Rolled back to last-known-good" in detail
    restored = squid_conf.read_text(encoding="utf-8")
    assert "# good" in restored
    assert "bad-but-parseable" not in restored


def test_squid_controller_validation_timeout_returns_actionable_detail(
    tmp_path,
) -> None:
    _add_repo_paths()
    from services.squid_core import SquidController  # type: ignore

    def fake_run(args, **_kwargs) -> NoReturn:
        raise subprocess.TimeoutExpired(args, timeout=15)

    controller = SquidController(str(tmp_path / "squid.conf"), cmd_run=fake_run)

    ok, detail = controller.validate_config_text("workers 1\n")

    assert ok is False
    assert detail == "Squid config validation timed out after 15 seconds."


def test_squid_controller_extracts_all_http_listener_ports(tmp_path) -> None:
    _add_repo_paths()
    from services.squid_core import SquidController  # type: ignore

    squid_conf = tmp_path / "squid.conf"
    squid_conf.write_text(
        """
http_port 0.0.0.0:3128 ssl-bump \\
    cert=/etc/squid/ssl/certs/ca.crt \\
    key=/etc/squid/ssl/certs/ca.key
http_port 0.0.0.0:3129 intercept
http_port 3130 tproxy
""".strip()
        + "\n",
        encoding="utf-8",
    )

    controller = SquidController(str(squid_conf))

    assert controller._http_listener_details() == (
        {"port": 3128, "mode": "explicit"},
        {"port": 3129, "mode": "intercept"},
        {"port": 3130, "mode": "tproxy"},
    )
    assert controller._http_listener_ports() == (3128, 3129, 3130)
    assert controller._http_listener_port() == 3128


def test_squid_controller_removes_stale_pidfile_before_restart(
    monkeypatch, tmp_path
) -> None:
    _add_repo_paths()
    from services import squid_core  # type: ignore
    from services.squid_core import SquidController  # type: ignore

    calls: list[list[str]] = []
    unlinked: list[str] = []

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        return _cp(0, stdout="ok")

    controller = SquidController(str(tmp_path / "squid.conf"), cmd_run=fake_run)
    monkeypatch.setattr(
        controller, "_wait_for_http_listener_absent", lambda *, timeout: True
    )
    monkeypatch.setattr(controller, "_wait_for_http_listener", lambda *, timeout: True)
    monkeypatch.setattr(
        squid_core.os.path, "exists", lambda path: path == "/var/run/squid.pid"
    )
    monkeypatch.setattr(squid_core.Path, "read_text", lambda self, **_kwargs: "12345")
    monkeypatch.setattr(squid_core.os, "unlink", unlinked.append)

    ok, detail = controller.restart_squid()

    assert ok is True
    assert unlinked == ["/var/run/squid.pid"]
    assert "Removed stale Squid PID file" in detail
    assert calls[-1][:4] == ["supervisorctl", "-c", "/etc/supervisord.conf", "start"]


def test_sync_adblock_state_rolls_back_compiled_artifact_when_cicap_restart_fails(
    tmp_path, monkeypatch
) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    compiled = tmp_path / "compiled"
    compiled.mkdir()
    (compiled / ".artifact-sha256").write_text("old-sha", encoding="utf-8")
    (compiled / "domains_block.txt").write_text("old.example\n", encoding="utf-8")
    recorded: list[dict[str, object]] = []
    restarts = iter([(False, "cicap_adblock BACKOFF"), (True, "cicap_adblock RUNNING")])

    class Artifacts:
        compiled_dir = str(compiled)

        def get_active_artifact_metadata(self):
            return SimpleNamespace(revision_id=42, artifact_sha256="new-sha")

        def get_active_artifact(self):
            return SimpleNamespace(
                revision_id=42, artifact_sha256="new-sha", archive_blob=b"new"
            )

        def record_apply_result(
            self, proxy_id, revision_id, *, ok, detail, applied_by, artifact_sha256
        ):
            recorded.append(
                {
                    "proxy_id": proxy_id,
                    "revision_id": revision_id,
                    "ok": ok,
                    "detail": detail,
                    "artifact_sha256": artifact_sha256,
                },
            )
            return SimpleNamespace(application_id=77)

    class Store:
        def init_db(self) -> None:
            pass

        def get_cache_flush_requested(self) -> bool:
            return False

    def fake_materialize(directory, *, archive_blob, artifact_sha256) -> None:
        root = Path(directory)
        root.mkdir(parents=True, exist_ok=True)
        (root / ".artifact-sha256").write_text(artifact_sha256, encoding="utf-8")
        (root / "domains_block.txt").write_text("bad.example\n", encoding="utf-8")

    runtime = _runtime_shell()
    runtime.services = SimpleNamespace(current_adblock_sha_reader=lambda: "old-sha")
    runtime.adblock_artifacts = Artifacts()
    runtime.adblock_store = Store()
    runtime.adblock_compiled_dir = str(compiled)
    runtime._restart_adblock_service = lambda: next(restarts)

    monkeypatch.setattr(
        runtime_module, "materialize_archive_to_directory", fake_materialize
    )

    result = runtime.sync_adblock_state(force=True)

    assert result["ok"] is False
    assert result["artifact_rolled_back"] is True
    assert "Restored previous adblock compiled artifact" in result["detail"]
    assert (compiled / ".artifact-sha256").read_text(encoding="utf-8") == "old-sha"
    assert (compiled / "domains_block.txt").read_text(
        encoding="utf-8"
    ) == "old.example\n"
    assert recorded[-1]["ok"] is False


def test_sync_adblock_state_force_does_not_restart_when_artifact_is_current() -> None:
    class Artifacts:
        def get_active_artifact_metadata(self):
            return SimpleNamespace(revision_id=42, artifact_sha256="same-sha")

        def get_active_artifact(
            self,
        ) -> NoReturn:  # pragma: no cover - should not be reached
            msg = "current artifact should not be fetched for a no-op force sync"
            raise AssertionError(msg)

        def record_apply_result(
            self, *args, **kwargs
        ) -> NoReturn:  # pragma: no cover - should not be reached
            msg = "no-op force sync should not record an adblock apply"
            raise AssertionError(msg)

    class Store:
        def init_db(self) -> None:
            pass

        def get_cache_flush_requested(self) -> bool:
            return False

    restarts = []
    runtime = _runtime_shell()
    runtime.services = SimpleNamespace(current_adblock_sha_reader=lambda: "same-sha")
    runtime.adblock_artifacts = Artifacts()
    runtime.adblock_store = Store()
    runtime._restart_adblock_service = lambda: (
        restarts.append(True)
        or (
            True,
            "restarted",
        )
    )

    result = runtime.sync_adblock_state(force=True)

    assert result["ok"] is True
    assert result["changed"] is False
    assert result["artifact_changed"] is False
    assert restarts == []


def test_sync_adblock_state_reports_cache_flush_as_runtime_change() -> None:
    recorded = []

    class Artifacts:
        def get_active_artifact_metadata(self):
            return SimpleNamespace(revision_id=42, artifact_sha256="same-sha")

        def get_active_artifact(self):
            return SimpleNamespace(
                revision_id=42, artifact_sha256="same-sha", archive_blob=b""
            )

        def record_apply_result(self, proxy_id, revision_id, **kwargs):
            recorded.append(
                {"proxy_id": proxy_id, "revision_id": revision_id, **kwargs}
            )
            return SimpleNamespace(application_id=7)

    class Store:
        def init_db(self) -> None:
            pass

        def get_cache_flush_requested(self) -> bool:
            return True

        def mark_cache_flushed(self, *, size=0) -> None:
            recorded.append({"cache_flushed_size": size})

    runtime = _runtime_shell()
    runtime.services = SimpleNamespace(current_adblock_sha_reader=lambda: "same-sha")
    runtime.adblock_artifacts = Artifacts()
    runtime.adblock_store = Store()
    runtime._restart_adblock_service = lambda: (True, "restarted")

    result = runtime.sync_adblock_state(force=False)

    assert result["ok"] is True
    assert result["changed"] is True
    assert result["adblock_changed"] is True
    assert result["artifact_changed"] is False
    assert result["cache_flushed"] is True
    assert recorded[-1]["ok"] is True


def test_collect_health_returns_stale_cache_during_inflight_refresh() -> None:
    runtime = _runtime_shell()
    runtime.health_cache_ttl_seconds = 3.0
    runtime._health_cache_lock = __import__("threading").Lock()
    runtime._health_refresh_lock = __import__("threading").Lock()
    runtime._health_cache_ts = 0.0
    runtime._health_cache_value = {"ok": True, "status": "healthy", "timestamp": 1}
    runtime._health_refresh_lock.acquire()
    try:
        result = runtime.collect_health()
    finally:
        runtime._health_refresh_lock.release()

    assert result["ok"] is True
    assert result["health_cache_stale"] is True
    assert "refresh was already in progress" in result["health_cache_detail"]


def test_collect_health_serializes_cold_refresh(monkeypatch) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    runtime.health_cache_ttl_seconds = 3.0
    runtime._health_cache_lock = runtime_module.threading.Lock()
    runtime._health_refresh_lock = runtime_module.threading.Lock()
    runtime._health_cache_ts = 0.0
    runtime._health_cache_value = None
    runtime.controller = SimpleNamespace(
        get_status=lambda: (b"squid ok", b""),
        _http_listener_details=lambda: ({"port": 3128, "mode": "explicit"},),
        _wait_for_http_listener=lambda *, timeout: True,
    )
    runtime.stats_provider = dict
    runtime.runtime_services_builder = lambda **_kwargs: {"icap": {"ok": True}}
    runtime._supervisor_programs_health = lambda: {
        "ok": True,
        "detail": "supervisor programs running",
        "programs": {},
    }
    runtime.revisions = SimpleNamespace(
        get_active_revision_metadata=lambda _proxy_id: None
    )
    runtime.certificate_bundles = SimpleNamespace(
        get_active_bundle_metadata=lambda: None
    )
    runtime.adblock_artifacts = SimpleNamespace(
        get_active_artifact_metadata=lambda: None
    )
    runtime._current_config_sha = lambda: "config-sha"
    runtime._current_certificate_bundle_sha = lambda: "cert-sha"
    runtime._current_adblock_artifact_sha = lambda: "adblock-sha"
    runtime._current_pac_state_sha = lambda: "pac-sha"
    runtime._current_policy_sha = lambda: "policy-sha"
    runtime._read_text_file = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        AssertionError(
            "collect_health should use _current_policy_sha() instead of reading policy files"
        ),
    )
    runtime.policy_state_builder = lambda _proxy_id: SimpleNamespace(
        policy_sha256="policy-sha", files=()
    )
    runtime.pac_state_builder = lambda _proxy_id: SimpleNamespace(
        state_sha256="desired-pac-sha"
    )

    result = runtime.collect_health()

    assert result["ok"] is True
    assert result["status"] == "healthy"
    assert result["current_policy_sha"] == "policy-sha"
    assert result["health_elapsed_seconds"] >= 0
    assert runtime._health_cache_value is result


def test_local_runtime_service_health_checks_run_in_parallel(monkeypatch) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    calls: list[str] = []

    def slow_ok(name):
        def _inner(**_kwargs):
            calls.append(name)
            runtime_module.time.sleep(0.05)
            return {"ok": True, "detail": name}

        return _inner

    monkeypatch.setattr(runtime_module, "_check_icap_adblock", slow_ok("icap"))
    monkeypatch.setattr(runtime_module, "_check_icap_av", slow_ok("av_icap"))
    monkeypatch.setattr(runtime_module, "_check_clamd", slow_ok("clamd"))
    started = runtime_module.time.monotonic()

    result = runtime_module.build_local_runtime_services(icap_timeout=0.8)

    assert set(calls) == {"icap", "av_icap", "clamd"}
    assert runtime_module.time.monotonic() - started < 0.13
    assert result["clamav"]["ok"] is True


def test_supervisor_programs_health_uses_single_status_call(monkeypatch) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    calls: list[list[str]] = []

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        return _cp(
            0,
            stdout=(
                "squid RUNNING pid 1\n"
                "cicap_adblock RUNNING pid 2\n"
                "cicap_av RUNNING pid 3\n"
                "proxy_api RUNNING pid 4\n"
                "proxy_agent RUNNING pid 5\n"
            ),
        )

    monkeypatch.setattr(runtime_module.subprocess, "run", fake_run)

    result = runtime._supervisor_programs_health()

    assert result["ok"] is True
    assert len(calls) == 1
    assert calls[0][:4] == ["supervisorctl", "-c", "/etc/supervisord.conf", "status"]


def test_packaged_proxy_healthcheck_treats_clamav_as_optional_by_default() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    healthcheck = (repo_root / "docker" / "healthcheck.sh").read_text(
        encoding="utf-8",
    )

    assert "clamav_required()" in healthcheck
    assert "supervisor reports cicap_adblock is not RUNNING" in healthcheck
    assert "CLAMAV_REQUIRED is set but supervisor reports cicap_av is not RUNNING" in healthcheck
    assert "CLAMAV_REQUIRED is set but remote clamd is not responding" in healthcheck
    assert "supervisor_program_running cicap_adblock || ! supervisor_program_running cicap_av" not in healthcheck


def test_packaged_proxy_entrypoint_does_not_wait_for_optional_clamav() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    entrypoint = (repo_root / "docker" / "entrypoint.sh").read_text(
        encoding="utf-8",
    )

    assert "CLAMAV_REQUIRED=0" in entrypoint
    assert "optional ClamAV backend" in entrypoint
    assert "exec sleep infinity" in entrypoint
    assert "i=0; while [ $i -lt 120 ]; do ping_clamd" in entrypoint


def test_squid_reload_treats_successful_stderr_warnings_as_detail() -> None:
    _add_repo_paths()
    from services.squid_core import SquidController  # type: ignore

    controller = SquidController.__new__(SquidController)
    controller._run = lambda *_args, **_kwargs: _cp(
        0, stdout="", stderr="WARNING: benign squid warning"
    )
    controller._wait_for_http_listener = lambda **_kwargs: True

    stdout, stderr = controller.reload_squid()

    assert stderr == b""
    assert b"WARNING: benign squid warning" in stdout


def test_squid_reload_preserves_nonzero_reconfigure_failure() -> None:
    _add_repo_paths()
    from services.squid_core import SquidController  # type: ignore

    controller = SquidController.__new__(SquidController)
    controller._run = lambda *_args, **_kwargs: _cp(
        1, stdout="", stderr="fatal squid error"
    )
    controller._wait_for_http_listener = lambda **_kwargs: True

    stdout, stderr = controller.reload_squid()

    assert stdout == b""
    assert b"fatal squid error" in stderr


def test_sync_from_db_reconfigures_squid_after_runtime_icap_include_change() -> None:
    runtime = _runtime_shell()
    reloads: list[bool] = []

    class Controller:
        def set_adblock_icap_revision_token(self, token) -> None:
            self.token = token

        def materialize_clamav_runtime_files(self, config_text):
            assert config_text == "http_port 3128\n"
            return True, "ClamAV runtime files updated: /etc/squid/conf.d/20-icap.conf"

    class Revisions:
        def get_active_revision_metadata(self, _proxy_id):
            return SimpleNamespace(revision_id=9, config_sha256="current-sha")

        def latest_apply(self, _proxy_id) -> None:
            return None

        def get_active_revision(
            self, _proxy_id
        ) -> NoReturn:  # pragma: no cover - should not be reached
            msg = "current config should not be reapplied"
            raise AssertionError(msg)

    class Registry:
        def mark_apply_result(self, *_args, **_kwargs) -> NoReturn:
            msg = "successful runtime include reload should not mark failed apply"
            raise AssertionError(msg)

    runtime.controller = Controller()
    runtime.revisions = Revisions()
    runtime.registry = Registry()
    runtime._invalidate_health_cache = lambda: None
    runtime.ensure_registered = lambda: None
    runtime.bootstrap_revision_if_missing = lambda: None
    runtime.sync_certificate_bundle = lambda force=False: {"ok": True, "changed": False}
    runtime.sync_policy_state = lambda force=False: {
        "ok": True,
        "changed": False,
        "reload_required": False,
    }
    runtime.sync_adblock_state = lambda force=False: {
        "ok": True,
        "changed": False,
        "artifact_sha256": "adblock-sha",
    }
    runtime.sync_pac_state = lambda force=False: {"ok": True, "changed": False}
    runtime._current_config_sha = lambda: "current-sha"
    runtime.controller.get_current_config = lambda: "http_port 3128\n"
    runtime._reload_for_policy_update = lambda: (
        reloads.append(True)
        or (
            True,
            "Squid reconfigured for policy update.",
        )
    )

    result = runtime.sync_from_db(force=False)

    assert result["ok"] is True
    assert result["changed"] is True
    assert reloads == [True]
    assert runtime.controller.token == "adblock-sha"
    assert "ClamAV runtime files updated" in result["detail"]
    assert "Squid reconfigured for policy update." in result["detail"]


def test_sync_from_db_normalizes_policy_runtime_includes_before_reconfigure() -> None:
    runtime = _runtime_shell()
    reloads: list[bool] = []

    class Controller:
        def __init__(self) -> None:
            self.config = (
                "icap_service adblock_req reqmod_precache icap://127.0.0.1:14000/adblockreq bypass=on\n"
                "adaptation_access adblock_req_set allow all\n"
                "http_access allow all\n"
            )
            self.applied: list[str] = []

        def set_adblock_icap_revision_token(self, token) -> None:
            self.token = token

        def materialize_clamav_runtime_files(self, _config_text):
            return True, ""

        def get_current_config(self):
            return self.config

        def normalize_config_text(self, text) -> str:
            assert "icap_service adblock_req" in text
            return "include /etc/squid/conf.d/20-icap.conf\ninclude /etc/squid/conf.d/30-webfilter.conf\nhttp_access allow all\n"

        def apply_config_text(self, text):
            self.applied.append(text)
            self.config = text
            return True, "Squid config normalized for generated policy includes."

    class Revisions:
        def get_active_revision_metadata(self, _proxy_id):
            return SimpleNamespace(revision_id=9, config_sha256="normalized-sha")

        def latest_apply(self, _proxy_id) -> None:
            return None

    class Registry:
        def mark_apply_result(self, *_args, **_kwargs) -> NoReturn:
            msg = (
                "successful runtime include normalization should not mark failed apply"
            )
            raise AssertionError(msg)

    controller = Controller()
    runtime.controller = controller
    runtime.revisions = Revisions()
    runtime.registry = Registry()
    runtime._invalidate_health_cache = lambda: None
    runtime.ensure_registered = lambda: None
    runtime.bootstrap_revision_if_missing = lambda: None
    runtime.sync_certificate_bundle = lambda force=False: {"ok": True, "changed": False}
    runtime.sync_policy_state = lambda force=False: {
        "ok": True,
        "changed": True,
        "reload_required": True,
    }
    runtime.sync_adblock_state = lambda force=False: {
        "ok": True,
        "changed": True,
        "artifact_sha256": "adblock-sha",
    }
    runtime.sync_pac_state = lambda force=False: {"ok": True, "changed": False}
    runtime._current_config_sha = lambda: "normalized-sha"
    runtime._reload_for_policy_update = lambda: (
        reloads.append(True)
        or (
            True,
            "Squid reconfigured for policy update.",
        )
    )

    result = runtime.sync_from_db(force=False)

    assert result["ok"] is True
    assert controller.applied == [
        (
            "include /etc/squid/conf.d/20-icap.conf\n"
            "include /etc/squid/conf.d/30-webfilter.conf\n"
            "http_access allow all\n"
        ),
    ]
    assert reloads == [True]
    assert "Squid config normalized for generated policy includes." in result["detail"]
    assert "Squid reconfigured for policy update." in result["detail"]


def test_sync_from_db_claims_and_marks_operation_ledger(monkeypatch) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    monkeypatch.setattr(runtime_module, "get_proxy_id", lambda: "edge-a")
    op = SimpleNamespace(operation_id=5)
    calls: list[tuple[str, object]] = []

    class Ledger:
        def requeue_stale_applying(self, proxy_id) -> None:
            calls.append(("requeue", proxy_id))

        def claim_pending(self, proxy_id, *, limit, operation_id=None):
            calls.append(("claim", (proxy_id, limit, operation_id)))
            return [op]

        def mark_many(self, operations, *, status, detail) -> None:
            calls.append(("mark", (operations, status, detail)))

    monkeypatch.setattr(runtime_module, "get_operation_ledger", Ledger)
    runtime._sync_from_db_unlocked = lambda *, force=False, operations=None: {
        "ok": True,
        "detail": "runtime reconciled",
        "claimed_operation_ids": [op.operation_id for op in (operations or [])],
    }

    result = runtime.sync_from_db(force=False)

    assert result["ok"] is True
    assert calls == [
        ("requeue", "edge-a"),
        ("claim", ("edge-a", 100, None)),
        ("mark", ([op], "applied", "runtime reconciled")),
    ]
