from __future__ import annotations

import contextlib
import hashlib
import os
import re
import sqlite3
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import NoReturn

import pytest


def _healthcheck_forwarding_canary_url_script() -> str:
    repo_root = Path(__file__).resolve().parents[2]
    healthcheck = (repo_root / "docker" / "healthcheck.sh").read_text(
        encoding="utf-8",
    )
    match = re.search(
        r"^def forwarding_canary_url\(\) -> str:\n(?P<body>.*?)^target_url = forwarding_canary_url\(\)",
        healthcheck,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert match is not None
    return (
        "import ipaddress\n"
        "import os\n"
        "def forwarding_canary_url() -> str:\n"
        + match.group("body")
        + "print(forwarding_canary_url())\n"
    )


def _healthcheck_forwarding_canary_url(**env_overrides: str) -> str:
    result = subprocess.run(
        [sys.executable, "-c", _healthcheck_forwarding_canary_url_script()],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, **env_overrides},
    )
    return result.stdout.strip()


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

    runtime = ProxyRuntime.__new__(ProxyRuntime)
    runtime._operation_ledger_health = lambda: {
        "ok": True,
        "detail": "operation ledger reachable; pending=0 applying=0 failed=0",
        "counts": {},
    }
    return runtime


def _cp(returncode: int, stdout: str = "", stderr: str = ""):
    return SimpleNamespace(
        returncode=returncode,
        stdout=stdout.encode("utf-8"),
        stderr=stderr.encode("utf-8"),
    )


def _write_adblock_lookup_metadata(path: Path, *, count_rules: int) -> None:
    conn = sqlite3.connect(str(path))
    try:
        conn.execute("CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT)")
        conn.execute(
            "INSERT INTO metadata(key, value) VALUES('count_rules', ?)",
            (str(int(count_rules)),),
        )
        conn.commit()
    finally:
        conn.close()


def test_sync_policy_state_failure_reports_desired_and_current_sha(
    tmp_path,
    monkeypatch,
) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    runtime.policy_state_builder = lambda _proxy_id: SimpleNamespace(
        policy_sha256="desired-policy-shaabcdef",
        files=(SimpleNamespace(path=str(tmp_path / "policy.conf"), content="new\n"),),
    )
    runtime._current_policy_sha = lambda: "current-policy-shaxyz"
    runtime._read_text_file = lambda _path: "old\n"

    def fail_policy_write(*_files) -> NoReturn:
        msg = "read-only policy directory"
        raise PermissionError(msg)

    monkeypatch.setattr(runtime_module, "write_managed_text_files", fail_policy_write)

    result = runtime.sync_policy_state()

    assert result["ok"] is False
    assert result["policy_sha256"] == "desired-policy-shaabcdef"
    assert result["current_policy_sha"] == "current-policy-shaxyz"
    assert "Failed to materialize policy state." in result["detail"]
    assert (
        "policy: desired desired-poli does not match current current-poli."
        in result["detail"]
    )


def test_sync_policy_state_rolls_back_partial_policy_materialization(
    tmp_path,
    monkeypatch,
) -> None:
    _add_repo_paths()
    from services import materialized_files  # type: ignore

    first = tmp_path / "10-sslfilter.conf"
    second = tmp_path / "30-webfilter.conf"
    first.write_text("old ssl policy\n", encoding="utf-8")
    second.write_text("old web policy\n", encoding="utf-8")
    real_replace = materialized_files.os.replace

    def flaky_replace(src, dst) -> None:
        if str(dst) == str(second):
            msg = "disk full during webfilter policy update"
            raise OSError(msg)
        real_replace(src, dst)

    monkeypatch.setattr(materialized_files.os, "replace", flaky_replace)

    runtime = _runtime_shell()
    runtime.policy_state_builder = lambda _proxy_id: SimpleNamespace(
        policy_sha256="desired-policy-sha",
        files=(
            SimpleNamespace(path=str(first), content="new ssl policy\n"),
            SimpleNamespace(path=str(second), content="new web policy\n"),
        ),
    )
    runtime._current_policy_sha = lambda: "current-policy-sha"

    result = runtime.sync_policy_state()

    assert result["ok"] is False
    assert "Failed to materialize policy state." in result["detail"]
    assert first.read_text(encoding="utf-8") == "old ssl policy\n"
    assert second.read_text(encoding="utf-8") == "old web policy\n"


def test_sync_policy_state_reapplies_missing_empty_materialized_file(tmp_path) -> None:
    missing_empty = tmp_path / "sslfilter_nobump.txt"
    policy_conf = tmp_path / "policy.conf"
    policy_conf.write_text("include policy\n", encoding="utf-8")
    desired_files = (
        SimpleNamespace(path=str(policy_conf), content="include policy\n"),
        SimpleNamespace(path=str(missing_empty), content=""),
    )
    runtime = _runtime_shell()
    runtime.policy_state_builder = lambda _proxy_id: SimpleNamespace(
        policy_sha256="same-policy-sha",
        files=desired_files,
    )
    runtime._current_policy_sha = lambda: "same-policy-sha"

    result = runtime.sync_policy_state()

    assert result["ok"] is True
    assert result["changed"] is True
    assert result["reload_required"] is True
    assert missing_empty.exists()
    assert missing_empty.read_text(encoding="utf-8") == ""
    assert "policy materialized file is missing" in result["detail"]


def test_sync_pac_state_failure_reports_desired_and_current_sha(monkeypatch) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    runtime.pac_state_builder = lambda _proxy_id: SimpleNamespace(
        state_sha256="desired-pac-shaabcdef"
    )
    runtime._current_pac_state_sha = lambda: "current-pac-shaxyz"
    runtime.pac_render_dir = "/unwritable/pac"

    def fail_materialize(*_args, **_kwargs) -> None:
        msg = "read-only PAC directory"
        raise PermissionError(msg)

    monkeypatch.setattr(runtime_module, "materialize_proxy_pac_state", fail_materialize)

    result = runtime.sync_pac_state()

    assert result["ok"] is False
    assert result["state_sha256"] == "desired-pac-shaabcdef"
    assert result["current_state_sha256"] == "current-pac-shaxyz"
    assert "Failed to materialize PAC state." in result["detail"]
    assert (
        "PAC: desired desired-pac- does not match current current-pac-."
        in result["detail"]
    )


def test_sync_pac_state_force_does_not_churn_intact_materialization(
    tmp_path,
    monkeypatch,
) -> None:
    _add_repo_paths()
    from services import pac_renderer  # type: ignore

    import proxy.runtime as runtime_module  # type: ignore

    state = pac_renderer.ProxyPacState(
        proxy_id="live",
        state_sha256="same-pac-sha",
        files=(
            pac_renderer.RenderedPacFile(
                relative_path="fallback.pac",
                content="PAC content\n",
            ),
            pac_renderer.RenderedPacFile(
                relative_path=pac_renderer.PAC_STATE_SHA_FILENAME,
                content="same-pac-sha\n",
            ),
        ),
    )
    pac_dir = tmp_path / "pac"
    pac_renderer.materialize_proxy_pac_state(pac_dir, state=state)

    def fail_materialize(*_args, **_kwargs) -> None:
        msg = "intact PAC materialization should not be rewritten"
        raise AssertionError(msg)

    runtime = _runtime_shell()
    runtime.pac_render_dir = str(pac_dir)
    runtime.pac_state_builder = lambda _proxy_id: state
    runtime._current_pac_state_sha = lambda: "same-pac-sha"
    monkeypatch.setattr(runtime_module, "materialize_proxy_pac_state", fail_materialize)

    result = runtime.sync_pac_state(force=True)

    assert result["ok"] is True
    assert result["changed"] is False
    assert result["state_sha256"] == "same-pac-sha"


def test_sync_pac_state_reapplies_when_marker_matches_but_file_missing(
    tmp_path,
) -> None:
    _add_repo_paths()
    from services import pac_renderer  # type: ignore

    state = pac_renderer.ProxyPacState(
        proxy_id="live",
        state_sha256="same-pac-sha",
        files=(
            pac_renderer.RenderedPacFile(
                relative_path="fallback.pac",
                content="PAC content\n",
            ),
            pac_renderer.RenderedPacFile(
                relative_path=pac_renderer.PAC_STATE_SHA_FILENAME,
                content="same-pac-sha\n",
            ),
        ),
    )
    pac_dir = tmp_path / "pac"
    pac_dir.mkdir()
    (pac_dir / pac_renderer.PAC_STATE_SHA_FILENAME).write_text(
        "same-pac-sha\n",
        encoding="utf-8",
    )

    runtime = _runtime_shell()
    runtime.pac_render_dir = str(pac_dir)
    runtime.pac_state_builder = lambda _proxy_id: state
    runtime._current_pac_state_sha = lambda: "same-pac-sha"

    result = runtime.sync_pac_state(force=True)

    assert result["ok"] is True
    assert result["changed"] is True
    assert result["previous_state_sha256"] == "same-pac-sha"
    assert "PAC materialized file is missing: fallback.pac" in result["detail"]
    assert (pac_dir / "fallback.pac").read_text(encoding="utf-8") == "PAC content\n"


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


def test_supervisor_program_status_accepts_scaled_icap_helpers(monkeypatch) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    monkeypatch.setattr(
        runtime_module.subprocess,
        "run",
        lambda *_args, **_kwargs: _cp(
            0,
            stdout=(
                "cicap_adblock_1 RUNNING pid 10, uptime 0:00:11\n"
                "cicap_adblock_2 RUNNING pid 11, uptime 0:00:10\n"
                "cicap_av_1 RUNNING pid 12, uptime 0:00:09\n"
                "proxy_api RUNNING pid 13, uptime 0:00:08\n"
            ),
        ),
    )

    ok, detail = _runtime_shell()._supervisor_program_status("cicap_adblock")

    assert ok is True
    assert "cicap_adblock_1 RUNNING" in detail
    assert "cicap_adblock_2 RUNNING" in detail
    assert "no such process" not in detail


def test_restart_supervisor_program_restarts_scaled_icap_helpers(monkeypatch) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    calls: list[tuple[str, str | None]] = []
    started: set[str] = set()

    def fake_run(args, **_kwargs):
        action = args[3]
        program = args[4] if len(args) > 4 else None
        calls.append((action, program))
        if program == "cicap_adblock":
            return _cp(2, stdout="cicap_adblock: ERROR (no such process)\n")
        if action == "status" and program is None:
            return _cp(
                0,
                stdout=(
                    "cicap_adblock_1 RUNNING pid 10, uptime 0:00:11\n"
                    "cicap_adblock_2 RUNNING pid 11, uptime 0:00:10\n"
                ),
            )
        if action == "status":
            state = (
                "RUNNING pid 42, uptime 0:00:01"
                if program in started
                else "STOPPED Jul 03 09:42 PM"
            )
            return _cp(0, stdout=f"{program} {state}\n")
        if action == "start" and program:
            started.add(program)
        return _cp(0, stdout=f"{program}: {action}ped\n")

    monkeypatch.setattr(runtime_module.subprocess, "run", fake_run)

    ok, detail = _runtime_shell()._restart_supervisor_program("cicap_adblock")

    assert ok is True
    assert ("stop", "cicap_adblock_1") in calls
    assert ("start", "cicap_adblock_1") in calls
    assert ("stop", "cicap_adblock_2") in calls
    assert ("start", "cicap_adblock_2") in calls
    assert "cicap_adblock_1" in detail
    assert "cicap_adblock_2" in detail


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
        "http_port 0.0.0.0:3128 ssl-bump\nhttp_port 0.0.0.0:3129 intercept\n"
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


def test_restart_supervisor_program_accepts_starting_after_startsecs_change(
    monkeypatch,
) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    calls: list[list[str]] = []
    monkeypatch.setattr(runtime_module.time, "sleep", lambda _seconds: None)
    results = [
        _cp(0, stdout="cicap_adblock: stopped"),
        _cp(0, stdout="cicap_adblock STOPPED Jun 15 02:17 AM"),
        _cp(0, stdout="cicap_adblock: started"),
        _cp(0, stdout="cicap_adblock STARTING Jun 15 02:17 AM"),
    ]

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        return results.pop(0)

    monkeypatch.setattr(runtime_module.subprocess, "run", fake_run)

    ok, detail = _runtime_shell()._restart_supervisor_program("cicap_adblock")

    assert ok is True
    assert "STARTING" in detail
    assert calls == [
        ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "cicap_adblock"],
        ["supervisorctl", "-c", "/etc/supervisord.conf", "status", "cicap_adblock"],
        ["supervisorctl", "-c", "/etc/supervisord.conf", "start", "cicap_adblock"],
        ["supervisorctl", "-c", "/etc/supervisord.conf", "status", "cicap_adblock"],
    ]


@pytest.mark.parametrize("state", ["BACKOFF", "FATAL"])
def test_restart_supervisor_program_rejects_unstable_post_start_states(
    monkeypatch,
    state: str,
) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    calls: list[list[str]] = []
    monkeypatch.setattr(runtime_module.time, "sleep", lambda _seconds: None)

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        if "stop" in args:
            return _cp(0, stdout="cicap_adblock: stopped")
        if "status" in args:
            if len(calls) == 2:
                return _cp(0, stdout="cicap_adblock STOPPED Jun 15 02:17 AM")
            return _cp(3, stdout=f"cicap_adblock {state} exited too quickly")
        return _cp(0, stdout="cicap_adblock: started")

    monkeypatch.setattr(runtime_module.subprocess, "run", fake_run)

    ok, detail = _runtime_shell()._restart_supervisor_program("cicap_adblock")

    assert ok is False
    assert state in detail
    assert sum(1 for call in calls if "start" in call) == 5


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
    assert result["certificate_revision_id"] == 7
    assert result["certificate_bundle_sha256"] == "same-sha"
    assert result["detail"] == "Proxy is already using the active certificate bundle."


def test_ssl_db_reinitialize_recovers_when_restart_reports_stopped_squid(
    monkeypatch,
    tmp_path,
) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    ssl_db = tmp_path / "ssl_db" / "store"
    calls: list[list[str]] = []

    def fake_run(args, **kwargs):
        calls.append(list(args))
        if args == ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "squid"]:
            return _cp(0, stdout="squid: stopped")
        if args == ["sh", "/scripts/init_ssl_db.sh"]:
            env = kwargs.get("env") or {}
            target = Path(str(env.get("SSL_DB_DIR") or ssl_db))
            (target / "certs").mkdir(parents=True, exist_ok=True)
            (target / "index.txt").touch()
            (target / "size").touch()
            return _cp(0, stdout="initialized")
        if args == ["supervisorctl", "-c", "/etc/supervisord.conf", "start", "squid"]:
            return _cp(0, stdout="squid: started")
        return _cp(0, stdout="ok")

    runtime = _runtime_shell()
    runtime.services = SimpleNamespace(ssl_db_reinitializer=None)
    runtime.ssl_db_dir = str(ssl_db)
    runtime.controller = SimpleNamespace(
        restart_squid=lambda: (
            False,
            "squid: stopped\nsquid: ERROR (not running)\nsquid: ERROR (abnormal termination)",
        ),
        _wait_for_http_listener=lambda *, timeout: True,
    )
    statuses = iter(
        [
            (False, "squid STOPPED Jul 18 02:18 AM"),
            (True, "squid RUNNING pid 42, uptime 0:00:01"),
        ],
    )
    runtime._supervisor_program_status = lambda *_args, **_kwargs: next(statuses)

    monkeypatch.setattr(runtime_module, "subprocess", SimpleNamespace(run=fake_run))
    monkeypatch.setattr(
        runtime_module.pathlib.Path,
        "exists",
        lambda self: str(self) == "/scripts/init_ssl_db.sh",
    )

    ok, detail = runtime._reinitialize_ssl_db_and_restart()

    assert ok is True
    assert "squid: ERROR (not running)" in detail
    assert "squid: started" in detail
    assert "HTTP listener is responding" in detail
    assert ["supervisorctl", "-c", "/etc/supervisord.conf", "start", "squid"] in calls


def test_ssl_db_reinitialize_reports_failure_when_recovery_start_is_not_running(
    monkeypatch,
    tmp_path,
) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    ssl_db = tmp_path / "ssl_db" / "store"

    def fake_run(args, **_kwargs):
        if args == ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "squid"]:
            return _cp(0, stdout="squid: stopped")
        if args == ["sh", "/scripts/init_ssl_db.sh"]:
            return _cp(0, stdout="initialized")
        if args == ["supervisorctl", "-c", "/etc/supervisord.conf", "start", "squid"]:
            return _cp(0, stdout="squid: ERROR (abnormal termination)")
        return _cp(0, stdout="ok")

    runtime = _runtime_shell()
    runtime.services = SimpleNamespace(ssl_db_reinitializer=None)
    runtime.ssl_db_dir = str(ssl_db)
    runtime.controller = SimpleNamespace(
        restart_squid=lambda: (False, "squid: ERROR (abnormal termination)"),
        _wait_for_http_listener=lambda *, timeout: False,
    )
    runtime._supervisor_program_status = lambda *_args, **_kwargs: (
        False,
        "squid BACKOFF Exited too quickly",
    )

    monkeypatch.setattr(runtime_module, "subprocess", SimpleNamespace(run=fake_run))
    monkeypatch.setattr(
        runtime_module.pathlib.Path,
        "exists",
        lambda self: str(self) == "/scripts/init_ssl_db.sh",
    )

    ok, detail = runtime._reinitialize_ssl_db_and_restart()

    assert ok is False
    assert "abnormal termination" in detail
    assert "squid BACKOFF" in detail


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
    assert result["certificate_revision_id"] == 8
    assert result["certificate_bundle_sha256"] == "same-sha"
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
    runtime._supervisor_program_status = lambda program, **_kwargs: (
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


def test_runtime_service_self_heal_defers_transient_adblock_icap_failures(
    monkeypatch,
) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    restarts: list[bool] = []
    runtime._supervisor_program_status = lambda program, **_kwargs: (
        True,
        "cicap_adblock RUNNING pid 123, uptime 0:10:00",
    )
    runtime._restart_adblock_service = lambda: (
        restarts.append(True) or (True, "cicap_adblock restarted")
    )
    monkeypatch.setenv("ADBLOCK_ICAP_SELF_HEAL_FAILURE_THRESHOLD", "3")
    monkeypatch.setenv("ADBLOCK_ICAP_SELF_HEAL_RESTART_COOLDOWN_SECONDS", "0")
    monkeypatch.setattr(
        runtime_module,
        "_check_icap_adblock",
        lambda **_kwargs: {"ok": False, "detail": "temporary timeout"},
    )

    first = runtime.self_heal_runtime_services_if_needed(reason="heartbeat")
    second = runtime.self_heal_runtime_services_if_needed(reason="heartbeat")
    third = runtime.self_heal_runtime_services_if_needed(reason="heartbeat")

    assert first["ok"] is True
    assert first["changed"] is False
    assert "1/3" in first["detail"]
    assert second["ok"] is True
    assert second["changed"] is False
    assert "2/3" in second["detail"]
    assert third["ok"] is True
    assert third["changed"] is True
    assert restarts == [True]


def test_runtime_service_self_heal_waits_for_starting_adblock(monkeypatch) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    status_calls: list[tuple[str, dict[str, object]]] = []

    def supervisor_status(program, **kwargs):
        status_calls.append((program, kwargs))
        return True, "cicap_adblock STARTING Jun 15 02:17 AM"

    runtime._supervisor_program_status = supervisor_status
    runtime._restart_adblock_service = lambda: (_ for _ in ()).throw(
        AssertionError("STARTING cicap_adblock should not be restarted"),
    )
    monkeypatch.setattr(
        runtime_module,
        "_check_icap_adblock",
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("STARTING cicap_adblock should not be probed"),
        ),
    )

    result = runtime.self_heal_runtime_services_if_needed(reason="test")

    assert result["ok"] is True
    assert result["changed"] is False
    assert "STARTING" in result["detail"]
    assert status_calls == [
        (
            "cicap_adblock",
            {
                "timeout_seconds": 5,
                "accepted_states": ("RUNNING", "STARTING"),
            },
        )
    ]


def test_clear_cache_only_clears_disk_cache_without_adblock_restart(
    monkeypatch,
) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    cleared: list[bool] = []
    marked: list[tuple[bool, str, str]] = []

    monkeypatch.setattr(runtime_module, "get_proxy_id", lambda: "edge-a")

    class Registry:
        def mark_apply_result(self, proxy_id, *, ok, detail, current_config_sha):
            marked.append((bool(ok), detail, current_config_sha))
            return SimpleNamespace(proxy_id=proxy_id)

    runtime.controller = SimpleNamespace(
        clear_disk_cache=lambda: (
            cleared.append(True) or (True, "Proxy disk cache cleared.")
        ),
    )
    runtime.registry = Registry()
    runtime._current_config_sha = lambda: "config-sha"
    runtime._invalidate_health_cache = lambda: None
    runtime._restart_adblock_service = lambda: (_ for _ in ()).throw(
        AssertionError("cache clear should not restart cicap_adblock")
    )

    result = runtime.clear_cache()

    assert result["ok"] is True
    assert cleared == [True]
    assert "Proxy disk cache cleared." in result["detail"]
    assert "cicap_adblock" not in result["detail"]
    assert marked == [(True, result["detail"], "config-sha")]


def test_clear_cache_reports_disk_cache_failure_without_adblock_restart(
    monkeypatch,
) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    marked: list[tuple[bool, str, str]] = []

    monkeypatch.setattr(runtime_module, "get_proxy_id", lambda: "edge-a")

    class Registry:
        def mark_apply_result(self, proxy_id, *, ok, detail, current_config_sha):
            marked.append((bool(ok), detail, current_config_sha))
            return SimpleNamespace(proxy_id=proxy_id)

    runtime.controller = SimpleNamespace(clear_disk_cache=lambda: (False, "rm failed"))
    runtime.registry = Registry()
    runtime._current_config_sha = lambda: "config-sha"
    runtime._invalidate_health_cache = lambda: None
    runtime._restart_adblock_service = lambda: (_ for _ in ()).throw(
        AssertionError("cache clear failure should not restart cicap_adblock")
    )

    result = runtime.clear_cache()

    assert result["ok"] is False
    assert result["detail"] == "rm failed"
    assert marked == [(False, result["detail"], "config-sha")]


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


def test_sync_from_db_accepts_normalized_active_revision_before_failed_apply_quarantine() -> (
    None
):
    active_config = "http_port 3128\nacl icap_adblockable method GET HEAD\n"
    normalized_config = "http_port 3128\ninclude /etc/squid/conf.d/20-icap.conf\n"
    active_sha = hashlib.sha256(active_config.encode()).hexdigest()
    normalized_sha = hashlib.sha256(normalized_config.encode()).hexdigest()

    def normalize_config_text(text: str) -> str:
        if "acl icap_adblockable" in text:
            return normalized_config
        return text

    runtime = _runtime_shell()
    runtime.controller = SimpleNamespace(
        get_current_config=lambda: normalized_config,
        normalize_config_text=normalize_config_text,
        apply_config_text=lambda _text: (_ for _ in ()).throw(
            AssertionError("normalized active revision should not be reapplied"),
        ),
    )

    class Revisions:
        def get_active_revision_metadata(self, _proxy_id):
            return SimpleNamespace(revision_id=9, config_sha256=active_sha)

        def get_active_revision(self, _proxy_id):
            return SimpleNamespace(revision_id=9, config_text=active_config)

        def latest_apply(self, _proxy_id) -> NoReturn:
            msg = "normalized current config should bypass failed apply quarantine"
            raise AssertionError(msg)

    class Registry:
        def mark_apply_result(self, *_args, **_kwargs) -> NoReturn:
            msg = "no apply result should be marked for an already-current config"
            raise AssertionError(msg)

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
    runtime._current_config_sha = lambda: normalized_sha
    runtime._reload_for_policy_update = lambda **_kwargs: (_ for _ in ()).throw(
        AssertionError("no policy reload should be needed"),
    )

    result = runtime.sync_from_db(force=False)

    assert active_sha != normalized_sha
    assert result["ok"] is True
    assert result["changed"] is False
    assert result["config_changed"] is False
    assert result["revision_id"] == 9
    assert result["detail"] == "Proxy is already using the active config revision."


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
    runtime._reload_for_policy_update = lambda *, wait_for_adblock_icap=True: (
        reloads.append(wait_for_adblock_icap)
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
    runtime.sync_adblock_state = lambda force=False: {
        "ok": True,
        "changed": False,
        "artifact_sha256": "adblock-sha",
    }
    runtime.sync_pac_state = lambda force=False: {"ok": True, "changed": False}
    runtime._current_config_sha = lambda: "current-sha"
    runtime._reload_for_policy_update = lambda *, wait_for_adblock_icap=True: (
        reloads.append(wait_for_adblock_icap)
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
    assert reloads == [False]
    assert recorded
    assert "Squid reconfigured for policy update." in recorded[0][2]


def test_sync_from_db_forced_noop_does_not_reapply_current_config() -> None:
    runtime = _runtime_shell()

    class Controller:
        def normalize_config_text(self, text):
            return text

        def apply_config_text(self, _text):
            msg = "forced no-op should not reapply active config"
            raise AssertionError(msg)

        def set_adblock_icap_revision_token(self, token) -> None:
            self.token = token

        def materialize_clamav_runtime_files(self, _config_text, **_kwargs):
            return True, "ClamAV runtime files already current."

        def get_current_config(self):
            return "http_port 3128\n"

    class Revisions:
        def get_active_revision_metadata(self, _proxy_id):
            return SimpleNamespace(revision_id=9, config_sha256="current-sha")

        def latest_apply(self, _proxy_id) -> None:
            return None

        def get_active_revision(self, _proxy_id):
            msg = "forced no-op should not load active config"
            raise AssertionError(msg)

    class Registry:
        def mark_apply_result(self, *_args, **_kwargs):
            msg = "forced no-op should not mark config apply result"
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
    runtime._reload_for_policy_update = lambda **_kwargs: (_ for _ in ()).throw(
        AssertionError("forced no-op should not reload policy includes"),
    )

    result = runtime.sync_from_db(force=True)

    assert result["ok"] is True
    assert result["changed"] is False
    assert result["config_changed"] is False
    assert result["policy_changed"] is False
    assert result["adblock_changed"] is False
    assert result["detail"].endswith(
        "Proxy is already using the active config revision.",
    )
    assert runtime.controller.token == "adblock-sha"


def test_sync_from_db_records_noop_apply_for_claimed_current_config_operation() -> None:
    runtime = _runtime_shell()
    recorded: list[tuple[object, int, bool, str]] = []
    registry_marks: list[tuple[object, bool, str, str]] = []
    op = SimpleNamespace(
        operation_id=5,
        operation_type="config_apply",
        target_kind="config_revision",
        target_ref="9",
        force=True,
    )

    class Controller:
        def normalize_config_text(self, text):
            return text

        def apply_config_text(self, _text):
            msg = "current config operation should not reapply active config"
            raise AssertionError(msg)

        def set_adblock_icap_revision_token(self, token) -> None:
            self.token = token

        def materialize_clamav_runtime_files(self, _config_text, **_kwargs):
            return True, "ClamAV runtime files already current."

        def get_current_config(self):
            return "http_port 3128\n"

    class Revisions:
        def get_active_revision_metadata(self, _proxy_id):
            return SimpleNamespace(revision_id=9, config_sha256="current-sha")

        def latest_apply(self, _proxy_id) -> None:
            return None

        def record_apply_result(
            self,
            proxy_id,
            revision_id,
            *,
            ok,
            detail,
            applied_by,
        ):
            recorded.append((proxy_id, revision_id, ok, applied_by))
            assert detail.endswith("Proxy is already using the active config revision.")
            return SimpleNamespace(application_id=77)

        def get_active_revision(self, _proxy_id):
            msg = "current config operation should not load active config text"
            raise AssertionError(msg)

    class Registry:
        def mark_apply_result(self, proxy_id, *, ok, detail, current_config_sha):
            registry_marks.append((proxy_id, ok, detail, current_config_sha))
            return SimpleNamespace()

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
    runtime._reload_for_policy_update = lambda **_kwargs: (_ for _ in ()).throw(
        AssertionError("current config operation should not reload policy includes"),
    )

    result = runtime._sync_from_db_unlocked(
        force=True,
        artifact_force=True,
        operations=[op],
    )

    assert result["ok"] is True
    assert result["changed"] is False
    assert result["config_changed"] is False
    assert result["revision_id"] == 9
    assert result["application_id"] == 77
    assert recorded == [("default", 9, True, "proxy")]
    assert registry_marks == [
        (
            "default",
            True,
            "Proxy is already using the active config revision.",
            "current-sha",
        ),
    ]


def test_sync_from_db_records_noop_apply_for_each_current_config_operation() -> None:
    runtime = _runtime_shell()
    recorded: list[tuple[object, int, bool, str]] = []
    registry_marks: list[tuple[object, bool, str, str]] = []
    op = SimpleNamespace(
        operation_id=5,
        operation_type="config_apply",
        target_kind="config_revision",
        target_ref="9",
        force=True,
    )

    class Controller:
        def normalize_config_text(self, text):
            return text

        def apply_config_text(self, _text):
            msg = "current config operation should not reapply active config"
            raise AssertionError(msg)

        def set_adblock_icap_revision_token(self, _token) -> None:
            return None

        def materialize_clamav_runtime_files(self, _config_text, **_kwargs):
            return True, "ClamAV runtime files already current."

        def get_current_config(self):
            return "http_port 3128\n"

    class Revisions:
        def get_active_revision_metadata(self, _proxy_id):
            return SimpleNamespace(revision_id=9, config_sha256="current-sha")

        def latest_apply(self, _proxy_id):
            return SimpleNamespace(revision_id=9, ok=True, application_id=44)

        def record_apply_result(
            self,
            proxy_id,
            revision_id,
            *,
            ok,
            detail,
            applied_by,
        ):
            recorded.append((proxy_id, revision_id, ok, applied_by))
            assert detail.endswith("Proxy is already using the active config revision.")
            return SimpleNamespace(application_id=78)

        def get_active_revision(self, _proxy_id):
            msg = "current config operation should not load active config text"
            raise AssertionError(msg)

    class Registry:
        def mark_apply_result(self, proxy_id, *, ok, detail, current_config_sha):
            registry_marks.append((proxy_id, ok, detail, current_config_sha))

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
    runtime._reload_for_policy_update = lambda **_kwargs: (_ for _ in ()).throw(
        AssertionError("current config operation should not reload policy includes"),
    )

    result = runtime._sync_from_db_unlocked(
        force=True,
        artifact_force=True,
        operations=[op],
    )

    assert result["ok"] is True
    assert result["revision_id"] == 9
    assert result["application_id"] == 78
    assert recorded == [("default", 9, True, "proxy")]
    assert registry_marks == [
        (
            "default",
            True,
            "Proxy is already using the active config revision.",
            "current-sha",
        ),
    ]


def test_sync_from_db_noop_materializes_adblock_setting_state() -> None:
    runtime = _runtime_shell()
    materialized_enabled = []

    class Controller:
        def normalize_config_text(self, text):
            return text

        def apply_config_text(self, _text):
            msg = "forced no-op should not reapply active config"
            raise AssertionError(msg)

        def set_adblock_icap_revision_token(self, token) -> None:
            self.token = token

        def set_adblock_enabled(self, enabled) -> None:
            self.enabled = enabled

        def materialize_clamav_runtime_files(self, _config_text, **kwargs):
            materialized_enabled.append(kwargs.get("adblock_enabled"))
            return True, "Updated ICAP include."

        def get_current_config(self):
            return "http_port 3128\n"

    class Revisions:
        def get_active_revision_metadata(self, _proxy_id):
            return SimpleNamespace(revision_id=9, config_sha256="current-sha")

        def latest_apply(self, _proxy_id) -> None:
            return None

        def get_active_revision(self, _proxy_id):
            msg = "forced no-op should not load active config"
            raise AssertionError(msg)

    class Registry:
        def mark_apply_result(self, *_args, **_kwargs):
            msg = "forced no-op should not mark config apply result"
            raise AssertionError(msg)

    class AdblockStore:
        def get_settings(self):
            return SimpleNamespace(enabled=False)

    runtime.controller = Controller()
    runtime.revisions = Revisions()
    runtime.registry = Registry()
    runtime.adblock_store = AdblockStore()
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
    runtime._reload_for_policy_update = lambda **_kwargs: (True, "reloaded")

    result = runtime.sync_from_db()

    assert result["ok"] is True
    assert result["changed"] is True
    assert result["config_changed"] is False
    assert materialized_enabled == [False]
    assert runtime.controller.enabled is False
    assert runtime.controller.token == "adblock-sha"


def test_sync_from_db_forced_normalized_noop_reloads_policy_without_reapply() -> None:
    active_config = "http_port 3128\r\n\r\n"
    normalized_config = "http_port 3128\n"
    active_sha = hashlib.sha256(active_config.encode("utf-8")).hexdigest()
    normalized_sha = hashlib.sha256(normalized_config.encode("utf-8")).hexdigest()

    runtime = _runtime_shell()
    applies: list[str] = []
    reloads: list[bool] = []
    marked: list[tuple[bool, str, str]] = []

    class Controller:
        def get_current_config(self):
            return normalized_config

        def normalize_config_text(self, text):
            return (text or "").replace("\r\n", "\n").rstrip() + "\n"

        def apply_config_text(self, text):
            applies.append(text)
            return True, "Squid reconfigured."

        def set_adblock_icap_revision_token(self, _token) -> None:
            return None

        def materialize_clamav_runtime_files(self, _config_text, **_kwargs):
            return True, "ClamAV runtime files already current."

    class Revisions:
        def get_active_revision_metadata(self, _proxy_id):
            return SimpleNamespace(revision_id=9, config_sha256=active_sha)

        def latest_apply(self, _proxy_id) -> None:
            return None

        def get_active_revision(self, _proxy_id):
            return SimpleNamespace(
                revision_id=9,
                config_text=active_config,
                config_sha256=active_sha,
            )

        def record_apply_result(self, *_args, **_kwargs):
            msg = "forced normalized no-op should not record apply"
            raise AssertionError(msg)

    class Registry:
        def mark_apply_result(self, _proxy_id, *, ok, detail, current_config_sha):
            marked.append((ok, detail, current_config_sha))
            return SimpleNamespace()

    runtime.controller = Controller()
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
        "detail": "Updated policy files.",
    }
    runtime.sync_adblock_state = lambda force=False: {
        "ok": True,
        "changed": False,
        "artifact_sha256": "adblock-sha",
    }
    runtime.sync_pac_state = lambda force=False: {"ok": True, "changed": False}
    runtime._current_config_sha = lambda: normalized_sha
    runtime._reload_for_policy_update = lambda *, wait_for_adblock_icap=True: (
        reloads.append(wait_for_adblock_icap)
        or (True, "Squid reconfigured for policy update.")
    )

    result = runtime.sync_from_db(force=True)

    assert result["ok"] is True
    assert result["changed"] is True
    assert result["config_changed"] is False
    assert result["policy_changed"] is True
    assert result["revision_id"] == 9
    assert applies == []
    assert reloads == [False]
    assert marked == []
    assert "Proxy is already using the active config revision." in result["detail"]


def test_reload_for_policy_update_can_skip_adblock_icap_health(monkeypatch) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()

    class Controller:
        def _run(self, args, **_kwargs):
            assert args == ["squid", "-k", "reconfigure"]
            return _cp(0, stdout="reconfigured")

        def _wait_for_http_listener(self, *, timeout) -> bool:
            assert timeout == pytest.approx(10.0)
            return True

    def fail_icap(**_kwargs) -> NoReturn:
        msg = "policy-only reload should not probe adblock ICAP"
        raise AssertionError(msg)

    runtime.controller = Controller()
    monkeypatch.setattr(runtime_module, "_check_icap_adblock", fail_icap)

    ok, detail = runtime._reload_for_policy_update(wait_for_adblock_icap=False)

    assert ok is True
    assert "reconfigured" in detail
    assert "Squid reconfigured for policy update." in detail


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

    ok, detail = runtime._reload_for_policy_update(wait_for_adblock_icap=True)

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

    ok, detail = runtime._reload_for_policy_update(wait_for_adblock_icap=True)

    assert ok is False
    assert "reconfigured" in detail
    assert "icap not ready" in detail


def test_reload_for_policy_update_accepts_missing_pid_when_listener_healthy(
    monkeypatch,
) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()

    class Controller:
        def reconfigure_squid(self, *, timeout, listener_timeout):
            assert timeout == pytest.approx(15.0)
            assert listener_timeout == pytest.approx(10.0)
            return (
                True,
                (
                    "FATAL: failed to open /var/run/squid.pid: (2) No such file or directory\n"
                    "Squid reconfigure could not signal a PID file, but the HTTP listener is responding."
                ),
            )

    def fail_icap(**_kwargs) -> NoReturn:
        msg = "policy-only reload should not probe adblock ICAP"
        raise AssertionError(msg)

    runtime.controller = Controller()
    monkeypatch.setattr(runtime_module, "_check_icap_adblock", fail_icap)

    ok, detail = runtime._reload_for_policy_update(wait_for_adblock_icap=False)

    assert ok is True
    assert "failed to open /var/run/squid.pid" in detail
    assert "Squid reconfigured for policy update." in detail


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


def test_squid_controller_apply_accepts_missing_pid_when_listener_is_healthy(
    tmp_path,
    monkeypatch,
) -> None:
    _add_repo_paths()
    from services.squid_core import SquidController  # type: ignore

    squid_conf = tmp_path / "squid.conf"
    persisted_conf = tmp_path / "persisted.conf"
    squid_conf.write_text("workers 1\n# old\n", encoding="utf-8")
    calls: list[list[str]] = []

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        if args[:3] == ["squid", "-k", "parse"]:
            return SimpleNamespace(returncode=0, stdout="parse ok", stderr="")
        if args[:3] == ["squid", "-k", "reconfigure"]:
            return SimpleNamespace(
                returncode=1,
                stdout="",
                stderr=(
                    "FATAL: failed to open /var/run/squid.pid: "
                    "(2) No such file or directory"
                ),
            )
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
    monkeypatch.setattr(controller, "_wait_for_http_listener", lambda *, timeout: True)
    monkeypatch.setattr(
        controller,
        "restore_last_known_good_config",
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("healthy listener should not trigger rollback"),
        ),
    )

    ok, detail = controller.apply_config_text("workers 1\n# new\n")

    assert ok is True
    assert "failed to open /var/run/squid.pid" in detail
    assert "HTTP listener is responding" in detail
    assert "# new" in squid_conf.read_text(encoding="utf-8")
    assert "# new" in persisted_conf.read_text(encoding="utf-8")
    assert ["squid", "-k", "reconfigure"] in calls


def test_squid_controller_apply_restarts_after_missing_pid_when_listener_is_down(
    tmp_path,
    monkeypatch,
) -> None:
    _add_repo_paths()
    from services.squid_core import SquidController  # type: ignore

    squid_conf = tmp_path / "squid.conf"
    persisted_conf = tmp_path / "persisted.conf"
    squid_conf.write_text("workers 1\n# old\n", encoding="utf-8")
    calls: list[list[str]] = []

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        if args[:3] == ["squid", "-k", "parse"]:
            return SimpleNamespace(returncode=0, stdout="parse ok", stderr="")
        if args[:3] == ["squid", "-k", "reconfigure"]:
            return SimpleNamespace(
                returncode=1,
                stdout="",
                stderr=(
                    "FATAL: failed to open /var/run/squid.pid: "
                    "(2) No such file or directory"
                ),
            )
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
    listener_checks = iter([False, True])
    monkeypatch.setattr(
        controller,
        "_wait_for_http_listener",
        lambda *, timeout: next(listener_checks),
    )
    monkeypatch.setattr(
        controller,
        "_wait_for_http_listener_absent",
        lambda *, timeout: True,
    )
    monkeypatch.setattr(
        controller,
        "_wait_for_squid_pidfile_stale_or_absent",
        lambda **_kwargs: True,
    )
    monkeypatch.setattr(
        controller,
        "restore_last_known_good_config",
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("restart recovery should not trigger rollback"),
        ),
    )

    ok, detail = controller.apply_config_text("workers 1\n# new\n")

    assert ok is True
    assert "failed to open /var/run/squid.pid" in detail
    assert "listener was unavailable" in detail
    assert "Squid HTTP listener is responding" in detail
    assert "# new" in squid_conf.read_text(encoding="utf-8")
    assert "# new" in persisted_conf.read_text(encoding="utf-8")
    assert ["squid", "-k", "reconfigure"] in calls
    assert ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "squid"] in calls
    assert ["supervisorctl", "-c", "/etc/supervisord.conf", "start", "squid"] in calls


def test_squid_controller_apply_stages_config_with_atomic_writes(
    tmp_path, monkeypatch
) -> None:
    _add_repo_paths()
    from services.squid_core import SquidController  # type: ignore

    squid_conf = tmp_path / "squid.conf"
    persisted_conf = tmp_path / "persisted.conf"
    squid_conf.write_text("workers 1\n# old\n", encoding="utf-8")

    def fake_run(args, **_kwargs):
        if args[:3] == ["squid", "-k", "parse"]:
            return SimpleNamespace(returncode=0, stdout="parse ok", stderr="")
        if args[:3] == ["squid", "-k", "reconfigure"]:
            return SimpleNamespace(returncode=0, stdout="reconfigured", stderr="")
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
    monkeypatch.setattr(controller, "_wait_for_http_listener", lambda *, timeout: True)

    def reject_direct_write_text(*_args, **_kwargs) -> NoReturn:
        msg = "Squid config apply must use atomic writes"
        raise AssertionError(msg)

    monkeypatch.setattr(Path, "write_text", reject_direct_write_text)

    ok, detail = controller.apply_config_text("workers 1\n# new\n")

    assert ok is True
    assert "reconfigured" in detail
    assert "# new" in squid_conf.read_text(encoding="utf-8")
    assert "# old" in (tmp_path / "squid.conf.bak").read_text(encoding="utf-8")
    assert "# new" in persisted_conf.read_text(encoding="utf-8")


def test_squid_controller_atomic_write_preserves_existing_file_mode(tmp_path) -> None:
    _add_repo_paths()
    from services.squid_core import SquidController  # type: ignore

    target = tmp_path / "squid.conf"
    target.write_text("old\n", encoding="utf-8")
    target.chmod(0o640)

    controller = SquidController(str(target))
    controller._atomic_write_file(str(target), "new\n")

    assert target.read_text(encoding="utf-8") == "new\n"
    assert target.stat().st_mode & 0o777 == 0o640


def test_squid_controller_atomic_write_uses_readable_mode_for_new_files(
    tmp_path,
) -> None:
    _add_repo_paths()
    from services.squid_core import SquidController  # type: ignore

    target = tmp_path / "conf.d" / "20-icap.conf"

    controller = SquidController(str(tmp_path / "squid.conf"))
    controller._atomic_write_file(str(target), "include\n")

    assert target.read_text(encoding="utf-8") == "include\n"
    assert target.stat().st_mode & 0o777 == 0o644


def test_runtime_icap_materialization_matches_startup_parity_contract(
    tmp_path,
    monkeypatch,
    request,
) -> None:
    _add_repo_paths()
    from services.clamav_config_forms import (  # type: ignore
        render_clamav_settings_block,
    )
    from services.squid_core import (  # type: ignore
        SquidController,
        _cached_icap_include_path,
        _cached_virus_scan_config_path,
    )

    supervisor_dir = tmp_path / "supervisor.d"
    cicap_dir = tmp_path / "c-icap"
    run_dir = tmp_path / "run" / "c-icap"
    include_path = tmp_path / "conf.d" / "20-icap.conf"
    virus_path = tmp_path / "virus_scan.conf"
    supervisor_dir.mkdir()
    cicap_dir.mkdir()
    run_dir.mkdir(parents=True)
    (cicap_dir / "c-icap.conf").write_text(
        "PidFile /var/run/c-icap/c-icap.pid\n"
        "Port 127.0.0.1:14001\n"
        "AccessLog /var/log/cicap-access.log\n"
        "Include /etc/virus_scan.conf\n",
        encoding="utf-8",
    )
    (supervisor_dir / "cicap_adblock_3.conf").write_text("stale\n", encoding="utf-8")
    (supervisor_dir / "cicap_av_3.conf").write_text("stale\n", encoding="utf-8")
    (supervisor_dir / "clamav_respmod_3.conf").write_text("stale\n", encoding="utf-8")
    (cicap_dir / "c-icap-av-3.conf").write_text("stale\n", encoding="utf-8")

    monkeypatch.setenv("SQUID_SUPERVISOR_INCLUDE_DIR", str(supervisor_dir))
    monkeypatch.setenv("CICAP_CONFIG_DIR", str(cicap_dir))
    monkeypatch.setenv("CICAP_BASE_CONFIG_PATH", str(cicap_dir / "c-icap.conf"))
    monkeypatch.setenv("CICAP_RUN_DIR", str(run_dir))
    monkeypatch.setenv("SQUID_ICAP_INCLUDE_PATH", str(include_path))
    monkeypatch.setenv("VIRUS_SCAN_CONFIG_PATH", str(virus_path))
    monkeypatch.setenv("CICAP_PORT", "15000")
    monkeypatch.setenv("CICAP_AV_PORT", "15001")
    monkeypatch.setenv("CICAP_AV_RESP_PORT", "15002")
    monkeypatch.setenv("CLAMD_HOST", "clamd.example.internal")
    monkeypatch.setenv("CLAMD_PORT", "3311")
    monkeypatch.setenv("CLAMAV_REQUIRED", "1")
    monkeypatch.setenv("ADBLOCK_ENABLED", "0")
    _cached_icap_include_path.cache_clear()
    _cached_virus_scan_config_path.cache_clear()
    request.addfinalizer(_cached_icap_include_path.cache_clear)
    request.addfinalizer(_cached_virus_scan_config_path.cache_clear)

    calls: list[list[str]] = []

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        return _cp(0, stdout="ok")

    controller = SquidController(str(tmp_path / "squid.conf"), cmd_run=fake_run)
    config_text = "workers 2\n" + render_clamav_settings_block(
        {"clamav_fail_mode": "open"},
    )

    ok, detail = controller.materialize_clamav_runtime_files(
        config_text,
        adblock_enabled=False,
    )

    assert ok is True
    assert "ClamAV runtime files updated" in detail
    assert calls == [
        ["supervisorctl", "-c", "/etc/supervisord.conf", "reread"],
        ["supervisorctl", "-c", "/etc/supervisord.conf", "update"],
    ]
    assert not (supervisor_dir / "cicap_adblock_3.conf").exists()
    assert not (supervisor_dir / "cicap_av_3.conf").exists()
    assert not (supervisor_dir / "clamav_respmod_3.conf").exists()
    assert not (cicap_dir / "c-icap-av-3.conf").exists()

    include = include_path.read_text(encoding="utf-8")
    assert "icap://127.0.0.1:15000/adblockreq bypass=on" in include
    assert "icap://127.0.0.1:15002/avrespmod bypass=off" in include
    assert "icap://127.0.0.1:15003/avrespmod bypass=off" in include
    assert "icap://127.0.0.1:15004/avrespmod bypass=off" in include
    assert "icap://127.0.0.1:15005/avrespmod bypass=off" in include
    assert "# Adblock request routing disabled by persisted UI setting." in include
    assert "adaptation_access adblock_req_set allow icap_adblockable" not in include

    assert "virus_scan.PassOnError off" in virus_path.read_text(encoding="utf-8")
    assert "Port 127.0.0.1:15002" in (cicap_dir / "c-icap-av-1.conf").read_text(
        encoding="utf-8",
    )
    assert f"PidFile {run_dir}/c-icap-av-2.pid" in (
        cicap_dir / "c-icap-av-2.conf"
    ).read_text(encoding="utf-8")

    adblock_supervisor = (supervisor_dir / "cicap_adblock_1.conf").read_text(
        encoding="utf-8",
    )
    assert "autorestart=unexpected" in adblock_supervisor
    assert "exitcodes=0" in adblock_supervisor
    assert "startsecs=1" in adblock_supervisor
    assert "startsecs=45" not in adblock_supervisor
    assert "startretries=2" in adblock_supervisor

    av_supervisor = (supervisor_dir / "cicap_av_1.conf").read_text(encoding="utf-8")
    assert 'CLAMD_HOST="clamd.example.internal"' in av_supervisor
    assert 'CLAMD_PORT="3311"' in av_supervisor
    assert 'CLAMAV_REQUIRED="1"' in av_supervisor
    assert "rm -f" in av_supervisor
    assert "cicap_av_runner.py" in av_supervisor

    respmod_supervisor = (supervisor_dir / "clamav_respmod_1.conf").read_text(
        encoding="utf-8",
    )
    assert '--port "15004"' in respmod_supervisor
    assert '--clamd-host "clamd.example.internal"' in respmod_supervisor
    assert '--clamd-port "3311"' in respmod_supervisor
    assert "--fail-closed" in respmod_supervisor
    assert "--fail-open" not in respmod_supervisor


def test_clamav_runtime_supervisor_update_restarts_squid_with_accept_only_probe(
    tmp_path,
) -> None:
    _add_repo_paths()
    from services.squid_core import SquidController  # type: ignore

    controller = SquidController.__new__(SquidController)
    calls: list[object] = []

    controller.normalize_config_text = lambda text: text
    controller._runtime_icap_workers = lambda _text: 1
    controller._virus_scan_config_path = lambda: tmp_path / "virus_scan.conf"
    controller._icap_include_path = lambda: tmp_path / "20-icap.conf"
    controller._snapshot_runtime_file = lambda _path: None
    controller._snapshot_managed_icap_runtime_files = dict
    controller._write_if_changed = lambda _path, _content: False
    controller._render_icap_include = lambda *_args, **_kwargs: "include\n"
    controller._sync_icap_supervisor_runtime_files = lambda **_kwargs: (
        True,
        ["/etc/supervisor.d/cicap_av_1.conf"],
    )
    controller._http_listener_ports = lambda *_args, **_kwargs: (3128,)
    controller._tcp_listener_accepts = lambda _port: True
    controller._run = lambda args, **kwargs: (
        calls.append(("run", list(args), kwargs)) or _cp(0, stdout="squid: stopped")
    )
    controller._decode_completed = lambda proc: (proc.stdout or b"").decode().strip()
    controller._wait_for_http_listener_absent = lambda *, timeout: True
    controller._supervisor_reread_update = lambda: (True, "supervisor updated")
    controller._wait_for_icap_readiness = lambda *, timeout: (True, "OPTIONS ready")

    def restart_squid(**kwargs):
        calls.append(("restart_squid", kwargs))
        return (
            True,
            "Squid HTTP listener is accepting connections and ICAP readiness is green.",
        )

    controller.restart_squid = restart_squid

    ok, detail = controller.materialize_clamav_runtime_files(
        "workers 1\nhttp_port 3128\n",
        adblock_enabled=True,
    )

    assert ok is True
    assert (
        "restart_squid",
        {"ready_timeout": 75.0, "require_http_response": False},
    ) in calls
    assert "Squid restarted after ICAP supervisor update." in detail


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
    (compiled / "request_lookup.sqlite").write_bytes(b"old-db")
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
        (root / "request_lookup.sqlite").unlink(missing_ok=True)
        _write_adblock_lookup_metadata(root / "request_lookup.sqlite", count_rules=0)

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
    assert (compiled / "request_lookup.sqlite").read_bytes() == b"old-db"
    assert recorded[-1]["ok"] is False


def test_sync_adblock_state_rolls_back_when_materialized_artifact_fails_integrity(
    tmp_path,
    monkeypatch,
) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    compiled = tmp_path / "compiled"
    compiled.mkdir()
    (compiled / ".artifact-sha256").write_text("old-sha", encoding="utf-8")
    (compiled / "request_lookup.sqlite").write_bytes(b"old-db")
    recorded: list[dict[str, object]] = []
    restarts: list[bool] = []

    class Artifacts:
        compiled_dir = str(compiled)

        def get_active_artifact_metadata(self):
            return SimpleNamespace(revision_id=42, artifact_sha256="new-sha")

        def get_active_artifact_summary(self):
            return SimpleNamespace(
                report={
                    "breakdowns": {
                        "lookup_index_counts": {
                            "rules": 12,
                        },
                    },
                },
            )

        def get_active_artifact(self):
            return SimpleNamespace(
                revision_id=42,
                artifact_sha256="new-sha",
                archive_blob=b"new",
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
        (root / "request_lookup.sqlite").unlink(missing_ok=True)
        _write_adblock_lookup_metadata(root / "request_lookup.sqlite", count_rules=3)

    runtime = _runtime_shell()
    runtime.services = SimpleNamespace(current_adblock_sha_reader=None)
    runtime.adblock_artifacts = Artifacts()
    runtime.adblock_store = Store()
    runtime.adblock_compiled_dir = str(compiled)
    runtime._restart_adblock_service = lambda: (
        restarts.append(True)
        or (
            True,
            "cicap_adblock RUNNING",
        )
    )

    monkeypatch.setattr(
        runtime_module,
        "materialize_archive_to_directory",
        fake_materialize,
    )

    result = runtime.sync_adblock_state(force=True)

    assert result["ok"] is False
    assert restarts == []
    assert "Failed to materialize adblock artifact" in result["detail"]
    assert "Restored previous adblock compiled artifact" in result["detail"]
    assert (compiled / ".artifact-sha256").read_text(encoding="utf-8") == "old-sha"
    assert (compiled / "request_lookup.sqlite").read_bytes() == b"old-db"
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

        def latest_apply(self, _proxy_id, *, revision_id=None):
            assert revision_id == 42
            return SimpleNamespace(application_id=7, ok=True)

        def record_apply_result(
            self, *args, **kwargs
        ) -> NoReturn:  # pragma: no cover - should not be reached
            msg = "no-op force sync should not churn existing adblock apply rows"
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
    assert result["application_id"] == 7
    assert restarts == []


def test_sync_adblock_state_reapplies_when_current_marker_has_incomplete_lookup(
    tmp_path,
    monkeypatch,
) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    compiled = tmp_path / "compiled"
    compiled.mkdir()
    (compiled / ".artifact-sha256").write_text("same-sha", encoding="utf-8")
    _write_adblock_lookup_metadata(compiled / "request_lookup.sqlite", count_rules=0)
    recorded: list[dict[str, object]] = []

    class Artifacts:
        compiled_dir = str(compiled)

        def get_active_artifact_metadata(self):
            return SimpleNamespace(revision_id=42, artifact_sha256="same-sha")

        def get_active_artifact_summary(self):
            return SimpleNamespace(
                report={
                    "breakdowns": {
                        "lookup_index_counts": {
                            "rules": 12,
                        },
                    },
                },
            )

        def get_active_artifact(self):
            return SimpleNamespace(
                revision_id=42,
                artifact_sha256="same-sha",
                archive_blob=b"archive",
            )

        def record_apply_result(self, proxy_id, revision_id, **kwargs):
            recorded.append(
                {"proxy_id": proxy_id, "revision_id": revision_id, **kwargs}
            )
            return SimpleNamespace(application_id=17)

    class Store:
        def init_db(self) -> None:
            pass

        def get_cache_flush_requested(self) -> bool:
            return False

    def fake_materialize(directory, *, archive_blob, artifact_sha256) -> None:
        root = Path(directory)
        (root / ".artifact-sha256").write_text(artifact_sha256, encoding="utf-8")
        (root / "request_lookup.sqlite").unlink()
        _write_adblock_lookup_metadata(root / "request_lookup.sqlite", count_rules=12)

    restarts: list[bool] = []
    runtime = _runtime_shell()
    runtime.services = SimpleNamespace(current_adblock_sha_reader=None)
    runtime.adblock_artifacts = Artifacts()
    runtime.adblock_store = Store()
    runtime.adblock_compiled_dir = str(compiled)
    runtime._restart_adblock_service = lambda: (
        restarts.append(True)
        or (
            True,
            "restarted",
        )
    )
    monkeypatch.setattr(
        runtime_module,
        "materialize_archive_to_directory",
        fake_materialize,
    )

    result = runtime.sync_adblock_state(force=True)

    assert result["ok"] is True
    assert result["changed"] is True
    assert result["artifact_changed"] is True
    assert result["application_id"] == 17
    assert "local materialization was stale" in result["detail"]
    assert restarts == [True]
    assert recorded[-1]["ok"] is True


def test_sync_adblock_state_reapplies_when_marker_matches_but_lookup_missing_without_rule_count(
    tmp_path,
    monkeypatch,
) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    compiled = tmp_path / "compiled"
    compiled.mkdir()
    (compiled / ".artifact-sha256").write_text("same-sha", encoding="utf-8")
    recorded: list[dict[str, object]] = []

    class Artifacts:
        compiled_dir = str(compiled)

        def get_active_artifact_metadata(self):
            return SimpleNamespace(revision_id=42, artifact_sha256="same-sha")

        def get_active_artifact_summary(self):
            return SimpleNamespace(report={})

        def get_active_artifact(self):
            return SimpleNamespace(
                revision_id=42,
                artifact_sha256="same-sha",
                archive_blob=b"archive",
            )

        def record_apply_result(self, proxy_id, revision_id, **kwargs):
            recorded.append(
                {"proxy_id": proxy_id, "revision_id": revision_id, **kwargs}
            )
            return SimpleNamespace(application_id=18)

    class Store:
        def init_db(self) -> None:
            pass

        def get_cache_flush_requested(self) -> bool:
            return False

    def fake_materialize(directory, *, archive_blob, artifact_sha256) -> None:
        root = Path(directory)
        (root / ".artifact-sha256").write_text(artifact_sha256, encoding="utf-8")
        (root / "request_lookup.sqlite").unlink(missing_ok=True)
        _write_adblock_lookup_metadata(root / "request_lookup.sqlite", count_rules=0)

    restarts: list[bool] = []
    runtime = _runtime_shell()
    runtime.services = SimpleNamespace(current_adblock_sha_reader=None)
    runtime.adblock_artifacts = Artifacts()
    runtime.adblock_store = Store()
    runtime.adblock_compiled_dir = str(compiled)
    runtime._restart_adblock_service = lambda: (
        restarts.append(True)
        or (
            True,
            "restarted",
        )
    )
    monkeypatch.setattr(
        runtime_module,
        "materialize_archive_to_directory",
        fake_materialize,
    )

    result = runtime.sync_adblock_state(force=True)

    assert result["ok"] is True
    assert result["changed"] is True
    assert result["artifact_changed"] is True
    assert result["application_id"] == 18
    assert "adblock request lookup database is missing" in result["detail"]
    assert (compiled / "request_lookup.sqlite").exists()
    assert restarts == [True]
    assert recorded[-1]["ok"] is True


def test_adblock_materialization_integrity_rejects_corrupt_lookup_without_rule_count(
    tmp_path,
) -> None:
    compiled = tmp_path / "compiled"
    compiled.mkdir()
    (compiled / ".artifact-sha256").write_text("same-sha", encoding="utf-8")
    (compiled / "request_lookup.sqlite").write_bytes(b"not a sqlite database")

    runtime = _runtime_shell()
    runtime.adblock_compiled_dir = str(compiled)
    runtime.adblock_artifacts = SimpleNamespace(
        get_active_artifact_summary=lambda: SimpleNamespace(report={}),
    )

    ok, detail = runtime._adblock_materialization_integrity(
        "same-sha",
        current_sha="same-sha",
    )

    assert ok is False
    assert "database" in detail.lower()


def test_sync_adblock_state_reapplies_when_marker_matches_but_lookup_corrupt_without_rule_count(
    tmp_path,
    monkeypatch,
) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    compiled = tmp_path / "compiled"
    compiled.mkdir()
    (compiled / ".artifact-sha256").write_text("same-sha", encoding="utf-8")
    (compiled / "request_lookup.sqlite").write_bytes(b"not a sqlite database")
    recorded: list[dict[str, object]] = []

    class Artifacts:
        compiled_dir = str(compiled)

        def get_active_artifact_metadata(self):
            return SimpleNamespace(revision_id=42, artifact_sha256="same-sha")

        def get_active_artifact_summary(self):
            return SimpleNamespace(report={})

        def get_active_artifact(self):
            return SimpleNamespace(
                revision_id=42,
                artifact_sha256="same-sha",
                archive_blob=b"archive",
            )

        def record_apply_result(self, proxy_id, revision_id, **kwargs):
            recorded.append(
                {"proxy_id": proxy_id, "revision_id": revision_id, **kwargs}
            )
            return SimpleNamespace(application_id=19)

    class Store:
        def init_db(self) -> None:
            pass

        def get_cache_flush_requested(self) -> bool:
            return False

    def fake_materialize(directory, *, archive_blob, artifact_sha256) -> None:
        root = Path(directory)
        (root / ".artifact-sha256").write_text(artifact_sha256, encoding="utf-8")
        (root / "request_lookup.sqlite").unlink(missing_ok=True)
        _write_adblock_lookup_metadata(root / "request_lookup.sqlite", count_rules=0)

    restarts: list[bool] = []
    runtime = _runtime_shell()
    runtime.services = SimpleNamespace(current_adblock_sha_reader=None)
    runtime.adblock_artifacts = Artifacts()
    runtime.adblock_store = Store()
    runtime.adblock_compiled_dir = str(compiled)
    runtime._restart_adblock_service = lambda: (
        restarts.append(True)
        or (
            True,
            "restarted",
        )
    )
    monkeypatch.setattr(
        runtime_module,
        "materialize_archive_to_directory",
        fake_materialize,
    )

    result = runtime.sync_adblock_state(force=True)

    assert result["ok"] is True
    assert result["changed"] is True
    assert result["artifact_changed"] is True
    assert result["application_id"] == 19
    assert "local materialization was stale" in result["detail"]
    assert "database" in result["detail"].lower()
    assert restarts == [True]
    assert recorded[-1]["ok"] is True


def test_sync_adblock_state_records_missing_apply_for_current_artifact() -> None:
    recorded = []

    class Artifacts:
        def get_active_artifact_metadata(self):
            return SimpleNamespace(revision_id=42, artifact_sha256="same-sha")

        def get_active_artifact(
            self,
        ) -> NoReturn:  # pragma: no cover - should not be reached
            msg = "current artifact should not be fetched for a ledger backfill"
            raise AssertionError(msg)

        def latest_apply(self, _proxy_id, *, revision_id=None):
            assert revision_id == 42

        def record_apply_result(self, proxy_id, revision_id, **kwargs):
            recorded.append(
                {"proxy_id": proxy_id, "revision_id": revision_id, **kwargs}
            )
            return SimpleNamespace(application_id=11)

    class Store:
        def init_db(self) -> None:
            pass

        def get_cache_flush_requested(self) -> bool:
            return False

    runtime = _runtime_shell()
    runtime.services = SimpleNamespace(current_adblock_sha_reader=lambda: "same-sha")
    runtime.adblock_artifacts = Artifacts()
    runtime.adblock_store = Store()
    runtime._restart_adblock_service = lambda: (True, "restarted")

    result = runtime.sync_adblock_state(force=True)

    assert result["ok"] is True
    assert result["changed"] is False
    assert result["artifact_changed"] is False
    assert result["application_id"] == 11
    assert recorded == [
        {
            "proxy_id": runtime.proxy_id,
            "revision_id": 42,
            "ok": True,
            "detail": "Proxy is already using the active adblock artifact.",
            "applied_by": "proxy",
            "artifact_sha256": "same-sha",
        }
    ]


def test_sync_adblock_state_reports_missing_apply_record_failure() -> None:
    class Artifacts:
        def get_active_artifact_metadata(self):
            return SimpleNamespace(revision_id=42, artifact_sha256="same-sha")

        def latest_apply(self, _proxy_id, *, revision_id=None):
            assert revision_id == 42

        def record_apply_result(self, *_args, **_kwargs):
            msg = "db unavailable"
            raise RuntimeError(msg)

    class Store:
        def init_db(self) -> None:
            pass

        def get_cache_flush_requested(self) -> bool:
            return False

    runtime = _runtime_shell()
    runtime.services = SimpleNamespace(current_adblock_sha_reader=lambda: "same-sha")
    runtime.adblock_artifacts = Artifacts()
    runtime.adblock_store = Store()

    result = runtime.sync_adblock_state(force=True)

    assert result["ok"] is False
    assert result["revision_id"] == 42
    assert result["artifact_sha256"] == "same-sha"
    assert result["detail"] == "Failed to record adblock artifact application."


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


def test_sync_adblock_state_cache_flush_does_not_fetch_current_artifact_archive() -> (
    None
):
    recorded = []

    class Artifacts:
        def get_active_artifact_metadata(self):
            return SimpleNamespace(revision_id=42, artifact_sha256="same-sha")

        def get_active_artifact(self) -> NoReturn:
            msg = "cache flush should not require fetching the active artifact archive"
            raise AssertionError(msg)

        def record_apply_result(self, proxy_id, revision_id, **kwargs):
            recorded.append(
                {"proxy_id": proxy_id, "revision_id": revision_id, **kwargs}
            )
            return SimpleNamespace(application_id=9)

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
    assert result["artifact_changed"] is False
    assert result["cache_flushed"] is True
    assert result["revision_id"] == 42
    assert result["artifact_sha256"] == "same-sha"
    assert recorded[-1]["ok"] is True


def test_sync_adblock_state_reports_cache_flush_marker_failure() -> None:
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
            return SimpleNamespace(application_id=8)

    class Store:
        def init_db(self) -> None:
            pass

        def get_cache_flush_requested(self) -> bool:
            return True

        def mark_cache_flushed(self, *, size=0) -> None:
            msg = "db unavailable"
            raise RuntimeError(msg)

    runtime = _runtime_shell()
    runtime.services = SimpleNamespace(current_adblock_sha_reader=lambda: "same-sha")
    runtime.adblock_artifacts = Artifacts()
    runtime.adblock_store = Store()
    runtime._restart_adblock_service = lambda: (True, "restarted")

    result = runtime.sync_adblock_state(force=False)

    assert result["ok"] is False
    assert result["changed"] is True
    assert result["adblock_changed"] is True
    assert result["artifact_changed"] is False
    assert result["cache_flushed"] is False
    assert "restarted" in result["detail"]
    assert "Failed to clear adblock cache flush request" in result["detail"]
    assert recorded[-1]["ok"] is False


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

    assert result["ok"] is False
    assert result["status"] == "degraded"
    assert result["previous_ok"] is True
    assert result["previous_status"] == "healthy"
    assert result["health_cache_stale"] is True
    assert "refresh was already in progress" in result["health_cache_detail"]


def test_collect_health_stale_cache_degrades_forwarding_without_preserving_green_detail() -> (
    None
):
    runtime = _runtime_shell()
    runtime.health_cache_ttl_seconds = 3.0
    runtime._health_cache_lock = __import__("threading").Lock()
    runtime._health_refresh_lock = __import__("threading").Lock()
    runtime._health_cache_ts = 0.0
    runtime._health_cache_value = {
        "ok": True,
        "status": "healthy",
        "timestamp": 1,
        "services": {
            "forwarding": {
                "ok": True,
                "detail": "HTTP/1.1 200 OK; local health ok",
                "contract": "Squid explicit forwarding path returned a local health response.",
            }
        },
    }
    runtime._health_refresh_lock.acquire()
    try:
        result = runtime.collect_health()
    finally:
        runtime._health_refresh_lock.release()

    forwarding = result["services"]["forwarding"]
    assert forwarding["ok"] is False
    assert forwarding["previous_ok"] is True
    assert forwarding["health_cache_stale"] is True
    assert forwarding["detail"] == result["health_cache_detail"]
    assert "local health response" not in forwarding["detail"]


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
        state_sha256="pac-sha"
    )

    result = runtime.collect_health()

    assert result["ok"] is True
    assert result["status"] == "healthy"
    assert result["current_policy_sha"] == "policy-sha"
    assert result["health_elapsed_seconds"] >= 0
    assert runtime._health_cache_value is result


def test_collect_health_cache_refreshes_when_config_sha_changes() -> None:
    runtime = _runtime_shell()
    runtime.health_cache_ttl_seconds = 60.0
    runtime._health_cache_lock = threading.Lock()
    runtime._health_refresh_lock = threading.Lock()
    runtime._health_cache_ts = 0.0
    runtime._health_cache_value = None
    state = {"sha": "config-a"}
    calls = {"listeners": 0}

    def listener_details():
        calls["listeners"] += 1
        listeners = [{"port": 3128, "mode": "explicit"}]
        if state["sha"] == "config-b":
            listeners.append({"port": 3129, "mode": "intercept"})
        return tuple(listeners)

    runtime.controller = SimpleNamespace(
        get_status=lambda: (b"squid ok", b""),
        _http_listener_details=listener_details,
        _wait_for_http_listener=lambda *, timeout: True,
    )
    runtime.stats_provider = dict
    runtime.runtime_services_builder = lambda **_kwargs: {"icap": {"ok": True}}
    runtime._supervisor_programs_health = lambda: {"ok": True, "programs": {}}
    runtime.revisions = SimpleNamespace(
        get_active_revision_metadata=lambda _proxy_id: SimpleNamespace(
            revision_id=7, config_sha256=state["sha"]
        )
    )
    runtime.certificate_bundles = SimpleNamespace(
        get_active_bundle_metadata=lambda: None
    )
    runtime.adblock_artifacts = SimpleNamespace(
        get_active_artifact_metadata=lambda: None
    )
    runtime._current_config_sha = lambda: state["sha"]
    runtime._current_certificate_bundle_sha = lambda: ""
    runtime._current_adblock_artifact_sha = lambda: ""
    runtime._current_policy_sha = lambda: "policy-sha"
    runtime._current_pac_state_sha = lambda: "pac-sha"
    runtime.policy_state_builder = lambda _proxy_id: SimpleNamespace(
        policy_sha256="policy-sha", files=()
    )
    runtime.pac_state_builder = lambda _proxy_id: SimpleNamespace(
        state_sha256="pac-sha"
    )

    first = runtime.collect_health()
    assert runtime.collect_health() is first
    assert calls["listeners"] == 1

    state["sha"] = "config-b"
    refreshed = runtime.collect_health()

    assert refreshed is not first
    assert refreshed["current_config_sha"] == "config-b"
    assert {item.get("mode") for item in refreshed["listener_details"]} == {
        "explicit",
        "intercept",
    }
    assert calls["listeners"] == 2


def test_operation_ledger_health_reports_counts_and_unavailable(monkeypatch) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore
    from proxy.runtime import ProxyRuntime  # type: ignore

    runtime = ProxyRuntime.__new__(ProxyRuntime)
    monkeypatch.setattr(runtime_module, "get_proxy_id", lambda: "edge-a")

    class Ledger:
        def counts_by_status(self, proxy_id):
            assert proxy_id == "edge-a"
            return {"pending": 2, "applying": 1, "failed": 3}

    monkeypatch.setattr(runtime_module, "get_operation_ledger", Ledger)

    result = ProxyRuntime._operation_ledger_health(runtime)

    assert result["ok"] is False
    assert result["counts"]["pending"] == 2
    assert result["counts"]["applying"] == 1
    assert result["counts"]["failed"] == 3
    assert "pending=2 applying=1 failed=3" in result["detail"]
    assert "convergence is still in progress" in result["detail"]

    class BrokenLedger:
        def counts_by_status(self, _proxy_id):
            msg = "ledger offline"
            raise RuntimeError(msg)

    monkeypatch.setattr(runtime_module, "get_operation_ledger", BrokenLedger)

    unavailable = ProxyRuntime._operation_ledger_health(runtime)

    assert unavailable["ok"] is False
    assert unavailable["counts"] == {}
    assert unavailable["detail"] == "Proxy operation ledger is unavailable."


def test_collect_navigation_health_degrades_while_operations_are_active() -> None:
    runtime = _runtime_shell()
    runtime.health_cache_ttl_seconds = 0.0
    runtime._health_cache_lock = threading.Lock()
    runtime.controller = SimpleNamespace(
        get_status=lambda: (b"squid ok", b""),
        _http_listener_details=lambda: ({"port": 3128, "mode": "explicit"},),
        _wait_for_http_listener=lambda *, timeout: True,
    )
    runtime._current_config_sha = lambda: "config-sha"
    runtime._supervisor_programs_health = lambda: {
        "ok": True,
        "detail": "supervisor programs running",
        "programs": {},
    }
    runtime._operation_ledger_health = lambda: {
        "ok": False,
        "detail": "operation ledger reachable; pending=1 applying=0 failed=0; proxy convergence is still in progress",
        "counts": {"pending": 1, "applying": 0, "failed": 0},
    }

    result = runtime.collect_navigation_health(force=True)

    assert result["ok"] is False
    assert result["status"] == "degraded"
    assert result["services"]["operation_ledger"]["counts"]["pending"] == 1


def test_collect_health_degrades_when_operation_ledger_unavailable() -> None:
    runtime = _runtime_shell()
    runtime.health_cache_ttl_seconds = 0.0
    runtime._health_cache_lock = threading.Lock()
    runtime._health_refresh_lock = threading.Lock()
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
    runtime._operation_ledger_health = lambda: {
        "ok": False,
        "detail": "operation ledger unavailable",
        "counts": {},
    }
    runtime.revisions = SimpleNamespace(
        get_active_revision_metadata=lambda _proxy_id: SimpleNamespace(
            revision_id=7,
            config_sha256="config-sha",
        ),
    )
    runtime.certificate_bundles = SimpleNamespace(
        get_active_bundle_metadata=lambda: SimpleNamespace(
            revision_id=8,
            bundle_sha256="cert-sha",
        ),
    )
    runtime.adblock_artifacts = SimpleNamespace(
        get_active_artifact_metadata=lambda: SimpleNamespace(
            revision_id=9,
            artifact_sha256="adblock-sha",
        ),
    )
    runtime._current_config_sha = lambda: "config-sha"
    runtime._current_certificate_bundle_sha = lambda: "cert-sha"
    runtime._current_adblock_artifact_sha = lambda: "adblock-sha"
    runtime._current_policy_sha = lambda: "policy-sha"
    runtime._current_pac_state_sha = lambda: "pac-sha"
    runtime.policy_state_builder = lambda _proxy_id: SimpleNamespace(
        policy_sha256="policy-sha",
        files=(),
    )
    runtime.pac_state_builder = lambda _proxy_id: SimpleNamespace(
        state_sha256="pac-sha",
        files=(),
    )
    runtime._adblock_materialization_integrity = lambda expected, *, current_sha=None: (
        True,
        "",
    )
    runtime._pac_materialization_integrity = lambda desired, *, current_sha=None: (
        True,
        "",
    )

    result = runtime.collect_health(force=True)

    assert result["ok"] is False
    assert result["status"] == "degraded"
    assert result["services"]["operation_ledger"]["detail"] == (
        "operation ledger unavailable"
    )


def test_collect_health_degrades_when_desired_runtime_state_drifts() -> None:
    runtime = _runtime_shell()
    runtime.health_cache_ttl_seconds = 0.0
    runtime._health_cache_lock = threading.Lock()
    runtime._health_refresh_lock = threading.Lock()
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
        get_active_revision_metadata=lambda _proxy_id: SimpleNamespace(
            revision_id=7,
            config_sha256="desired-config-sha",
        ),
    )
    runtime.certificate_bundles = SimpleNamespace(
        get_active_bundle_metadata=lambda: SimpleNamespace(
            revision_id=8,
            bundle_sha256="desired-cert-sha",
        ),
    )
    runtime.adblock_artifacts = SimpleNamespace(
        get_active_artifact_metadata=lambda: SimpleNamespace(
            revision_id=9,
            artifact_sha256="desired-adblock-sha",
        ),
    )
    runtime._current_config_sha = lambda: "current-config-sha"
    runtime._current_certificate_bundle_sha = lambda: "current-cert-sha"
    runtime._current_adblock_artifact_sha = lambda: "current-adblock-sha"
    runtime._current_policy_sha = lambda: "current-policy-sha"
    runtime._current_pac_state_sha = lambda: "current-pac-sha"
    runtime.policy_state_builder = lambda _proxy_id: SimpleNamespace(
        policy_sha256="desired-policy-sha",
        files=(),
    )
    runtime.pac_state_builder = lambda _proxy_id: SimpleNamespace(
        state_sha256="desired-pac-sha",
    )

    result = runtime.collect_health(force=True)

    assert result["ok"] is False
    assert result["status"] == "degraded"
    assert result["state_errors"] == [
        "config: desired desired-conf does not match current current-conf.",
        "certificate bundle: desired desired-cert does not match current current-cert.",
        "adblock artifact: desired desired-adbl does not match current current-adbl.",
        "policy: desired desired-poli does not match current current-poli.",
        "PAC: desired desired-pac- does not match current current-pac-.",
    ]


def test_collect_health_degrades_when_materialized_runtime_payload_is_stale() -> None:
    runtime = _runtime_shell()
    runtime.health_cache_ttl_seconds = 0.0
    runtime._health_cache_lock = threading.Lock()
    runtime._health_refresh_lock = threading.Lock()
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
        get_active_revision_metadata=lambda _proxy_id: SimpleNamespace(
            revision_id=7,
            config_sha256="config-sha",
        ),
    )
    runtime.certificate_bundles = SimpleNamespace(
        get_active_bundle_metadata=lambda: SimpleNamespace(
            revision_id=8,
            bundle_sha256="cert-sha",
        ),
    )
    runtime.adblock_artifacts = SimpleNamespace(
        get_active_artifact_metadata=lambda: SimpleNamespace(
            revision_id=9,
            artifact_sha256="adblock-sha",
        ),
    )
    pac_state = SimpleNamespace(state_sha256="pac-sha", files=())
    runtime._current_config_sha = lambda: "config-sha"
    runtime._current_certificate_bundle_sha = lambda: "cert-sha"
    runtime._current_adblock_artifact_sha = lambda: "adblock-sha"
    runtime._current_policy_sha = lambda: "policy-sha"
    runtime._current_pac_state_sha = lambda: "pac-sha"
    runtime.policy_state_builder = lambda _proxy_id: SimpleNamespace(
        policy_sha256="policy-sha",
        files=(),
    )
    runtime.pac_state_builder = lambda _proxy_id: pac_state
    runtime._adblock_materialization_integrity = lambda expected, *, current_sha=None: (
        False,
        "adblock request lookup database is missing.",
    )
    runtime._pac_materialization_integrity = lambda desired, *, current_sha=None: (
        False,
        "PAC materialized file is stale: fallback.pac",
    )

    result = runtime.collect_health(force=True)

    assert result["ok"] is False
    assert result["status"] == "degraded"
    assert result["state_errors"] == [
        "adblock artifact: adblock request lookup database is missing.",
        "PAC: PAC materialized file is stale: fallback.pac",
    ]


def test_collect_health_accepts_normalized_active_config_revision() -> None:
    _add_repo_paths()
    from services.squid_core import SquidController  # type: ignore

    controller = SquidController("/tmp/nonexistent-squid.conf")
    active_config = """http_port 3128
include /etc/squid/conf.d/30-webfilter.conf
acl icap_adblockable method GET HEAD
include /etc/squid/conf.d/20-icap.conf
adaptation_access adblock_req_set allow icap_adblockable
adaptation_access adblock_req_set deny all
http_access deny all
"""
    normalized_config = controller.normalize_config_text(active_config)
    active_sha = hashlib.sha256(active_config.encode()).hexdigest()
    normalized_sha = hashlib.sha256(normalized_config.encode()).hexdigest()

    runtime = _runtime_shell()
    runtime.health_cache_ttl_seconds = 0.0
    runtime._health_cache_lock = threading.Lock()
    runtime._health_refresh_lock = threading.Lock()
    runtime.controller = SimpleNamespace(
        get_status=lambda: (b"squid ok", b""),
        _http_listener_details=lambda: ({"port": 3128, "mode": "explicit"},),
        _wait_for_http_listener=lambda *, timeout: True,
        normalize_config_text=controller.normalize_config_text,
    )
    runtime.stats_provider = dict
    runtime.runtime_services_builder = lambda **_kwargs: {"icap": {"ok": True}}
    runtime._supervisor_programs_health = lambda: {
        "ok": True,
        "detail": "supervisor programs running",
        "programs": {},
    }
    runtime.revisions = SimpleNamespace(
        get_active_revision_metadata=lambda _proxy_id: SimpleNamespace(
            revision_id=7,
            config_sha256=active_sha,
        ),
        get_active_revision=lambda _proxy_id: SimpleNamespace(
            revision_id=7,
            config_sha256=active_sha,
            config_text=active_config,
        ),
    )
    runtime.certificate_bundles = SimpleNamespace(
        get_active_bundle_metadata=lambda: None,
    )
    runtime.adblock_artifacts = SimpleNamespace(
        get_active_artifact_metadata=lambda: None,
    )
    runtime._current_config_sha = lambda: normalized_sha
    runtime._current_certificate_bundle_sha = lambda: ""
    runtime._current_adblock_artifact_sha = lambda: ""
    runtime._current_policy_sha = lambda: "policy-sha"
    runtime._current_pac_state_sha = lambda: "pac-sha"
    runtime.policy_state_builder = lambda _proxy_id: SimpleNamespace(
        policy_sha256="policy-sha",
        files=(),
    )
    runtime.pac_state_builder = lambda _proxy_id: SimpleNamespace(
        state_sha256="pac-sha",
    )

    result = runtime.collect_health(force=True)

    assert active_sha != normalized_sha
    assert result["ok"] is True
    assert result["active_revision_sha"] == normalized_sha
    assert result["current_config_sha"] == normalized_sha
    assert result["state_errors"] == []


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
    monkeypatch.setattr(
        runtime_module,
        "_check_forwarding",
        lambda **_kwargs: {"ok": True, "detail": "forwarding ok"},
    )
    started = runtime_module.time.monotonic()

    result = runtime_module.build_local_runtime_services(icap_timeout=0.8)

    assert set(calls) == {"icap", "av_icap", "clamd"}
    assert runtime_module.time.monotonic() - started < 0.13
    assert result["clamav"]["ok"] is True


def test_local_runtime_service_health_uses_tcp_timeout_for_clamd(monkeypatch) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    captured: dict[str, float] = {}

    def ok_probe(**_kwargs):
        return {"ok": True, "detail": "ok"}

    def clamd_probe(**kwargs):
        captured["timeout"] = kwargs["timeout"]
        return {"ok": True, "detail": "clamd"}

    monkeypatch.setattr(runtime_module, "_check_icap_adblock", ok_probe)
    monkeypatch.setattr(runtime_module, "_check_icap_av", ok_probe)
    monkeypatch.setattr(runtime_module, "_check_clamd", clamd_probe)
    monkeypatch.setattr(
        runtime_module,
        "_check_forwarding",
        lambda **_kwargs: {"ok": True, "detail": "forwarding ok"},
    )

    result = runtime_module.build_local_runtime_services(
        icap_timeout=0.8,
        tcp_timeout=0.25,
    )

    assert captured["timeout"] == pytest.approx(0.25)
    assert result["clamd"]["ok"] is True


def test_local_runtime_service_health_does_not_wait_for_stuck_probe(
    monkeypatch,
) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    def stuck_probe(**_kwargs):
        runtime_module.time.sleep(2.0)
        return {"ok": True, "detail": "late"}

    def ok_probe(**_kwargs):
        return {"ok": True, "detail": "ok"}

    monkeypatch.setattr(runtime_module, "_check_icap_adblock", stuck_probe)
    monkeypatch.setattr(runtime_module, "_check_icap_av", ok_probe)
    monkeypatch.setattr(runtime_module, "_check_clamd", ok_probe)
    monkeypatch.setattr(
        runtime_module,
        "_check_forwarding",
        lambda **_kwargs: {"ok": True, "detail": "forwarding ok"},
    )
    started = runtime_module.time.monotonic()

    result = runtime_module.build_local_runtime_services(
        icap_timeout=0.01,
        tcp_timeout=0.01,
    )

    assert runtime_module.time.monotonic() - started < 1.4
    assert result["icap"]["ok"] is False
    assert "timed out" in result["icap"]["detail"]


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
                "forwarding_canary RUNNING pid 5\n"
                "proxy_agent RUNNING pid 6\n"
            ),
        )

    monkeypatch.setattr(runtime_module.subprocess, "run", fake_run)

    result = runtime._supervisor_programs_health()

    assert result["ok"] is True
    assert len(calls) == 1
    assert calls[0][:4] == ["supervisorctl", "-c", "/etc/supervisord.conf", "status"]


def test_squid_restart_waits_for_icap_readiness_before_accepting_success() -> None:
    _add_repo_paths()
    from services.squid_core import SquidController  # type: ignore

    calls: list[list[str]] = []

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        return _cp(0, stdout="ok")

    controller = SquidController.__new__(SquidController)
    controller.squid_conf_path = "/etc/squid/squid.conf"
    controller._run = fake_run
    controller._decode_completed = lambda proc: (proc.stdout or b"").decode().strip()
    controller._http_listener_ports = lambda *_args, **_kwargs: (3128,)
    controller._http_listener_response_ports = lambda *_args, **_kwargs: (3128,)
    controller._wait_for_http_listener_absent = lambda *, timeout: True
    controller._wait_for_squid_pidfile_stale_or_absent = lambda *, timeout: True
    controller._remove_stale_squid_pidfile = lambda **_kwargs: ""
    controller._accept_running_squid_restart = lambda *args, **kwargs: None
    controller._wait_for_http_listener = lambda *, timeout: True
    controller._check_icap_readiness = lambda *, timeout: (
        False,
        "adblock OPTIONS not ready",
    )

    ok, detail = controller._restart_squid_locked(ready_timeout=1.0)

    assert ok is False
    assert "adblock OPTIONS not ready" in detail
    assert ["supervisorctl", "-c", "/etc/supervisord.conf", "start", "squid"] in calls


def test_adblock_artifact_restart_pauses_squid_until_icap_ready() -> None:
    runtime = _runtime_shell()
    calls: list[object] = []

    class Controller:
        def _supervisor_program_running(self, program):
            assert program == "squid"
            return True

        def _run(self, args, **_kwargs):
            calls.append(list(args))
            return _cp(0, stdout="squid: stopped")

        def _decode_completed(self, proc):
            return (proc.stdout or b"").decode().strip()

        def _wait_for_http_listener_absent(self, *, timeout):
            calls.append(("absent", timeout))
            return True

        def _wait_for_icap_readiness(self, *, timeout):
            calls.append(("icap", timeout))
            return True, "ICAP ready"

        def restart_squid(self, *, ready_timeout):
            msg = "public restart_squid must not be called while lifecycle lock is held"
            raise AssertionError(msg)

        def _restart_squid_locked(self, *, ready_timeout):
            calls.append(("restart_squid_locked", ready_timeout))
            return (
                True,
                "Squid HTTP listener is responding and ICAP readiness is green.",
            )

    runtime.controller = Controller()
    runtime._restart_adblock_service = lambda: (
        calls.append("adblock_restart") or (True, "adblock restarted")
    )

    ok, detail = runtime._restart_adblock_service_with_squid_paused()

    assert ok is True
    assert calls == [
        ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "squid"],
        ("absent", 30.0),
        "adblock_restart",
        ("restart_squid_locked", 75.0),
    ]
    assert "adblock restarted" in detail
    assert "Squid HTTP listener is responding" in detail


def test_adblock_restart_under_lifecycle_lock_uses_locked_squid_restart_without_deadlock(
    monkeypatch,
) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    lock_state = {"held": False}

    @contextlib.contextmanager
    def detecting_lifecycle_lock():
        if lock_state["held"]:
            msg = "recursive public Squid lifecycle lock acquisition would deadlock"
            raise AssertionError(msg)
        lock_state["held"] = True
        try:
            yield
        finally:
            lock_state["held"] = False

    monkeypatch.setattr(
        runtime_module,
        "_exclusive_squid_lifecycle_lock",
        detecting_lifecycle_lock,
    )

    runtime = _runtime_shell()
    calls: list[object] = []
    result: dict[str, object] = {}

    class Controller:
        def _supervisor_program_running(self, program):
            assert program == "squid"
            return True

        def _run(self, args, **_kwargs):
            calls.append(list(args))
            return _cp(0, stdout="squid: stopped")

        def _decode_completed(self, proc):
            return (proc.stdout or b"").decode().strip()

        def _wait_for_http_listener_absent(self, *, timeout):
            calls.append(("absent", timeout))
            return True

        def restart_squid(self, *, ready_timeout):
            # The pre-fix path called this public API while already holding the
            # lifecycle lock, which recursively acquired the flock and left Squid
            # stopped.  The detecting lock raises here instead of hanging the
            # regression test.
            calls.append(("public_restart_squid", ready_timeout))
            with runtime_module._exclusive_squid_lifecycle_lock():
                return True, "unexpected public restart"

        def _restart_squid_locked(self, *, ready_timeout):
            assert lock_state["held"] is True
            calls.append(("locked_restart_squid", ready_timeout))
            return True, "Squid HTTP listener returned after locked restart."

    runtime.controller = Controller()
    runtime._restart_adblock_service = lambda: (
        calls.append("adblock_restart") or (True, "adblock restarted")
    )

    def invoke_restart() -> None:
        ok, detail = runtime._restart_adblock_service_with_squid_paused()
        result["ok"] = ok
        result["detail"] = detail

    thread = threading.Thread(target=invoke_restart, daemon=True)
    thread.start()
    thread.join(timeout=1.0)

    assert not thread.is_alive()
    assert result == {
        "ok": True,
        "detail": "squid: stopped\nadblock restarted\nSquid HTTP listener returned after locked restart.",
    }
    assert ("public_restart_squid", 75.0) not in calls
    assert ("locked_restart_squid", 75.0) in calls


def test_sync_from_db_initial_helper_restart_restores_squid_and_noops_next_sync() -> (
    None
):
    runtime = _runtime_shell()
    calls: list[object] = []

    class Controller:
        def __init__(self) -> None:
            self.materialized = False

        def set_adblock_icap_revision_token(self, token) -> None:
            self.token = token

        def set_adblock_enabled(self, enabled) -> None:
            self.adblock_enabled = enabled

        def get_current_config(self):
            return "workers 1\nhttp_port 3128\n"

        def materialize_clamav_runtime_files(self, config_text, **_kwargs):
            calls.append(("materialize", config_text))
            return True, "ClamAV runtime files already current."

        def normalize_config_text(self, text):
            return text

        def _supervisor_program_running(self, program):
            calls.append(("status", program))
            return True

        def _run(self, args, **_kwargs):
            calls.append(list(args))
            return _cp(0, stdout="squid: stopped")

        def _decode_completed(self, proc):
            return (proc.stdout or b"").decode().strip()

        def _wait_for_http_listener_absent(self, *, timeout):
            calls.append(("absent", timeout))
            return True

        def _wait_for_icap_readiness(self, *, timeout):
            msg = "Squid restart wrapper should own the ICAP readiness gate"
            raise AssertionError(msg)

        def restart_squid(self, *, ready_timeout):
            msg = "public restart_squid must not be called while lifecycle lock is held"
            raise AssertionError(msg)

        def _restart_squid_locked(self, *, ready_timeout):
            calls.append(("restart_squid_locked", ready_timeout))
            return (
                True,
                "Squid HTTP listener is responding and ICAP readiness is green.",
            )

    class Revisions:
        def get_active_revision_metadata(self, _proxy_id):
            return SimpleNamespace(revision_id=9, config_sha256="current-sha")

        def latest_apply(self, _proxy_id) -> None:
            return None

        def get_active_revision(self, _proxy_id) -> NoReturn:
            msg = "active config should not be fetched during no-op sync"
            raise AssertionError(msg)

    class Registry:
        def mark_apply_result(self, *_args, **_kwargs) -> NoReturn:
            msg = "successful no-op sync should not mark failed apply"
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
        "changed": False,
        "reload_required": False,
    }
    adblock_results = iter(
        [
            {"ok": True, "changed": True, "artifact_sha256": "adblock-sha"},
            {"ok": True, "changed": False, "artifact_sha256": "adblock-sha"},
        ],
    )

    def sync_adblock(force=False):
        result = next(adblock_results)
        if result["changed"]:
            ok_restart, restart_detail = (
                runtime._restart_adblock_service_with_squid_paused()
            )
            result = {**result, "ok": ok_restart, "detail": restart_detail}
        return result

    runtime._restart_adblock_service = lambda: (True, "adblock restarted")
    runtime.sync_adblock_state = sync_adblock
    runtime.sync_pac_state = lambda force=False: {"ok": True, "changed": False}
    runtime._current_config_sha = lambda: "current-sha"
    runtime._current_adblock_artifact_sha = lambda: "adblock-sha"
    runtime._current_adblock_enabled = lambda: True
    runtime._ensure_policy_runtime_config = lambda: (True, "", False)
    runtime._reload_for_policy_update = lambda *, wait_for_adblock_icap=True: (
        calls.append(("reload", wait_for_adblock_icap))
        or (True, "Squid reconfigured for policy update.")
    )

    first = runtime.sync_from_db(force=False)
    second = runtime.sync_from_db(force=False)

    assert first["ok"] is True
    assert first["changed"] is True
    assert second["ok"] is True
    assert second["changed"] is False
    assert calls == [
        ("status", "squid"),
        ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "squid"],
        ("absent", 30.0),
        ("restart_squid_locked", 75.0),
        ("materialize", "workers 1\nhttp_port 3128\n"),
        ("reload", True),
        ("materialize", "workers 1\nhttp_port 3128\n"),
    ]


def test_packaged_proxy_healthcheck_treats_icap_helpers_as_fail_open_by_default() -> (
    None
):
    repo_root = Path(__file__).resolve().parents[2]
    healthcheck = (repo_root / "docker" / "healthcheck.sh").read_text(
        encoding="utf-8",
    )

    assert "clamav_required()" in healthcheck
    assert "adblock_icap_required()" in healthcheck
    assert "extract_squid_workers_from_file()" in healthcheck
    assert (
        'ICAP_WORKERS_RAW="$(extract_squid_workers_from_file /etc/squid/squid.conf)"'
        in healthcheck
    )
    assert (
        'ICAP_WORKERS="$(clamp_workers "${ICAP_WORKERS_RAW:-${SQUID_WORKERS:-${WORKERS:-1}}}")"'
        in healthcheck
    )
    assert "cicap_adblock_${instance}" in healthcheck
    assert "cicap_av_${instance}" in healthcheck
    assert "clamav_respmod_${instance}" in healthcheck
    assert "supervisor_program_running proxy_agent" in healthcheck
    assert "supervisor reports proxy_agent is not RUNNING" in healthcheck
    assert "supervisor_program_running forwarding_canary" in healthcheck
    assert "forwarding_canary is not accepting loopback connections" in healthcheck
    assert "docker-proxy-forwarding-canary" in healthcheck
    assert "icap_av_base_port" in healthcheck
    assert "icap_av_resp_base_port" in healthcheck
    assert "clamd_host_is_remote" in healthcheck
    assert "Squid adblock ICAP is fail-open" in healthcheck
    assert "check_squid_forwarding_path" in healthcheck
    assert "check_icap_readiness" in healthcheck
    assert "/usr/local/bin/icap_readiness.py check" in healthcheck
    assert "Configured ICAP services are not OPTIONS-ready" in healthcheck
    assert "PROXY_HEALTHCHECK_FORWARDING_REQUIRED" in healthcheck
    assert "squid-flask-proxy-forwarding-health" in healthcheck
    assert "local canary target" in healthcheck
    assert (
        "ADBLOCK_ICAP_REQUIRED is set but supervisor reports ${adblock_program} is not RUNNING"
        in healthcheck
    )
    assert (
        "CLAMAV_REQUIRED is set but supervisor reports ${av_program} is not RUNNING"
        in healthcheck
    )
    assert (
        "CLAMAV_REQUIRED is set but supervisor reports ${resp_program} is not RUNNING"
        in healthcheck
    )
    assert "CLAMAV_REQUIRED is set but remote clamd is not responding" in healthcheck
    assert (
        "supervisor_program_running cicap_adblock || ! supervisor_program_running cicap_av"
        not in healthcheck
    )


def test_packaged_proxy_healthcheck_checks_https_intercept_listeners() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    healthcheck = (repo_root / "docker" / "healthcheck.sh").read_text(
        encoding="utf-8",
    )

    assert "lower.startswith(('http_port ', 'https_port '))" in healthcheck
    assert "Squid listener(s) not accepting connections" in healthcheck


def test_packaged_proxy_healthcheck_normalizes_forwarding_canary_path_like_runtime() -> None:
    default_url = (
        "http://127.0.0.1:18080/__docker_proxy_forwarding_canary?probe=squid-respmod"
    )

    assert (
        _healthcheck_forwarding_canary_url(FORWARDING_CANARY_PATH="/bad//canary")
        == default_url
    )
    assert (
        _healthcheck_forwarding_canary_url(FORWARDING_CANARY_PATH="/custom-canary")
        == "http://127.0.0.1:18080/custom-canary?probe=squid-respmod"
    )


def test_packaged_proxy_entrypoint_does_not_wait_for_optional_clamav() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    entrypoint = (repo_root / "docker" / "entrypoint.sh").read_text(
        encoding="utf-8",
    )

    assert "CLAMAV_REQUIRED=0" in entrypoint
    assert "/usr/local/bin/cicap_av_runner.py" in entrypoint
    av_section = entrypoint.split("[program:cicap_av_${instance}]", 1)[1].split(
        "autostart=true",
        1,
    )[0]
    assert "python3 -c" not in av_section
    assert "ping_clamd" not in av_section


def test_packaged_proxy_entrypoint_keeps_adblock_running_before_squid_gate() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    entrypoint = (repo_root / "docker" / "entrypoint.sh").read_text(
        encoding="utf-8",
    )
    section = entrypoint.split("[program:cicap_adblock_${instance}]", 1)[1].split(
        "[program:cicap_av_${instance}]",
        1,
    )[0]

    assert "autorestart=unexpected" in section
    assert "exitcodes=0" in section
    assert "startsecs=1" in section
    assert "startsecs=45" not in section
    assert "startretries=2" in section
    assert "bypass=on" in entrypoint


def test_runtime_adblock_supervisor_config_matches_startup_readiness_contract() -> None:
    _add_repo_paths()
    from services.squid_core import SquidController  # type: ignore

    files = SquidController()._render_icap_supervisor_files(workers=1)
    adblock_configs = [
        content
        for path, content in files.items()
        if path.name == "cicap_adblock_1.conf"
    ]
    assert len(adblock_configs) == 1
    section = adblock_configs[0]

    assert "autorestart=unexpected" in section
    assert "exitcodes=0" in section
    assert "startsecs=1" in section
    assert "startsecs=45" not in section


def test_packaged_proxy_supervisor_stops_squid_process_group() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    supervisord = (repo_root / "docker" / "supervisord.proxy.conf").read_text(
        encoding="utf-8",
    )
    section = supervisord.split("[program:squid]", 1)[1].split("[program:", 1)[0]

    assert "command=/usr/local/bin/squid_ready_start.sh" in section
    assert "priority=40" in section
    assert "stopasgroup=true" in section
    assert "killasgroup=true" in section


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


def test_squid_controller_matches_socket_inode_symlink_targets(
    monkeypatch,
    tmp_path,
) -> None:
    _add_repo_paths()
    import pathlib

    from services import squid_core  # type: ignore
    from services.squid_core import SquidController  # type: ignore

    proc_root = tmp_path / "proc"
    fd_dir = proc_root / "4321" / "fd"
    fd_dir.mkdir(parents=True)
    (fd_dir / "7").symlink_to("socket:[12345]")

    def fake_path(value):
        if str(value) == "/proc":
            return proc_root
        return pathlib.Path(value)

    monkeypatch.setattr(squid_core, "Path", fake_path)

    controller = SquidController.__new__(SquidController)

    assert controller._pids_with_socket_inodes({"12345"}) == {4321}


def test_sync_from_db_reconfigures_squid_after_runtime_icap_include_change() -> None:
    runtime = _runtime_shell()
    reloads: list[bool] = []

    class Controller:
        def set_adblock_icap_revision_token(self, token) -> None:
            self.token = token

        def materialize_clamav_runtime_files(self, config_text, **_kwargs):
            self.config_text = config_text
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
    runtime.controller.get_current_config = lambda: "workers 2\nhttp_port 3128\n"
    runtime._reload_for_policy_update = lambda *, wait_for_adblock_icap=True: (
        reloads.append(wait_for_adblock_icap)
        or (
            True,
            "Squid reconfigured for policy update.",
        )
    )

    result = runtime.sync_from_db(force=False)

    assert result["ok"] is True
    assert result["changed"] is True
    assert reloads == [False]
    assert runtime.controller.token == "adblock-sha"
    assert runtime.controller.config_text == "workers 2\nhttp_port 3128\n"
    assert "ClamAV runtime files updated" in result["detail"]
    assert "Squid reconfigured for policy update." in result["detail"]


def test_sync_from_db_skips_extra_reload_after_clamav_runtime_restart() -> None:
    runtime = _runtime_shell()
    reloads: list[bool] = []

    class Controller:
        def set_adblock_icap_revision_token(self, token) -> None:
            self.token = token

        def materialize_clamav_runtime_files(self, config_text, **_kwargs):
            self.config_text = config_text
            detail = (
                "ClamAV runtime files updated: /etc/squid/conf.d/20-icap.conf, "
                "Squid restarted after ICAP supervisor update."
            )
            return True, detail

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
            msg = "successful runtime ICAP restart should not mark failed apply"
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
    runtime.controller.get_current_config = lambda: "workers 2\nhttp_port 3128\n"
    runtime._reload_for_policy_update = lambda *, wait_for_adblock_icap=True: (
        reloads.append(wait_for_adblock_icap)
        or (
            True,
            "Squid reconfigured for policy update.",
        )
    )

    result = runtime.sync_from_db(force=False)

    assert result["ok"] is True
    assert result["changed"] is True
    assert reloads == []
    assert runtime.controller.token == "adblock-sha"
    assert runtime.controller.config_text == "workers 2\nhttp_port 3128\n"
    assert "Squid restarted after ICAP supervisor update." in result["detail"]


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

        def materialize_clamav_runtime_files(self, _config_text, **_kwargs):
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
    runtime._reload_for_policy_update = lambda *, wait_for_adblock_icap=True: (
        reloads.append(wait_for_adblock_icap)
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
    op = SimpleNamespace(operation_id=5, target_kind="", target_ref="")
    calls: list[tuple[str, object]] = []

    class Ledger:
        def requeue_stale_applying(self, proxy_id) -> None:
            calls.append(("requeue", proxy_id))

        def claim_pending(self, proxy_id, *, limit, operation_id=None):
            calls.append(("claim", (proxy_id, limit, operation_id)))
            return [op]

        def mark_status(self, operation_id, *, status, detail) -> None:
            calls.append(("mark", (operation_id, status, detail)))

    monkeypatch.setattr(runtime_module, "get_operation_ledger", Ledger)
    runtime._sync_from_db_unlocked = (
        lambda *, force=False, artifact_force=None, operations=None: {
            "ok": True,
            "detail": "runtime reconciled",
            "claimed_operation_ids": [op.operation_id for op in (operations or [])],
        }
    )

    result = runtime.sync_from_db(force=False)

    assert result["ok"] is True
    assert calls == [
        ("requeue", "edge-a"),
        ("claim", ("edge-a", 100, None)),
        ("mark", (5, "applied", "runtime reconciled")),
    ]


def test_sync_from_db_routes_claimed_operation_force_to_artifact_sync(
    monkeypatch,
) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    monkeypatch.setattr(runtime_module, "get_proxy_id", lambda: "edge-a")
    op = SimpleNamespace(operation_id=5, target_kind="", target_ref="", force=True)
    observed: list[tuple[bool, bool]] = []

    class Ledger:
        def requeue_stale_applying(self, _proxy_id) -> None:
            return None

        def claim_pending(self, _proxy_id, *, limit, operation_id=None):
            assert limit == 100
            assert operation_id is None
            return [op]

        def mark_status(self, *_args, **_kwargs) -> None:
            return None

    monkeypatch.setattr(runtime_module, "get_operation_ledger", Ledger)

    def sync_unlocked(*, force=False, artifact_force=None, operations=None):
        observed.append((bool(force), bool(artifact_force)))
        assert operations == [op]
        return {"ok": True, "detail": "runtime reconciled"}

    runtime._sync_from_db_unlocked = sync_unlocked

    result = runtime.sync_from_db(force=False)

    assert result["ok"] is True
    assert observed == [(False, True)]


def test_sync_from_db_logs_operation_ledger_claim_failure(monkeypatch) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    log_calls: list[tuple[str, str, str, str]] = []
    observed: list[tuple[bool, list[object]]] = []

    class Ledger:
        def requeue_stale_applying(self, _proxy_id) -> None:
            msg = "ledger unavailable"
            raise RuntimeError(msg)

    def capture_log(
        key,
        *,
        recoverable_message,
        unexpected_message,
        exc,
        interval_seconds,
    ) -> None:
        log_calls.append(
            (key, recoverable_message, unexpected_message, str(exc)),
        )

    monkeypatch.setattr(runtime_module, "get_proxy_id", lambda: "edge-a")
    monkeypatch.setattr(runtime_module, "get_operation_ledger", Ledger)
    monkeypatch.setattr(
        runtime_module,
        "_log_recoverable_db_or_unexpected",
        capture_log,
    )

    def sync_unlocked(*, force=False, artifact_force=None, operations=None):
        observed.append((bool(force), list(operations or [])))
        return {"ok": True, "detail": "runtime reconciled"}

    runtime._sync_from_db_unlocked = sync_unlocked

    result = runtime.sync_from_db(force=False)

    assert result["ok"] is True
    assert observed == [(False, [])]
    assert log_calls == [
        (
            "proxy_runtime.operation_ledger.claim",
            "Proxy operation ledger unavailable during runtime reconciliation",
            "Proxy operation ledger claim failed",
            "ledger unavailable",
        )
    ]


def test_sync_from_db_marks_matching_config_revision_applied(monkeypatch) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    monkeypatch.setattr(runtime_module, "get_proxy_id", lambda: "edge-a")
    op = SimpleNamespace(
        operation_id=6,
        operation_type="config_apply",
        target_kind="config_revision",
        target_ref="9",
    )
    calls: list[tuple[int, str, str]] = []

    class Ledger:
        def requeue_stale_applying(self, proxy_id) -> None:
            assert proxy_id == "edge-a"

        def claim_pending(self, proxy_id, *, limit, operation_id=None):
            assert proxy_id == "edge-a"
            assert limit == 100
            assert operation_id is None
            return [op]

        def mark_status(self, operation_id, *, status, detail) -> None:
            calls.append((operation_id, status, detail))

    monkeypatch.setattr(runtime_module, "get_operation_ledger", Ledger)
    runtime._sync_from_db_unlocked = (
        lambda *, force=False, artifact_force=None, operations=None: {
            "ok": True,
            "revision_id": 9,
            "detail": "runtime reconciled",
            "executed_operation_types": ["config_apply"],
        }
    )

    result = runtime.sync_from_db(force=False)

    assert result["ok"] is True
    assert calls == [(6, "applied", "runtime reconciled")]


def test_sync_from_db_marks_stale_config_operations_superseded(monkeypatch) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    monkeypatch.setattr(runtime_module, "get_proxy_id", lambda: "edge-a")
    stale = SimpleNamespace(
        operation_id=5,
        operation_type="config_apply",
        target_kind="config_revision",
        target_ref="7",
    )
    current = SimpleNamespace(
        operation_id=6,
        operation_type="config_apply",
        target_kind="config_revision",
        target_ref="9",
    )
    calls: list[tuple[int, str, str]] = []

    class Ledger:
        def requeue_stale_applying(self, proxy_id) -> None:
            assert proxy_id == "edge-a"

        def claim_pending(self, proxy_id, *, limit, operation_id=None):
            assert proxy_id == "edge-a"
            assert limit == 100
            assert operation_id is None
            return [stale, current]

        def mark_status(self, operation_id, *, status, detail) -> None:
            calls.append((operation_id, status, detail))

    monkeypatch.setattr(runtime_module, "get_operation_ledger", Ledger)
    runtime._sync_from_db_unlocked = (
        lambda *, force=False, artifact_force=None, operations=None: {
            "ok": True,
            "revision_id": 9,
            "detail": "runtime reconciled",
            "executed_operation_types": ["config_apply"],
        }
    )

    result = runtime.sync_from_db(force=False)

    assert result["ok"] is True
    assert calls[0][0:2] == (5, "superseded")
    assert "active config revision 9" in calls[0][2]
    assert "queued config revision 7 was not applied" in calls[0][2]
    assert calls[1] == (6, "applied", "runtime reconciled")


@pytest.mark.parametrize("invalid_target", [None, "", "not-a-revision"])
def test_sync_from_db_fails_config_operation_with_invalid_target(
    monkeypatch,
    invalid_target,
) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    monkeypatch.setattr(runtime_module, "get_proxy_id", lambda: "edge-a")
    op = SimpleNamespace(
        operation_id=5,
        operation_type="config_apply",
        target_kind="config_revision",
        target_ref=invalid_target,
    )
    calls: list[tuple[int, str, str]] = []

    class Ledger:
        def requeue_stale_applying(self, _proxy_id) -> None:
            return None

        def claim_pending(self, _proxy_id, *, limit, operation_id=None):
            assert limit == 100
            assert operation_id is None
            return [op]

        def mark_status(self, operation_id, *, status, detail) -> None:
            calls.append((operation_id, status, detail))

    monkeypatch.setattr(runtime_module, "get_operation_ledger", Ledger)
    runtime._sync_from_db_unlocked = (
        lambda *, force=False, artifact_force=None, operations=None: {
            "ok": True,
            "revision_id": 9,
            "detail": "runtime reconciled",
            "executed_operation_types": ["config_apply"],
        }
    )

    result = runtime.sync_from_db(force=False)

    assert result["ok"] is True
    assert calls[0][0:2] == (5, "failed")
    assert "valid queued config revision target" in calls[0][2]
    assert "runtime reconciled" in calls[0][2]


def test_sync_from_db_fails_config_operation_without_revision_evidence(
    monkeypatch,
) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    monkeypatch.setattr(runtime_module, "get_proxy_id", lambda: "edge-a")
    op = SimpleNamespace(
        operation_id=5,
        operation_type="config_apply",
        target_kind="config_revision",
        target_ref="9",
    )
    calls: list[tuple[int, str, str]] = []

    class Ledger:
        def requeue_stale_applying(self, _proxy_id) -> None:
            return None

        def claim_pending(self, _proxy_id, *, limit, operation_id=None):
            assert limit == 100
            assert operation_id is None
            return [op]

        def mark_status(self, operation_id, *, status, detail) -> None:
            calls.append((operation_id, status, detail))

    monkeypatch.setattr(runtime_module, "get_operation_ledger", Ledger)
    runtime._sync_from_db_unlocked = (
        lambda *, force=False, artifact_force=None, operations=None: {
            "ok": True,
            "detail": "runtime reconciled without active config revision evidence",
            "executed_operation_types": ["config_apply"],
        }
    )

    result = runtime.sync_from_db(force=False)

    assert result["ok"] is True
    assert calls[0][0:2] == (5, "failed")
    assert "did not report the active config revision evidence" in calls[0][2]
    assert "runtime reconciled without active config revision evidence" in calls[0][2]


def test_sync_from_db_fails_claimed_config_operation_when_no_active_revision(
    monkeypatch,
) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    monkeypatch.setattr(runtime_module, "get_proxy_id", lambda: "edge-a")
    op = SimpleNamespace(
        operation_id=5,
        operation_type="config_apply",
        target_kind="config_revision",
        target_ref="12",
    )
    calls: list[tuple[int, str, str]] = []

    class Ledger:
        def requeue_stale_applying(self, proxy_id) -> None:
            assert proxy_id == "edge-a"

        def claim_pending(self, proxy_id, *, limit, operation_id=None):
            assert proxy_id == "edge-a"
            assert limit == 100
            assert operation_id is None
            return [op]

        def mark_status(self, operation_id, *, status, detail) -> None:
            calls.append((operation_id, status, detail))

    monkeypatch.setattr(runtime_module, "get_operation_ledger", Ledger)
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
        "artifact_sha256": "artifact-sha",
    }
    runtime.sync_pac_state = lambda force=False: {"ok": True, "changed": False}
    runtime._ensure_policy_runtime_config = lambda: (True, "", False)
    runtime._current_config_sha = lambda: "current-config-sha"
    runtime._current_adblock_artifact_sha = lambda: "artifact-sha"
    runtime._current_adblock_enabled = lambda: True
    runtime.controller = SimpleNamespace(
        set_adblock_icap_revision_token=lambda _token: None
    )
    runtime.revisions = SimpleNamespace(
        get_active_revision_metadata=lambda _proxy_id: None,
    )

    result = runtime.sync_from_db(force=False)

    assert result["ok"] is True
    assert "revision_id" not in result
    assert result["detail"] == "No active config revision is available for this proxy."
    assert calls[0][0:2] == (5, "failed")
    assert "did not report the active config revision evidence" in calls[0][2]
    assert "No active config revision is available for this proxy." in calls[0][2]


def test_sync_from_db_marks_matching_certificate_revision_applied(monkeypatch) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    monkeypatch.setattr(runtime_module, "get_proxy_id", lambda: "edge-a")
    op = SimpleNamespace(
        operation_id=5,
        operation_type="certificate_apply",
        target_kind="certificate_revision",
        target_ref="12",
    )
    calls: list[tuple[int, str, str]] = []

    class Ledger:
        def requeue_stale_applying(self, proxy_id) -> None:
            assert proxy_id == "edge-a"

        def claim_pending(self, proxy_id, *, limit, operation_id=None):
            assert proxy_id == "edge-a"
            assert limit == 100
            assert operation_id is None
            return [op]

        def mark_status(self, operation_id, *, status, detail) -> None:
            calls.append((operation_id, status, detail))

    monkeypatch.setattr(runtime_module, "get_operation_ledger", Ledger)
    runtime._invalidate_health_cache = lambda: None
    runtime.ensure_registered = lambda: None
    runtime.bootstrap_revision_if_missing = lambda: None
    runtime.sync_certificate_bundle = lambda force=False: {
        "ok": True,
        "changed": False,
        "certificate_revision_id": 12,
        "certificate_bundle_sha256": "cert-sha-12",
        "detail": "Proxy is already using the active certificate bundle.",
    }
    runtime.sync_policy_state = lambda force=False: {
        "ok": True,
        "changed": False,
        "reload_required": False,
    }
    runtime.sync_adblock_state = lambda force=False: {
        "ok": True,
        "changed": False,
        "artifact_sha256": "artifact-sha",
    }
    runtime.sync_pac_state = lambda force=False: {"ok": True, "changed": False}
    runtime._ensure_policy_runtime_config = lambda: (True, "", False)
    runtime._current_config_sha = lambda: "current-config-sha"
    runtime._current_adblock_artifact_sha = lambda: "artifact-sha"
    runtime._current_adblock_enabled = lambda: True
    runtime.controller = SimpleNamespace(
        set_adblock_icap_revision_token=lambda _token: None
    )
    runtime.revisions = SimpleNamespace(
        get_active_revision_metadata=lambda _proxy_id: None,
    )

    result = runtime.sync_from_db(force=False)

    assert result["ok"] is True
    assert result["certificate_revision_id"] == 12
    assert result["certificate_bundle_sha256"] == "cert-sha-12"
    assert calls == [
        (
            5,
            "applied",
            "Proxy is already using the active certificate bundle.",
        )
    ]


def test_sync_from_db_marks_stale_certificate_revision_superseded(monkeypatch) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    monkeypatch.setattr(runtime_module, "get_proxy_id", lambda: "edge-a")
    stale = SimpleNamespace(
        operation_id=5,
        operation_type="certificate_apply",
        target_kind="certificate_revision",
        target_ref="11",
    )
    current = SimpleNamespace(
        operation_id=6,
        operation_type="certificate_apply",
        target_kind="certificate_revision",
        target_ref="12",
    )
    calls: list[tuple[int, str, str]] = []

    class Ledger:
        def requeue_stale_applying(self, proxy_id) -> None:
            assert proxy_id == "edge-a"

        def claim_pending(self, proxy_id, *, limit, operation_id=None):
            assert proxy_id == "edge-a"
            assert limit == 100
            assert operation_id is None
            return [stale, current]

        def mark_status(self, operation_id, *, status, detail) -> None:
            calls.append((operation_id, status, detail))

    monkeypatch.setattr(runtime_module, "get_operation_ledger", Ledger)
    runtime._invalidate_health_cache = lambda: None
    runtime.ensure_registered = lambda: None
    runtime.bootstrap_revision_if_missing = lambda: None
    runtime.sync_certificate_bundle = lambda force=False: {
        "ok": True,
        "changed": False,
        "certificate_revision_id": 12,
        "certificate_bundle_sha256": "cert-sha-12",
        "detail": "Proxy is already using the active certificate bundle.",
    }
    runtime.sync_policy_state = lambda force=False: {
        "ok": True,
        "changed": False,
        "reload_required": False,
    }
    runtime.sync_adblock_state = lambda force=False: {
        "ok": True,
        "changed": False,
        "artifact_sha256": "artifact-sha",
    }
    runtime.sync_pac_state = lambda force=False: {"ok": True, "changed": False}
    runtime._ensure_policy_runtime_config = lambda: (True, "", False)
    runtime._current_config_sha = lambda: "config-sha-11"
    runtime._current_adblock_artifact_sha = lambda: "artifact-sha"
    runtime._current_adblock_enabled = lambda: True
    runtime.controller = SimpleNamespace(
        set_adblock_icap_revision_token=lambda _token: None
    )
    runtime.revisions = SimpleNamespace(
        get_active_revision_metadata=lambda _proxy_id: SimpleNamespace(
            revision_id=11,
            config_sha256="config-sha-11",
        ),
        latest_apply=lambda _proxy_id: None,
    )

    result = runtime.sync_from_db(force=False)

    assert result["ok"] is True
    assert result["revision_id"] == 11
    assert result["certificate_revision_id"] == 12
    assert calls[0][0:2] == (5, "superseded")
    assert "active certificate revision 12" in calls[0][2]
    assert "queued certificate revision 11 was not applied" in calls[0][2]
    assert calls[1] == (
        6,
        "applied",
        (
            "Proxy is already using the active certificate bundle.\n"
            "Proxy is already using the active config revision."
        ),
    )


def test_sync_from_db_fails_certificate_operation_without_revision_evidence(
    monkeypatch,
) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    monkeypatch.setattr(runtime_module, "get_proxy_id", lambda: "edge-a")
    op = SimpleNamespace(
        operation_id=5,
        operation_type="certificate_apply",
        target_kind="certificate_revision",
        target_ref="12",
    )
    calls: list[tuple[int, str, str]] = []

    class Ledger:
        def requeue_stale_applying(self, proxy_id) -> None:
            assert proxy_id == "edge-a"

        def claim_pending(self, proxy_id, *, limit, operation_id=None):
            assert proxy_id == "edge-a"
            assert limit == 100
            assert operation_id is None
            return [op]

        def mark_status(self, operation_id, *, status, detail) -> None:
            calls.append((operation_id, status, detail))

    monkeypatch.setattr(runtime_module, "get_operation_ledger", Ledger)
    runtime._invalidate_health_cache = lambda: None
    runtime.ensure_registered = lambda: None
    runtime.bootstrap_revision_if_missing = lambda: None
    runtime.sync_certificate_bundle = lambda force=False: {
        "ok": True,
        "changed": False,
        "certificate_bundle_sha256": "cert-sha-12",
        "detail": "Proxy certificate state reconciled without revision evidence.",
    }
    runtime.sync_policy_state = lambda force=False: {
        "ok": True,
        "changed": False,
        "reload_required": False,
    }
    runtime.sync_adblock_state = lambda force=False: {
        "ok": True,
        "changed": False,
        "artifact_sha256": "artifact-sha",
    }
    runtime.sync_pac_state = lambda force=False: {"ok": True, "changed": False}
    runtime._ensure_policy_runtime_config = lambda: (True, "", False)
    runtime._current_config_sha = lambda: "config-sha-12"
    runtime._current_adblock_artifact_sha = lambda: "artifact-sha"
    runtime._current_adblock_enabled = lambda: True
    runtime.controller = SimpleNamespace(
        set_adblock_icap_revision_token=lambda _token: None
    )
    runtime.revisions = SimpleNamespace(
        get_active_revision_metadata=lambda _proxy_id: SimpleNamespace(
            revision_id=12,
            config_sha256="config-sha-12",
        ),
        latest_apply=lambda _proxy_id: None,
    )

    result = runtime.sync_from_db(force=False)

    assert result["ok"] is True
    assert result["revision_id"] == 12
    assert result["certificate_revision_id"] is None
    assert calls[0][0:2] == (5, "failed")
    assert "did not report the active certificate revision evidence" in calls[0][2]


def test_sync_from_db_policy_operation_requires_selected_proxy_policy_convergence(
    monkeypatch,
) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    monkeypatch.setattr(runtime_module, "get_proxy_id", lambda: "edge-a")
    op = SimpleNamespace(
        operation_id=5,
        operation_type="policy_sync",
        target_kind="policy_state",
        target_ref="desired-a",
    )
    calls: list[tuple[int, str, str]] = []

    class Ledger:
        def requeue_stale_applying(self, _proxy_id) -> None:
            return None

        def claim_pending(self, _proxy_id, *, limit, operation_id=None):
            assert limit == 100
            assert operation_id is None
            return [op]

        def mark_status(self, operation_id, *, status, detail) -> None:
            calls.append((operation_id, status, detail))

    monkeypatch.setattr(runtime_module, "get_operation_ledger", Ledger)

    def sync_unlocked(*, force=False, artifact_force=None, operations=None):
        assert operations == [op]
        return {
            "ok": True,
            "detail": "runtime reconciled",
            "executed_operation_types": ["policy_sync"],
            "policy_sha256": "desired-a",
        }

    runtime._sync_from_db_unlocked = sync_unlocked
    runtime._current_policy_sha = lambda: "old-a"

    result = runtime.sync_from_db(force=False)

    assert result["ok"] is True
    assert calls == [
        (
            5,
            "failed",
            (
                "policy state sync did not converge selected-proxy runtime state; "
                "queued policy state desired-a differs from current policy state old-a.\n"
                "runtime reconciled"
            ),
        )
    ]


def test_sync_from_db_policy_operation_uses_selected_proxy_current_policy_sha(
    monkeypatch,
) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    monkeypatch.setattr(runtime_module, "get_proxy_id", lambda: "edge-a")
    edge_a = SimpleNamespace(
        operation_id=5,
        operation_type="policy_sync",
        target_kind="policy_state",
        target_ref="desired-a",
    )
    edge_b = SimpleNamespace(
        operation_id=6,
        operation_type="policy_sync",
        target_kind="policy_state",
        target_ref="desired-b",
    )
    calls: list[tuple[int, str, str]] = []

    class Ledger:
        def requeue_stale_applying(self, _proxy_id) -> None:
            return None

        def claim_pending(self, _proxy_id, *, limit, operation_id=None):
            assert limit == 100
            assert operation_id is None
            return [edge_a, edge_b]

        def mark_status(self, operation_id, *, status, detail) -> None:
            calls.append((operation_id, status, detail))

    monkeypatch.setattr(runtime_module, "get_operation_ledger", Ledger)

    def sync_unlocked(*, force=False, artifact_force=None, operations=None):
        assert operations == [edge_a, edge_b]
        return {
            "ok": True,
            "detail": "runtime reconciled",
            "executed_operation_types": ["policy_sync"],
            "policy_sha256": "desired-a",
            "current_policy_sha": "desired-a",
        }

    runtime._sync_from_db_unlocked = sync_unlocked
    runtime._current_policy_sha = lambda: "desired-b"

    result = runtime.sync_from_db(force=False)

    assert result["ok"] is True
    assert calls[0] == (5, "applied", "runtime reconciled")
    assert calls[1][0:2] == (6, "superseded")
    assert "queued policy state desired-b was not applied" in calls[1][2]


def test_operation_completion_requires_exact_pac_target_and_current_runtime() -> None:
    from proxy import runtime as runtime_module

    op = SimpleNamespace(
        operation_type="pac_refresh",
        target_kind="pac_state",
        target_ref="pac-a",
    )

    assert runtime_module._operation_completion_status(
        op,
        default_status="applied",
        detail="runtime reconciled",
        result={
            "executed_operation_types": ["pac_refresh"],
            "state_sha256": "pac-a",
            "current_state_sha256": "pac-a",
        },
    ) == ("applied", "runtime reconciled")

    status, detail = runtime_module._operation_completion_status(
        op,
        default_status="applied",
        detail="runtime reconciled",
        result={
            "executed_operation_types": ["pac_refresh"],
            "state_sha256": "pac-b",
            "current_state_sha256": "pac-b",
        },
    )
    assert status == "superseded"
    assert "queued PAC state pac-a" in detail

    missing_status, missing_detail = runtime_module._operation_completion_status(
        op,
        default_status="applied",
        detail="runtime reconciled",
        result={"executed_operation_types": ["pac_refresh"]},
    )
    assert missing_status == "failed"
    assert "did not report active target evidence" in missing_detail

    mismatch_status, mismatch_detail = runtime_module._operation_completion_status(
        op,
        default_status="applied",
        detail="runtime reconciled",
        result={
            "executed_operation_types": ["pac_refresh"],
            "state_sha256": "pac-a",
            "current_state_sha256": "pac-current-mismatch",
        },
    )
    assert mismatch_status == "failed"
    assert "did not converge selected-proxy runtime state" in mismatch_detail


def test_operation_completion_requires_exact_adblock_artifact_revision_and_hash() -> (
    None
):
    from proxy import runtime as runtime_module

    op = SimpleNamespace(
        operation_type="adblock_refresh",
        target_kind="adblock_artifact",
        target_ref="7",
        request_hash="artifact-a",
    )

    assert runtime_module._operation_completion_status(
        op,
        default_status="applied",
        detail="runtime reconciled",
        result={
            "executed_operation_types": ["adblock_refresh"],
            "revision_id": 7,
            "artifact_sha256": "artifact-a",
            "current_adblock_artifact_sha256": "artifact-a",
        },
    ) == ("applied", "runtime reconciled")

    status, detail = runtime_module._operation_completion_status(
        op,
        default_status="applied",
        detail="runtime reconciled",
        result={
            "executed_operation_types": ["adblock_refresh"],
            "revision_id": 8,
            "artifact_sha256": "artifact-b",
            "current_adblock_artifact_sha256": "artifact-b",
        },
    )
    assert status == "superseded"
    assert "queued revision 7" in detail

    missing_status, missing_detail = runtime_module._operation_completion_status(
        op,
        default_status="applied",
        detail="runtime reconciled",
        result={"executed_operation_types": ["adblock_refresh"]},
    )
    assert missing_status == "failed"
    assert "did not report the active revision/hash evidence" in missing_detail

    mismatch_status, mismatch_detail = runtime_module._operation_completion_status(
        op,
        default_status="applied",
        detail="runtime reconciled",
        result={
            "executed_operation_types": ["adblock_refresh"],
            "revision_id": 7,
            "artifact_sha256": "artifact-a",
            "current_adblock_artifact_sha256": "artifact-current-mismatch",
        },
    )
    assert mismatch_status == "failed"
    assert "queued artifact artifact-a" in mismatch_detail


def test_operation_completion_tracks_adblock_build_settings_version_target() -> None:
    from proxy import runtime as runtime_module

    op = SimpleNamespace(
        operation_type="adblock_refresh",
        target_kind="adblock_artifact_build",
        target_ref="12",
        request_hash="",
    )

    assert runtime_module._operation_completion_status(
        op,
        default_status="applied",
        detail="runtime reconciled",
        result={
            "executed_operation_types": ["adblock_refresh"],
            "adblock_settings_version": 12,
            "revision_id": 9,
            "artifact_sha256": "artifact-c",
        },
    ) == ("applied", "runtime reconciled")

    status, detail = runtime_module._operation_completion_status(
        op,
        default_status="applied",
        detail="runtime reconciled",
        result={
            "executed_operation_types": ["adblock_refresh"],
            "adblock_settings_version": 13,
            "revision_id": 10,
            "artifact_sha256": "artifact-d",
        },
    )
    assert status == "superseded"
    assert "queued settings version 12" in detail


def test_sync_from_db_marks_unsupported_operation_failed(monkeypatch) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    monkeypatch.setattr(runtime_module, "get_proxy_id", lambda: "edge-a")
    op = SimpleNamespace(
        operation_id=5,
        operation_type="rebuild_container",
        target_kind="",
        target_ref="",
    )
    calls: list[tuple[int, str, str]] = []

    class Ledger:
        def requeue_stale_applying(self, _proxy_id) -> None:
            return None

        def claim_pending(self, _proxy_id, *, limit, operation_id=None):
            assert limit == 100
            assert operation_id is None
            return [op]

        def mark_status(self, operation_id, *, status, detail) -> None:
            calls.append((operation_id, status, detail))

    monkeypatch.setattr(runtime_module, "get_operation_ledger", Ledger)
    runtime._invalidate_health_cache = lambda: None
    runtime.ensure_registered = lambda: None
    runtime.bootstrap_revision_if_missing = lambda: None
    runtime._current_config_sha = lambda: "current-sha"

    result = runtime.sync_from_db(force=False)

    assert result["ok"] is False
    assert result["executed_operation_types"] == []
    assert result["unsupported_operation_types"] == ["rebuild_container"]
    assert calls == [
        (
            5,
            "failed",
            (
                "Unsupported proxy operation type 'rebuild_container' was not executed.\n"
                "Unsupported proxy operation type(s) were not executed: rebuild_container"
            ),
        )
    ]


def test_sync_from_db_requires_operation_execution_evidence(monkeypatch) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    monkeypatch.setattr(runtime_module, "get_proxy_id", lambda: "edge-a")
    op = SimpleNamespace(operation_id=5, operation_type="cache_clear")
    calls: list[tuple[int, str, str]] = []

    class Ledger:
        def requeue_stale_applying(self, _proxy_id) -> None:
            return None

        def claim_pending(self, _proxy_id, *, limit, operation_id=None):
            assert limit == 100
            assert operation_id is None
            return [op]

        def mark_status(self, operation_id, *, status, detail) -> None:
            calls.append((operation_id, status, detail))

    monkeypatch.setattr(runtime_module, "get_operation_ledger", Ledger)
    runtime._sync_from_db_unlocked = (
        lambda *, force=False, artifact_force=None, operations=None: {
            "ok": True,
            "detail": "runtime reconciled",
            "executed_operation_types": [],
            "cache_cleared": False,
        }
    )

    result = runtime.sync_from_db(force=False)

    assert result["ok"] is True
    assert calls == [
        (
            5,
            "failed",
            (
                "Proxy operation 'cache_clear' completed reconciliation but did not report "
                "execution evidence for the requested operation.\nruntime reconciled"
            ),
        )
    ]


def test_sync_from_db_reports_cache_clear_as_runtime_change(monkeypatch) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    cleared: list[bool] = []

    monkeypatch.setattr(runtime_module, "get_proxy_id", lambda: "edge-a")
    runtime.ensure_registered = lambda: None
    runtime.bootstrap_revision_if_missing = lambda: None
    runtime._invalidate_health_cache = lambda: None
    runtime.sync_certificate_bundle = lambda force=False: {"ok": True, "changed": False}
    runtime.sync_policy_state = lambda force=False: {
        "ok": True,
        "changed": False,
        "reload_required": False,
    }
    runtime.sync_adblock_state = lambda force=False: {
        "ok": True,
        "changed": False,
        "artifact_sha256": "artifact-sha",
    }
    runtime.sync_pac_state = lambda force=False: {"ok": True, "changed": False}
    runtime._ensure_policy_runtime_config = lambda: (True, "", False)
    runtime._current_config_sha = lambda: "current-sha"
    runtime._current_adblock_artifact_sha = lambda: "artifact-sha"
    runtime.controller = SimpleNamespace(
        clear_disk_cache=lambda: (
            cleared.append(True) or (True, "Proxy disk cache cleared.")
        ),
    )
    runtime._restart_adblock_service = lambda: (_ for _ in ()).throw(
        AssertionError("cache clear sync should not restart cicap_adblock")
    )

    class Revisions:
        def get_active_revision_metadata(self, _proxy_id):
            return SimpleNamespace(revision_id=9, config_sha256="current-sha")

        def latest_apply(self, _proxy_id):
            return None

    runtime.revisions = Revisions()

    result = runtime._sync_from_db_unlocked(
        operations=[SimpleNamespace(operation_type="cache_clear")],
    )

    assert result["ok"] is True
    assert result["changed"] is True
    assert result["cache_cleared"] is True
    assert cleared == [True]
    assert "Proxy disk cache cleared." in result["detail"]
    assert "cicap_adblock" not in result["detail"]


def test_sync_certificate_bundle_rolls_back_material_after_restart_failure(
    tmp_path,
) -> None:
    _add_repo_paths()
    from services.certificate_core import CertificateBundle  # type: ignore

    runtime = _runtime_shell()
    cert_dir = tmp_path / "certs"
    cert_dir.mkdir()
    (cert_dir / "ca.crt").write_text("OLD CERT\n", encoding="utf-8")
    (cert_dir / "ca.key").write_text("OLD KEY\n", encoding="utf-8")
    (cert_dir / "uploaded_ca.pfx").write_bytes(b"old-pfx")
    runtime.cert_manager = SimpleNamespace(ca_dir=str(cert_dir))
    runtime.services = SimpleNamespace(current_certificate_sha_reader=lambda: "oldsha")
    restart_results = [
        (False, "spawn error while starting squid"),
        (True, "old squid ready"),
    ]
    runtime._reinitialize_ssl_db_and_restart = lambda: restart_results.pop(0)

    class Revision:
        revision_id = 7
        bundle_sha256 = "newsha"
        original_pfx_blob = b"new-pfx"

        def to_bundle(self):
            return CertificateBundle(
                cert_pem="NEW CERT\n",
                key_pem="NEW KEY\n",
                bundle_sha256="newsha",
                cert_sha256="newcertsha",
                original_pfx_bytes=b"new-pfx",
            )

    records: list[tuple[bool, str, str]] = []

    class Bundles:
        def get_active_bundle_metadata(self):
            return SimpleNamespace(revision_id=7, bundle_sha256="newsha")

        def latest_apply(self, *_args, **_kwargs):
            return None

        def get_active_bundle(self):
            return Revision()

        def record_apply_result(self, _proxy_id, revision_id, **kwargs):
            records.append(
                (
                    bool(kwargs["ok"]),
                    str(kwargs["detail"]),
                    str(kwargs["bundle_sha256"]),
                )
            )
            return SimpleNamespace(application_id=11, revision_id=revision_id)

    runtime.certificate_bundles = Bundles()

    result = runtime.sync_certificate_bundle()

    assert result["ok"] is False
    assert result["changed"] is False
    assert (cert_dir / "ca.crt").read_text(encoding="utf-8") == "OLD CERT\n"
    assert (cert_dir / "ca.key").read_text(encoding="utf-8") == "OLD KEY\n"
    assert (cert_dir / "uploaded_ca.pfx").read_bytes() == b"old-pfx"
    assert not (cert_dir / ".ca-material.json").exists()
    assert records
    assert records[-1][0] is False
    assert records[-1][2] == "oldsha"
    assert result["certificate_bundle_sha256"] == "oldsha"
    assert result["current_certificate_sha"] == "oldsha"
    assert result["desired_certificate_bundle_sha256"] == "newsha"
    assert "spawn error" in result["detail"]
    assert "Restored previous certificate material" in result["detail"]
    assert "restarted successfully after rollback" in result["detail"]
    assert (
        "Current certificate bundle after failed apply/rollback: oldsha"
        in result["detail"]
    )
    assert "Desired failed revision bundle: newsha" in result["detail"]


def test_sync_certificate_bundle_rolls_back_after_materialization_exception(
    monkeypatch,
) -> None:
    _add_repo_paths()
    from services.certificate_core import CertificateBundle  # type: ignore

    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    current_sha = {"value": "oldsha"}
    runtime.services = SimpleNamespace(
        current_certificate_sha_reader=lambda: current_sha["value"]
    )
    runtime.cert_manager = SimpleNamespace(ca_dir="/unused")
    runtime._snapshot_certificate_material = lambda: {"ca.crt": b"old cert"}

    def restore_snapshot(snapshot):
        assert snapshot == {"ca.crt": b"old cert"}
        current_sha["value"] = "oldsha"
        return True, "Restored previous certificate material after failed apply."

    runtime._restore_certificate_material = restore_snapshot
    runtime._reinitialize_ssl_db_and_restart = lambda: (_ for _ in ()).throw(
        AssertionError("materialization failures must not restart squid")
    )

    def fail_materialize(_ca_dir, bundle, **_kwargs) -> None:
        current_sha["value"] = bundle.bundle_sha256
        msg = "simulated replace failure after ca.crt"
        raise ValueError(msg)

    monkeypatch.setattr(
        runtime_module,
        "materialize_certificate_bundle",
        fail_materialize,
    )

    class Revision:
        revision_id = 7
        bundle_sha256 = "newsha"
        original_pfx_blob = None

        def to_bundle(self):
            return CertificateBundle(
                cert_pem="NEW CERT\n",
                key_pem="NEW KEY\n",
                bundle_sha256="newsha",
                cert_sha256="newcertsha",
            )

    records: list[tuple[bool, str, str]] = []

    class Bundles:
        def get_active_bundle_metadata(self):
            return SimpleNamespace(revision_id=7, bundle_sha256="newsha")

        def latest_apply(self, *_args, **_kwargs):
            return None

        def get_active_bundle(self):
            return Revision()

        def record_apply_result(self, _proxy_id, revision_id, **kwargs):
            records.append(
                (
                    bool(kwargs["ok"]),
                    str(kwargs["bundle_sha256"]),
                    str(kwargs["detail"]),
                )
            )
            return SimpleNamespace(application_id=12, revision_id=revision_id)

    runtime.certificate_bundles = Bundles()

    result = runtime.sync_certificate_bundle(force=False)

    assert result["ok"] is False
    assert result["changed"] is False
    assert records
    assert records[-1][0] is False
    assert records[-1][1] == "oldsha"
    assert result["certificate_bundle_sha256"] == "oldsha"
    assert result["current_certificate_sha"] == "oldsha"
    assert result["desired_certificate_bundle_sha256"] == "newsha"
    assert "simulated replace failure" in result["detail"]
    assert "Restored previous certificate material" in result["detail"]
    assert (
        "Current certificate bundle after failed materialization/rollback: oldsha"
        in result["detail"]
    )
    assert "Desired failed revision bundle: newsha" in result["detail"]


def test_sync_certificate_bundle_retries_materialization_after_successful_rollback(
    monkeypatch,
) -> None:
    _add_repo_paths()
    from services.certificate_core import CertificateBundle  # type: ignore

    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    current_sha = {"value": "oldsha"}
    runtime.services = SimpleNamespace(
        current_certificate_sha_reader=lambda: current_sha["value"]
    )
    runtime.cert_manager = SimpleNamespace(ca_dir="/unused")
    runtime._snapshot_certificate_material = lambda: {"ca.crt": b"old cert"}
    runtime._restore_certificate_material = lambda _snapshot: (
        current_sha.update(value="oldsha")
        or (True, "Restored previous certificate material after failed apply.")
    )
    restart_calls: list[bool] = []
    runtime._reinitialize_ssl_db_and_restart = lambda: (
        restart_calls.append(True) or (True, "new squid ready")
    )
    materialize_attempts = {"count": 0}

    def flaky_materialize(_ca_dir, bundle, **_kwargs) -> None:
        materialize_attempts["count"] += 1
        current_sha["value"] = bundle.bundle_sha256
        if materialize_attempts["count"] == 1:
            msg = "simulated partial materialization failure"
            raise ValueError(msg)

    monkeypatch.setattr(
        runtime_module,
        "materialize_certificate_bundle",
        flaky_materialize,
    )

    class Revision:
        revision_id = 7
        bundle_sha256 = "newsha"
        original_pfx_blob = None

        def to_bundle(self):
            return CertificateBundle(
                cert_pem="NEW CERT\n",
                key_pem="NEW KEY\n",
                bundle_sha256="newsha",
                cert_sha256="newcertsha",
            )

    records: list[tuple[bool, str]] = []

    class Bundles:
        def get_active_bundle_metadata(self):
            return SimpleNamespace(revision_id=7, bundle_sha256="newsha")

        def latest_apply(self, *_args, **_kwargs):
            if not records:
                return None
            ok, bundle_sha256 = records[-1]
            return SimpleNamespace(
                revision_id=7,
                ok=ok,
                detail="previous apply attempt",
                bundle_sha256=bundle_sha256,
            )

        def get_active_bundle(self):
            return Revision()

        def record_apply_result(self, _proxy_id, revision_id, **kwargs):
            records.append((bool(kwargs["ok"]), str(kwargs["bundle_sha256"])))
            return SimpleNamespace(
                application_id=12 + len(records),
                revision_id=revision_id,
            )

    runtime.certificate_bundles = Bundles()

    first = runtime.sync_certificate_bundle(force=False)
    second = runtime.sync_certificate_bundle(force=False)

    assert first["ok"] is False
    assert first["certificate_bundle_sha256"] == "oldsha"
    assert first["desired_certificate_bundle_sha256"] == "newsha"
    assert second["ok"] is True
    assert second["certificate_bundle_sha256"] == "newsha"
    assert materialize_attempts["count"] == 2
    assert restart_calls == [True]
    assert records == [(False, "oldsha"), (True, "newsha")]


def test_sync_certificate_bundle_failed_restart_and_failed_rollback_reports_unknown_current(
    monkeypatch,
) -> None:
    _add_repo_paths()
    from services.certificate_core import CertificateBundle  # type: ignore

    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    current_sha = {"value": "oldsha"}
    runtime.services = SimpleNamespace(
        current_certificate_sha_reader=lambda: current_sha["value"]
    )
    runtime.cert_manager = SimpleNamespace(ca_dir="/unused")
    runtime._snapshot_certificate_material = lambda: {"ca.crt": b"old cert"}
    runtime._restore_certificate_material = lambda _snapshot: (
        current_sha.update(value="")
        or (False, "failed to restore previous certificate material")
    )
    restart_calls: list[bool] = []
    runtime._reinitialize_ssl_db_and_restart = lambda: (
        restart_calls.append(True) or (False, "squid restart failed")
    )

    def fake_materialize(_ca_dir, bundle, **_kwargs) -> None:
        current_sha["value"] = bundle.bundle_sha256

    monkeypatch.setattr(
        runtime_module,
        "materialize_certificate_bundle",
        fake_materialize,
    )

    class Revision:
        revision_id = 7
        bundle_sha256 = "newsha"
        original_pfx_blob = None

        def to_bundle(self):
            return CertificateBundle(
                cert_pem="NEW CERT\n",
                key_pem="NEW KEY\n",
                bundle_sha256="newsha",
                cert_sha256="newcertsha",
            )

    records: list[tuple[bool, str, str]] = []

    class Bundles:
        def get_active_bundle_metadata(self):
            return SimpleNamespace(revision_id=7, bundle_sha256="newsha")

        def latest_apply(self, *_args, **_kwargs):
            return None

        def get_active_bundle(self):
            return Revision()

        def record_apply_result(self, _proxy_id, revision_id, **kwargs):
            records.append(
                (
                    bool(kwargs["ok"]),
                    str(kwargs["bundle_sha256"]),
                    str(kwargs["detail"]),
                )
            )
            return SimpleNamespace(application_id=12, revision_id=revision_id)

    runtime.certificate_bundles = Bundles()

    result = runtime.sync_certificate_bundle(force=False)

    assert result["ok"] is False
    assert result["changed"] is False
    assert restart_calls == [True]
    assert records
    assert records[-1][0] is False
    assert records[-1][1] == ""
    assert result["certificate_bundle_sha256"] == ""
    assert result["current_certificate_sha"] == ""
    assert result["previous_certificate_bundle_sha256"] == "oldsha"
    assert result["desired_certificate_bundle_sha256"] == "newsha"
    assert "squid restart failed" in result["detail"]
    assert "failed to restore previous certificate material" in result["detail"]
    assert "could not be verified" in result["detail"]
    assert "Last-known certificate bundle before failed apply: oldsha" in result["detail"]


def test_sync_certificate_bundle_retry_after_unknown_rollback_rematerializes(
    monkeypatch,
) -> None:
    _add_repo_paths()
    from services.certificate_core import CertificateBundle  # type: ignore

    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    current_sha = {"value": ""}
    runtime.services = SimpleNamespace(
        current_certificate_sha_reader=lambda: current_sha["value"]
    )
    runtime.cert_manager = SimpleNamespace(ca_dir="/unused")
    runtime._snapshot_certificate_material = lambda: {"ca.crt": b"unknown current"}
    runtime._restore_certificate_material = lambda _snapshot: (
        False,
        "failed to restore previous certificate material",
    )
    restart_calls: list[bool] = []
    runtime._reinitialize_ssl_db_and_restart = lambda: (
        restart_calls.append(True) or (True, "new squid ready")
    )

    materialized: list[str] = []

    def fake_materialize(_ca_dir, bundle, **_kwargs) -> None:
        materialized.append(bundle.bundle_sha256)
        current_sha["value"] = bundle.bundle_sha256

    monkeypatch.setattr(
        runtime_module,
        "materialize_certificate_bundle",
        fake_materialize,
    )

    class Revision:
        revision_id = 7
        bundle_sha256 = "newsha"
        original_pfx_blob = None

        def to_bundle(self):
            return CertificateBundle(
                cert_pem="NEW CERT\n",
                key_pem="NEW KEY\n",
                bundle_sha256="newsha",
                cert_sha256="newcertsha",
            )

    records: list[tuple[bool, str]] = []

    class Bundles:
        def get_active_bundle_metadata(self):
            return SimpleNamespace(revision_id=7, bundle_sha256="newsha")

        def latest_apply(self, *_args, **_kwargs):
            return SimpleNamespace(
                revision_id=7,
                ok=False,
                detail="previous rollback failed; current certificate unknown",
                bundle_sha256="",
            )

        def get_active_bundle(self):
            return Revision()

        def record_apply_result(self, _proxy_id, revision_id, **kwargs):
            records.append((bool(kwargs["ok"]), str(kwargs["bundle_sha256"])))
            return SimpleNamespace(application_id=13, revision_id=revision_id)

    runtime.certificate_bundles = Bundles()

    result = runtime.sync_certificate_bundle(force=False)

    assert result["ok"] is True
    assert materialized == ["newsha"]
    assert restart_calls == [True]
    assert records == [(True, "newsha")]
    assert result["certificate_bundle_sha256"] == "newsha"


def test_sync_certificate_bundle_retries_failed_rollback_against_desired_revision(
    monkeypatch,
) -> None:
    _add_repo_paths()
    from services.certificate_core import CertificateBundle  # type: ignore

    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    current_sha = {"value": "oldsha"}
    runtime.services = SimpleNamespace(
        current_certificate_sha_reader=lambda: current_sha["value"]
    )
    runtime.cert_manager = SimpleNamespace(ca_dir="/unused")
    runtime._snapshot_certificate_material = dict
    restart_calls: list[bool] = []
    runtime._reinitialize_ssl_db_and_restart = lambda: (
        restart_calls.append(True) or (True, "new squid ready")
    )

    materialized: list[str] = []

    def fake_materialize(_ca_dir, bundle, **_kwargs) -> None:
        materialized.append(bundle.bundle_sha256)
        current_sha["value"] = bundle.bundle_sha256

    monkeypatch.setattr(
        runtime_module,
        "materialize_certificate_bundle",
        fake_materialize,
    )

    class Revision:
        revision_id = 7
        bundle_sha256 = "newsha"
        original_pfx_blob = None

        def to_bundle(self):
            return CertificateBundle(
                cert_pem="NEW CERT\n",
                key_pem="NEW KEY\n",
                bundle_sha256="newsha",
                cert_sha256="newcertsha",
            )

    records: list[tuple[bool, str]] = []

    class Bundles:
        def get_active_bundle_metadata(self):
            return SimpleNamespace(revision_id=7, bundle_sha256="newsha")

        def latest_apply(self, *_args, **_kwargs):
            return SimpleNamespace(
                revision_id=7,
                ok=False,
                detail="failed apply restored oldsha",
                bundle_sha256="oldsha",
            )

        def get_active_bundle(self):
            return Revision()

        def record_apply_result(self, _proxy_id, revision_id, **kwargs):
            records.append((bool(kwargs["ok"]), str(kwargs["bundle_sha256"])))
            return SimpleNamespace(application_id=13, revision_id=revision_id)

    runtime.certificate_bundles = Bundles()

    result = runtime.sync_certificate_bundle(force=False)

    assert result["ok"] is True
    assert materialized == ["newsha"]
    assert restart_calls == [True]
    assert records == [(True, "newsha")]
    assert result["certificate_bundle_sha256"] == "newsha"


def test_sync_certificate_bundle_retries_restart_after_failed_apply_without_rematerializing(
    monkeypatch,
) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    runtime.services = SimpleNamespace(current_certificate_sha_reader=lambda: "newsha")
    runtime.cert_manager = SimpleNamespace(ca_dir="/unused")
    restart_calls: list[bool] = []
    runtime._reinitialize_ssl_db_and_restart = lambda: (
        restart_calls.append(True) or (True, "Squid HTTP listener is responding.")
    )
    monkeypatch.setattr(
        runtime_module,
        "materialize_certificate_bundle",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError(
                "matching failed applies should retry restart, not rewrite certificate files"
            )
        ),
    )

    records: list[tuple[bool, str]] = []

    class Bundles:
        def get_active_bundle_metadata(self):
            return SimpleNamespace(revision_id=7, bundle_sha256="newsha")

        def latest_apply(self, *_args, **_kwargs):
            return SimpleNamespace(
                revision_id=7, ok=False, detail="last restart failed"
            )

        def record_apply_result(self, _proxy_id, revision_id, **kwargs):
            records.append((bool(kwargs["ok"]), str(kwargs["detail"])))
            return SimpleNamespace(application_id=12, revision_id=revision_id)

    runtime.certificate_bundles = Bundles()

    result = runtime.sync_certificate_bundle(force=False)

    assert result["ok"] is True
    assert restart_calls == [True]
    assert records[-1][0] is True
    assert "previous apply failed" in records[-1][1]
    assert "Squid HTTP listener is responding" in result["detail"]


def test_current_config_sha_uses_normalized_config_text() -> None:
    runtime = _runtime_shell()
    runtime.services = SimpleNamespace(current_config_sha_reader=None)
    runtime.controller = SimpleNamespace(
        get_current_config=lambda: "http_port 3128\r\n\r\n",
        normalize_config_text=lambda text: (
            (text or "").strip().replace("\r\n", "\n") + "\n"
        ),
    )

    expected = hashlib.sha256(b"http_port 3128\n").hexdigest()

    assert runtime._current_config_sha() == expected


def test_sync_from_db_skips_apply_when_config_only_differs_by_normalization() -> None:
    runtime = _runtime_shell()
    runtime.services = SimpleNamespace(current_config_sha_reader=None)
    applied: list[object] = []

    runtime.ensure_registered = lambda: None
    runtime.bootstrap_revision_if_missing = lambda: None
    runtime._invalidate_health_cache = lambda: None
    runtime.sync_certificate_bundle = lambda force=False: {"ok": True, "changed": False}
    runtime.sync_policy_state = lambda force=False: {
        "ok": True,
        "changed": False,
        "reload_required": False,
    }
    runtime.sync_adblock_state = lambda force=False: {"ok": True, "changed": False}
    runtime.sync_pac_state = lambda force=False: {"ok": True, "changed": False}
    runtime._ensure_policy_runtime_config = lambda: (True, "", False)
    runtime.controller = SimpleNamespace(
        get_current_config=lambda: "http_port 3128\r\n\r\n",
        normalize_config_text=lambda text: (
            (text or "").strip().replace("\r\n", "\n") + "\n"
        ),
        apply_config_text=lambda *args, **kwargs: applied.append((args, kwargs)),
    )
    revision = SimpleNamespace(
        revision_id=9,
        config_text="http_port 3128\r\n\r\n",
        config_sha256="raw-db-sha",
        created_by="admin",
        created_ts=123,
    )
    runtime.revisions = SimpleNamespace(
        get_active_revision_metadata=lambda _proxy_id: SimpleNamespace(
            revision_id=9,
            config_sha256="raw-db-sha",
        ),
        get_active_revision=lambda _proxy_id: revision,
        latest_apply=lambda _proxy_id: revision,
    )

    result = runtime._sync_from_db_unlocked(force=False)

    assert result["ok"] is True
    assert result["changed"] is False
    assert result["revision_id"] == 9
    assert applied == []
    assert result["detail"] == "Proxy is already using the active config revision."


def test_forced_non_config_operation_refreshes_artifacts_only() -> None:
    runtime = _runtime_shell()
    revision_text = "http_port 3128\n"
    revision_sha = hashlib.sha256(revision_text.encode("utf-8")).hexdigest()
    applied: list[object] = []
    force_calls: list[tuple[str, bool]] = []

    def _artifact_result(name: str):
        def _sync(*, force: bool = False):
            force_calls.append((name, bool(force)))
            return {"ok": True, "changed": False}

        return _sync

    runtime.services = SimpleNamespace(current_config_sha_reader=None)
    runtime.ensure_registered = lambda: None
    runtime.bootstrap_revision_if_missing = lambda: None
    runtime._invalidate_health_cache = lambda: None
    runtime.sync_certificate_bundle = _artifact_result("cert")
    runtime.sync_policy_state = lambda *, force=False: (
        force_calls.append(("policy", bool(force)))
        or {"ok": True, "changed": False, "reload_required": False}
    )
    runtime.sync_adblock_state = _artifact_result("adblock")
    runtime.sync_pac_state = _artifact_result("pac")
    runtime._ensure_policy_runtime_config = lambda: (True, "", False)
    runtime._current_adblock_artifact_sha = lambda: ""
    runtime.registry = SimpleNamespace(mark_apply_result=lambda *args, **kwargs: None)
    runtime.controller = SimpleNamespace(
        get_current_config=lambda: revision_text,
        normalize_config_text=lambda text: (text or "").strip() + "\n",
        set_adblock_icap_revision_token=lambda _token: None,
        materialize_clamav_runtime_files=lambda _text, **_kwargs: (True, "unchanged"),
        apply_config_text=lambda *args, **kwargs: applied.append((args, kwargs)),
    )
    runtime.revisions = SimpleNamespace(
        get_active_revision_metadata=lambda _proxy_id: SimpleNamespace(
            revision_id=10,
            config_sha256=revision_sha,
        ),
        get_active_revision=lambda _proxy_id: SimpleNamespace(
            revision_id=10,
            config_text=revision_text,
            config_sha256=revision_sha,
        ),
        latest_apply=lambda _proxy_id: None,
    )
    operation = SimpleNamespace(
        force=True,
        operation_type="pac_refresh",
        target_kind="pac_profile",
    )

    result = runtime._sync_from_db_unlocked(
        force=False,
        artifact_force=True,
        operations=[operation],
    )

    assert result["ok"] is True
    assert result["changed"] is False
    assert applied == []
    assert force_calls == [
        ("cert", True),
        ("policy", True),
        ("adblock", True),
        ("pac", True),
    ]


def test_operation_config_force_is_limited_to_config_affecting_requests() -> None:
    from proxy import runtime as runtime_module

    assert runtime_module._operations_request_config_force(
        [SimpleNamespace(force=True, operation_type="manual_sync", target_kind="")]
    )
    assert runtime_module._operations_request_config_force(
        [SimpleNamespace(force=True, operation_type="config_apply", target_kind="")]
    )
    pac_operation = SimpleNamespace(
        force=True,
        operation_type="pac_refresh",
        target_kind="pac_profile",
    )
    assert not runtime_module._operations_request_config_force([pac_operation])
    assert runtime_module._operations_request_force([pac_operation])
