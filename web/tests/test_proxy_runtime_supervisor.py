from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace


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
    return SimpleNamespace(returncode=returncode, stdout=stdout.encode("utf-8"), stderr=stderr.encode("utf-8"))


def test_restart_supervisor_program_accepts_already_started_output(monkeypatch) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    calls: list[list[str]] = []
    results = [
        _cp(0, stdout="cicap_adblock: stopped"),
        _cp(1, stderr="cicap_adblock: ERROR (already started)"),
    ]

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        return results.pop(0)

    monkeypatch.setattr(runtime_module.subprocess, "run", fake_run)

    ok, detail = _runtime_shell()._restart_supervisor_program("cicap_adblock")

    assert ok is True
    assert calls == [
        ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "cicap_adblock"],
        ["supervisorctl", "-c", "/etc/supervisord.conf", "start", "cicap_adblock"],
    ]
    assert "already started" in detail


def test_restart_supervisor_program_trusts_running_status_after_failed_start(monkeypatch) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore

    monkeypatch.setattr(runtime_module.time, "sleep", lambda _seconds: None)
    results = [
        _cp(0, stdout="cicap_adblock: stopped"),
        _cp(1, stderr="cicap_adblock: ERROR (abnormal termination)"),
        _cp(0, stdout="cicap_adblock RUNNING pid 123, uptime 0:00:01"),
    ]

    monkeypatch.setattr(runtime_module.subprocess, "run", lambda *_args, **_kwargs: results.pop(0))

    ok, detail = _runtime_shell()._restart_supervisor_program("cicap_adblock")

    assert ok is True
    assert "abnormal termination" in detail
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
    assert calls["count"] == 11  # stop + five start/status attempts
    assert "abnormal termination" in detail


def test_restart_adblock_service_uses_injected_restarter() -> None:
    runtime = _runtime_shell()
    runtime.services = SimpleNamespace(adblock_service_restarter=lambda: (True, "custom restarter"))

    assert runtime._restart_adblock_service() == (True, "custom restarter")
