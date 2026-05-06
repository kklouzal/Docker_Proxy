from __future__ import annotations

import subprocess
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
        ["supervisorctl", "-c", "/etc/supervisord.conf", "start", "cicap_adblock"],
        ["supervisorctl", "-c", "/etc/supervisord.conf", "status", "cicap_adblock"],
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
    assert calls[-1] == ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "cicap_adblock"]


def test_sync_certificate_bundle_skips_current_bundle_even_when_forced() -> None:
    runtime = _runtime_shell()

    class Bundles:
        def get_active_bundle_metadata(self):
            return SimpleNamespace(revision_id=7, bundle_sha256="same-sha")

        def latest_apply(self, proxy_id):
            return SimpleNamespace(proxy_id=proxy_id, revision_id=7)

        def get_active_bundle(self):
            raise AssertionError("current certificate bundle should not be loaded")

        def record_apply_result(self, *_args, **_kwargs):
            raise AssertionError("current certificate bundle should not be recorded as re-applied")

    runtime.services = SimpleNamespace(current_certificate_sha_reader=lambda: "same-sha")
    runtime.certificate_bundles = Bundles()

    result = runtime.sync_certificate_bundle(force=True)

    assert result["ok"] is True
    assert result["changed"] is False
    assert result["revision_id"] == 7
    assert result["detail"] == "Proxy is already using the active certificate bundle."


def test_sync_certificate_bundle_records_noop_apply_for_current_bundle_without_apply_record() -> None:
    runtime = _runtime_shell()
    recorded: list[tuple[object, int, bool, str]] = []

    class Bundles:
        def get_active_bundle_metadata(self):
            return SimpleNamespace(revision_id=8, bundle_sha256="same-sha")

        def latest_apply(self, _proxy_id):
            return None

        def record_apply_result(self, proxy_id, revision_id, *, ok, detail, applied_by, bundle_sha256):
            recorded.append((proxy_id, revision_id, ok, bundle_sha256))
            assert detail == "Proxy is already using the active certificate bundle."
            assert applied_by == "proxy"
            return SimpleNamespace(application_id=123)

        def get_active_bundle(self):
            raise AssertionError("current certificate bundle should not be loaded")

    runtime.services = SimpleNamespace(current_certificate_sha_reader=lambda: "same-sha")
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

        def _wait_for_http_listener(self, *, timeout):
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
    runtime._supervisor_program_status = lambda program, timeout_seconds=5: (False, "cicap_adblock BACKOFF")
    runtime._restart_adblock_service = lambda: (True, "cicap_adblock restarted")
    monkeypatch.setattr(runtime_module, "_check_icap_adblock", lambda **_kwargs: {"ok": False, "detail": "not listening"})

    result = runtime.self_heal_runtime_services_if_needed(reason="test")

    assert result["ok"] is True
    assert result["changed"] is True
    assert "BACKOFF" in result["detail"]
    assert "not listening" in result["detail"]


def test_sync_from_db_quarantines_previously_failed_active_revision_without_retry() -> None:
    runtime = _runtime_shell()
    marked: list[tuple[bool, str, str]] = []

    class Revisions:
        def get_active_revision_metadata(self, _proxy_id):
            return SimpleNamespace(revision_id=9, config_sha256="desired-sha")

        def latest_apply(self, _proxy_id):
            return SimpleNamespace(revision_id=9, ok=False)

        def get_active_revision(self, _proxy_id):
            raise AssertionError("failed active revision should not be retried without force")

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
    runtime.sync_policy_state = lambda force=False: {"ok": True, "changed": False, "reload_required": False}
    runtime.sync_adblock_state = lambda force=False: {"ok": True, "changed": False}
    runtime.sync_pac_state = lambda force=False: {"ok": True, "changed": False}
    runtime._current_config_sha = lambda: "last-good-sha"

    result = runtime.sync_from_db(force=False)

    assert result["ok"] is False
    assert result["rollback_active"] is True
    assert result["config_changed"] is False
    assert "previously failed" in result["detail"]
    assert marked == [(False, result["detail"], "last-good-sha")]


def test_squid_controller_rolls_back_to_persisted_config_after_reconfigure_timeout(tmp_path, monkeypatch) -> None:
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

    controller = SquidController(str(squid_conf), cmd_run=fake_run)
    controller.persisted_squid_conf_path = str(persisted_conf)
    monkeypatch.setattr(controller, "_wait_for_http_listener_absent", lambda *, timeout: True)
    monkeypatch.setattr(controller, "_wait_for_http_listener", lambda *, timeout: True)

    ok, detail = controller.apply_config_text("workers 1\n# bad-but-parseable\n")

    assert ok is False
    assert "timed out" in detail.lower()
    assert "Rolled back to last-known-good" in detail
    restored = squid_conf.read_text(encoding="utf-8")
    assert "# good" in restored
    assert "bad-but-parseable" not in restored


def test_squid_controller_validation_timeout_returns_actionable_detail(tmp_path) -> None:
    _add_repo_paths()
    from services.squid_core import SquidController  # type: ignore

    def fake_run(args, **_kwargs):
        raise subprocess.TimeoutExpired(args, timeout=15)

    controller = SquidController(str(tmp_path / "squid.conf"), cmd_run=fake_run)

    ok, detail = controller.validate_config_text("workers 1\n")

    assert ok is False
    assert detail == "Squid config validation timed out after 15 seconds."


def test_squid_controller_removes_stale_pidfile_before_restart(monkeypatch, tmp_path) -> None:
    _add_repo_paths()
    import services.squid_core as squid_core  # type: ignore
    from services.squid_core import SquidController  # type: ignore

    calls: list[list[str]] = []
    unlinked: list[str] = []

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        return _cp(0, stdout="ok")

    controller = SquidController(str(tmp_path / "squid.conf"), cmd_run=fake_run)
    monkeypatch.setattr(controller, "_wait_for_http_listener_absent", lambda *, timeout: True)
    monkeypatch.setattr(controller, "_wait_for_http_listener", lambda *, timeout: True)
    monkeypatch.setattr(squid_core.os.path, "exists", lambda path: path == "/var/run/squid.pid")
    monkeypatch.setattr(squid_core.Path, "read_text", lambda self, **_kwargs: "12345")
    monkeypatch.setattr(squid_core.os, "unlink", lambda path: unlinked.append(path))

    ok, detail = controller.restart_squid()

    assert ok is True
    assert unlinked == ["/var/run/squid.pid"]
    assert "Removed stale Squid PID file" in detail
    assert calls[-1][:4] == ["supervisorctl", "-c", "/etc/supervisord.conf", "start"]


def test_sync_adblock_state_rolls_back_compiled_artifact_when_cicap_restart_fails(tmp_path, monkeypatch) -> None:
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
            return SimpleNamespace(revision_id=42, artifact_sha256="new-sha", archive_blob=b"new")

        def record_apply_result(self, proxy_id, revision_id, *, ok, detail, applied_by, artifact_sha256):
            recorded.append(
                {
                    "proxy_id": proxy_id,
                    "revision_id": revision_id,
                    "ok": ok,
                    "detail": detail,
                    "artifact_sha256": artifact_sha256,
                }
            )
            return SimpleNamespace(application_id=77)

    class Store:
        def init_db(self):
            pass

        def get_cache_flush_requested(self):
            return False

    def fake_materialize(directory, *, archive_blob, artifact_sha256):
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

    monkeypatch.setattr(runtime_module, "materialize_archive_to_directory", fake_materialize)

    result = runtime.sync_adblock_state(force=True)

    assert result["ok"] is False
    assert result["artifact_rolled_back"] is True
    assert "Restored previous adblock compiled artifact" in result["detail"]
    assert (compiled / ".artifact-sha256").read_text(encoding="utf-8") == "old-sha"
    assert (compiled / "domains_block.txt").read_text(encoding="utf-8") == "old.example\n"
    assert recorded[-1]["ok"] is False
