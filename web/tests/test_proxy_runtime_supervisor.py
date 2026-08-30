from __future__ import annotations

import builtins
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

from .subprocess_test_utils import run_test_process


@pytest.fixture(autouse=True)
def _isolated_squid_transaction_journal(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv(
        "SQUID_TRANSACTION_JOURNAL_PATH",
        str(tmp_path / "squid-transaction.json"),
    )


POLICY_SHA_A = "a" * 64
POLICY_SHA_B = "b" * 64
POLICY_SHA_OLD = "c" * 64
PAC_SHA_A = "d" * 64
PAC_SHA_B = "e" * 64
PAC_SHA_OLD = "f" * 64


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
    result = run_test_process(
        [sys.executable, "-c", _healthcheck_forwarding_canary_url_script()],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, **env_overrides},
    )
    return result.stdout.strip()


def _healthcheck_forwarding_canary_port_script() -> str:
    repo_root = Path(__file__).resolve().parents[2]
    healthcheck = (repo_root / "docker" / "healthcheck.sh").read_text(
        encoding="utf-8",
    )
    match = re.search(
        r"^forwarding_canary_port\(\) \{\n(?P<body>.*?)^\}\n\ncheck_squid_forwarding_path\(\)",
        healthcheck,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert match is not None
    return match.group("body")


def _healthcheck_forwarding_canary_port(**env_overrides: str) -> str:
    result = run_test_process(
        ["sh", "-c", _healthcheck_forwarding_canary_port_script()],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, **env_overrides},
    )
    return result.stdout.strip()


def _entrypoint_forwarding_canary_path_script() -> str:
    repo_root = Path(__file__).resolve().parents[2]
    entrypoint = (repo_root / "docker" / "entrypoint.sh").read_text(
        encoding="utf-8",
    )
    match = re.search(
        r"^sanitize_forwarding_canary_path\(\) \{\n.*?^\}\n",
        entrypoint,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert match is not None
    return (
        match.group(0)
        + '\nFORWARDING_CANARY_PATH="$(sanitize_forwarding_canary_path '
        + '"${FORWARDING_CANARY_PATH:-/__docker_proxy_forwarding_canary}")"\n'
        + "printf '%s\\n' \"$FORWARDING_CANARY_PATH\"\n"
    )


def _entrypoint_forwarding_canary_path(**env_overrides: str) -> str:
    result = run_test_process(
        ["sh", "-c", _entrypoint_forwarding_canary_path_script()],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, **env_overrides},
    )
    return result.stdout.strip()


def _runtime_shell():
    from proxy.runtime import ProxyRuntime  # type: ignore

    runtime = ProxyRuntime.__new__(ProxyRuntime)
    runtime._operation_ledger_health = lambda: {
        "ok": True,
        "detail": "operation ledger reachable; pending=0 applying=0 failed=0",
        "counts": {},
    }
    runtime._squid_transaction_health = lambda: {
        "ok": True,
        "ready": True,
        "status": "complete",
        "detail": "Squid transaction journal is reconciled.",
    }
    return runtime


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("1", True),
        (" TRUE ", True),
        ("enabled", True),
        ("0", False),
        (" FALSE ", False),
        ("disabled", False),
        (True, True),
        (False, False),
        (1, True),
        (0, False),
        (2, True),
        (0.0, True),
        (None, True),
        ("", True),
        ("malformed", True),
    ],
)
def test_current_adblock_enabled_uses_fail_safe_shared_boolean_contract(
    value: object, expected: bool
) -> None:
    runtime = _runtime_shell()
    runtime.adblock_store = SimpleNamespace(get_settings=lambda: {"enabled": value})

    assert runtime._current_adblock_enabled() is expected


def test_current_adblock_enabled_defaults_enabled_when_setting_is_missing() -> None:
    runtime = _runtime_shell()
    runtime.adblock_store = SimpleNamespace(get_settings=dict)

    assert runtime._current_adblock_enabled() is True


def test_runtime_lock_open_failure_prevents_supervisor_and_sync_mutations(
    monkeypatch,
) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    monkeypatch.setattr(runtime_module, "get_proxy_id", lambda: "edge-a")
    supervisor_calls: list[str] = []
    sync_calls: list[str] = []
    runtime._restart_supervisor_program_unlocked = lambda *_args, **_kwargs: (
        supervisor_calls.append("restart") or (True, "")
    )
    runtime._sync_from_db_unlocked = lambda **_kwargs: (
        sync_calls.append("sync") or {"ok": True}
    )

    def fail_open(*_args, **_kwargs):
        error_detail = "secret lock path detail"
        raise OSError(error_detail)

    monkeypatch.setattr(runtime_module.pathlib.Path, "open", fail_open)

    restart_ok, restart_detail = runtime._restart_supervisor_program("squid")
    sync_result = runtime.sync_from_db()

    assert restart_ok is False
    assert restart_detail == "Required supervisor runtime lock is unavailable."
    assert sync_result["ok"] is False
    assert sync_result["changed"] is False
    assert sync_result["detail"] == "Required sync runtime lock is unavailable."
    assert "secret" not in restart_detail
    assert "secret" not in sync_result["detail"]
    assert supervisor_calls == []
    assert sync_calls == []


def test_runtime_lock_flock_failure_closes_open_handle(monkeypatch, tmp_path) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    real_import = builtins.__import__
    handle = SimpleNamespace(closed=False, fileno=lambda: 123)
    handle.close = lambda: setattr(handle, "closed", True)
    fake_fcntl = SimpleNamespace(
        LOCK_EX=1,
        LOCK_UN=2,
        flock=lambda *_args: (_ for _ in ()).throw(OSError("secret flock detail")),
    )

    def import_with_failed_flock(name, *args, **kwargs):
        if name == "fcntl":
            return fake_fcntl
        return real_import(name, *args, **kwargs)

    monkeypatch.setenv("PROXY_RUNTIME_LOCK_DIR", str(tmp_path))
    monkeypatch.setattr(runtime_module.pathlib.Path, "open", lambda *_a, **_k: handle)
    monkeypatch.setattr(builtins, "__import__", import_with_failed_flock)

    with pytest.raises(
        runtime_module._RuntimeLockError,
        match=r"^Required sync runtime lock is unavailable\.$",
    ):
        with runtime_module._exclusive_runtime_lock(
            "sync", runtime_module._SYNC_CONTROL_LOCK
        ):
            pytest.fail("protected body must not run")

    assert handle.closed is True


def test_manual_rollback_uses_sync_transaction_lock(monkeypatch, tmp_path) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    lock_events: list[str] = []

    @contextlib.contextmanager
    def fake_lock(name, thread_lock):
        assert name == "sync"
        assert thread_lock is runtime_module._SYNC_CONTROL_LOCK
        lock_events.append("enter")
        try:
            yield
        finally:
            lock_events.append("exit")

    monkeypatch.setattr(runtime_module, "_exclusive_runtime_lock", fake_lock)
    runtime._rollback_last_known_good_config_locked = lambda **_kwargs: (
        lock_events.append("rollback")
        or {"ok": True, "changed": True, "rolled_back": True}
    )

    result = runtime.rollback_last_known_good_config(reason="operator")

    assert result["ok"] is True
    assert lock_events == ["enter", "rollback", "exit"]


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


def test_sync_policy_state_reports_partial_state_after_rollback_failure(
    tmp_path, monkeypatch
) -> None:
    from services import materialized_files  # type: ignore

    first = tmp_path / "10-sslfilter.conf"
    second = tmp_path / "30-webfilter.conf"
    first.write_text("old ssl policy\n", encoding="utf-8")
    second.write_text("old web policy\n", encoding="utf-8")
    real_replace = materialized_files.os.replace

    def policy_sha() -> str:
        return "|".join(
            (first.read_text(encoding="utf-8"), second.read_text(encoding="utf-8"))
        )

    def fail_publish_and_rollback(source, destination) -> None:
        content = Path(source).read_text(encoding="utf-8")
        if Path(destination) == second and content == "new web policy\n":
            msg = "injected publication failure"
            raise OSError(msg)
        if Path(destination) == first and content == "old ssl policy\n":
            msg = "injected rollback failure"
            raise OSError(msg)
        real_replace(source, destination)

    monkeypatch.setattr(materialized_files.os, "replace", fail_publish_and_rollback)
    runtime = _runtime_shell()
    runtime.policy_state_builder = lambda _proxy_id: SimpleNamespace(
        policy_sha256="desired-policy-sha",
        files=(
            SimpleNamespace(path=str(first), content="new ssl policy\n"),
            SimpleNamespace(path=str(second), content="new web policy\n"),
        ),
    )
    runtime._current_policy_sha = policy_sha
    old_sha = policy_sha()

    result = runtime.sync_policy_state()

    assert result["ok"] is False
    assert result["changed"] is True
    assert result["reload_required"] is True
    assert result["current_policy_sha"] == policy_sha()
    assert result["current_policy_sha"] != old_sha
    assert "rollback was incomplete" in result["detail"]
    assert "injected" not in result["detail"]

    monkeypatch.setattr(materialized_files.os, "replace", real_replace)
    retry = runtime.sync_policy_state()
    assert retry["ok"] is True
    assert retry["changed"] is True
    assert retry["reload_required"] is True
    assert first.read_text(encoding="utf-8") == "new ssl policy\n"
    assert second.read_text(encoding="utf-8") == "new web policy\n"


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


def test_sync_pac_state_reports_verified_current_sha_after_materialize(
    tmp_path,
) -> None:
    from services import pac_renderer  # type: ignore

    state = pac_renderer.ProxyPacState(
        proxy_id="live",
        state_sha256="new-pac-sha",
        files=(
            pac_renderer.RenderedPacFile(
                relative_path="fallback.pac",
                content="PAC content\n",
            ),
            pac_renderer.RenderedPacFile(
                relative_path=pac_renderer.PAC_STATE_SHA_FILENAME,
                content="new-pac-sha\n",
            ),
        ),
    )
    pac_dir = tmp_path / "pac"

    runtime = _runtime_shell()
    runtime.services = SimpleNamespace(current_pac_sha_reader=None)
    runtime.pac_render_dir = str(pac_dir)
    runtime.pac_state_builder = lambda _proxy_id: state

    result = runtime.sync_pac_state()

    assert result["ok"] is True
    assert result["changed"] is True
    assert result["state_sha256"] == "new-pac-sha"
    assert result["current_state_sha256"] == "new-pac-sha"
    assert "verified current" in result["detail"]


def test_sync_pac_state_fails_when_post_materialize_evidence_is_absent(
    tmp_path,
    monkeypatch,
) -> None:
    from services import pac_renderer  # type: ignore

    import proxy.runtime as runtime_module  # type: ignore

    state = pac_renderer.ProxyPacState(
        proxy_id="live",
        state_sha256="new-pac-sha",
        files=(
            pac_renderer.RenderedPacFile(
                relative_path="fallback.pac",
                content="PAC content\n",
            ),
            pac_renderer.RenderedPacFile(
                relative_path=pac_renderer.PAC_STATE_SHA_FILENAME,
                content="new-pac-sha\n",
            ),
        ),
    )
    pac_dir = tmp_path / "pac"

    def stale_materialize(target_dir, *, state):
        pathlib_target = Path(target_dir)
        pathlib_target.mkdir(parents=True, exist_ok=True)
        (pathlib_target / pac_renderer.PAC_STATE_SHA_FILENAME).write_text(
            "old-pac-sha\n",
            encoding="utf-8",
        )

    runtime = _runtime_shell()
    runtime.services = SimpleNamespace(current_pac_sha_reader=None)
    runtime.pac_render_dir = str(pac_dir)
    runtime.pac_state_builder = lambda _proxy_id: state
    monkeypatch.setattr(
        runtime_module, "materialize_proxy_pac_state", stale_materialize
    )

    result = runtime.sync_pac_state()

    assert result["ok"] is False
    assert result["state_sha256"] == "new-pac-sha"
    assert result["current_state_sha256"] == "old-pac-sha"
    assert "could not verify convergence" in result["detail"]


def test_sync_from_db_pac_evidence_does_not_invent_current_sha(monkeypatch) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    runtime._invalidate_health_cache = lambda: None
    runtime.ensure_registered = lambda: None
    runtime.bootstrap_revision_if_missing = lambda: None
    runtime.sync_certificate_bundle = lambda force=False, operations=None: {
        "ok": True,
        "changed": False,
        "detail": "",
    }
    runtime.sync_policy_state = lambda force=False: {
        "ok": True,
        "changed": False,
        "reload_required": False,
        "detail": "",
        "policy_sha256": POLICY_SHA_A,
        "current_policy_sha": POLICY_SHA_A,
    }
    runtime.sync_adblock_state = lambda force=False, operations=None: {
        "ok": True,
        "changed": False,
        "detail": "",
    }
    runtime.sync_pac_state = lambda force=False: {
        "ok": True,
        "changed": True,
        "detail": "PAC reported no current evidence.",
        "state_sha256": PAC_SHA_A,
    }
    runtime._current_config_sha = lambda: "config-sha"
    runtime._current_policy_sha = lambda: POLICY_SHA_A
    runtime._current_adblock_artifact_sha = lambda: ""
    runtime._current_pac_state_sha = lambda: ""
    runtime._current_adblock_enabled = lambda: False
    runtime._ensure_policy_runtime_config = lambda: (True, "", False)
    runtime._capture_recovery_bundle_after_sync = lambda _result: None
    runtime.controller = SimpleNamespace()
    runtime.registry = SimpleNamespace(mark_apply_result=lambda *args, **kwargs: None)
    runtime.revisions = SimpleNamespace(
        get_active_revision_metadata=lambda _proxy_id: None
    )

    result = runtime._sync_from_db_unlocked(
        operations=[
            SimpleNamespace(
                operation_type="pac_refresh",
                target_kind="pac_state",
                target_ref=PAC_SHA_A,
                force=True,
            ),
        ],
    )

    assert result["ok"] is True
    assert result["state_sha256"] == PAC_SHA_A
    assert result["current_state_sha256"] == ""
    status, detail = runtime_module._operation_completion_status(
        SimpleNamespace(
            operation_type="pac_refresh",
            target_kind="pac_state",
            target_ref=PAC_SHA_A,
        ),
        default_status="applied",
        detail=result["detail"],
        result=result,
    )
    assert status == "failed"
    assert "current runtime evidence" in detail


def test_sync_pac_state_reapplies_when_marker_matches_but_file_missing(
    tmp_path,
) -> None:
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
    import proxy.runtime as runtime_module  # type: ignore

    monkeypatch.setenv("SQUID_WORKERS", "2")
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


def test_supervisor_program_status_rejects_partial_scaled_icap_helpers(
    monkeypatch,
) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    monkeypatch.setenv("SQUID_WORKERS", "2")
    monkeypatch.setattr(
        runtime_module.subprocess,
        "run",
        lambda *_args, **_kwargs: _cp(
            0, stdout="cicap_adblock_1 RUNNING pid 10, uptime 0:00:11\n"
        ),
    )

    ok, detail = _runtime_shell()._supervisor_program_status("cicap_adblock")

    assert ok is False
    assert "missing configured programs: cicap_adblock_2" in detail


def test_resolve_supervisor_program_names_rejects_partial_scaled_set(
    monkeypatch,
) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    monkeypatch.setenv("SQUID_WORKERS", "2")
    monkeypatch.setattr(
        runtime_module.subprocess,
        "run",
        lambda *_args, **_kwargs: _cp(
            0, stdout="cicap_adblock_1 RUNNING pid 10, uptime 0:00:11\n"
        ),
    )

    programs, detail = _runtime_shell()._resolve_supervisor_program_names(
        "cicap_adblock"
    )

    assert programs == []
    assert "missing configured programs: cicap_adblock_2" in detail


def test_supervisor_program_status_rejects_duplicate_scaled_member(monkeypatch) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    monkeypatch.setenv("SQUID_WORKERS", "2")
    monkeypatch.setattr(
        runtime_module.subprocess,
        "run",
        lambda *_args, **_kwargs: _cp(
            0,
            stdout=(
                "cicap_adblock_1 RUNNING pid 10, uptime 0:00:11\n"
                "cicap_adblock_1 RUNNING pid 99, uptime 0:00:01\n"
                "cicap_adblock_2 RUNNING pid 11, uptime 0:00:10\n"
            ),
        ),
    )

    ok, detail = _runtime_shell()._supervisor_program_status("cicap_adblock")

    assert ok is False
    assert "cicap_adblock_1 RUNNING pid 10" in detail
    assert "cicap_adblock_1 RUNNING pid 99" in detail


def test_supervisor_program_status_preserves_legacy_single_name(monkeypatch) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    monkeypatch.delenv("SQUID_WORKERS", raising=False)
    monkeypatch.delenv("WORKERS", raising=False)
    monkeypatch.setattr(
        runtime_module.subprocess,
        "run",
        lambda *_args, **_kwargs: _cp(
            0, stdout="cicap_adblock RUNNING pid 10, uptime 0:00:11\n"
        ),
    )

    ok, detail = _runtime_shell()._supervisor_program_status("cicap_adblock")

    assert ok is True
    assert "cicap_adblock RUNNING" in detail


@pytest.mark.parametrize(
    ("raw_workers", "expected"),
    [
        ("   ", ("cicap_adblock_1",)),
        ("malformed", ("cicap_adblock_1",)),
        ("0", ("cicap_adblock_1",)),
        ("3", ("cicap_adblock_1", "cicap_adblock_2", "cicap_adblock_3")),
        ("99", tuple(f"cicap_adblock_{index}" for index in range(1, 5))),
    ],
)
def test_icap_supervisor_program_names_use_shared_worker_normalization(
    monkeypatch, raw_workers: str, expected: tuple[str, ...]
) -> None:
    from proxy.runtime import _icap_supervisor_programs

    monkeypatch.setenv("SQUID_WORKERS", raw_workers)
    monkeypatch.delenv("WORKERS", raising=False)

    assert _icap_supervisor_programs("cicap_adblock") == expected


def test_restart_supervisor_program_restarts_scaled_icap_helpers(monkeypatch) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    monkeypatch.setenv("SQUID_WORKERS", "2")
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
    assert not any(program == "cicap_adblock" for _action, program in calls)
    assert "no such process" not in detail


def test_restart_supervisor_program_scaled_fail_safe_avoids_logical_no_such_process(
    monkeypatch,
) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    monkeypatch.setenv("SQUID_WORKERS", "1")
    monkeypatch.setattr(runtime_module.time, "sleep", lambda _seconds: None)
    calls: list[tuple[str, str | None]] = []
    started = False

    def fake_run(args, **_kwargs):
        nonlocal started
        action = args[3]
        program = args[4] if len(args) > 4 else None
        calls.append((action, program))
        if program == "cicap_adblock":
            return _cp(2, stdout="cicap_adblock: ERROR (no such process)\n")
        if action == "status" and program is None:
            return _cp(
                0,
                stdout="cicap_adblock_1 RUNNING pid 10, uptime 0:00:11\n",
            )
        if action == "stop":
            started = False
            return _cp(0, stdout=f"{program}: stopped\n")
        if action == "start":
            started = True
            return _cp(1, stderr=f"{program}: ERROR (abnormal termination)\n")
        if action == "status":
            state = "BACKOFF exited too quickly" if started else "STOPPED Aug 10 01:00 AM"
            return _cp(3, stdout=f"{program} {state}\n")
        pytest.fail(f"unexpected supervisor call: {args}")

    monkeypatch.setattr(runtime_module.subprocess, "run", fake_run)

    ok, detail = _runtime_shell()._restart_supervisor_program(
        "cicap_adblock",
        stop_on_failure=True,
    )

    assert ok is False
    assert calls.count(("stop", "cicap_adblock_1")) == 2
    assert not any(program == "cicap_adblock" for _action, program in calls)
    assert "Fail-safe stop confirmed for cicap_adblock_1." in detail
    assert "Unable to verify fail-safe stop" not in detail
    assert "no such process" not in detail


@pytest.mark.parametrize(
    "status_output",
    [
        "cicap_adblock_1 RUNNING pid 10, uptime 0:00:11\n",
        "cicap_av_1 RUNNING pid 10, uptime 0:00:11\n",
        (
            "cicap_adblock_1 RUNNING pid 10, uptime 0:00:11\n"
            "cicap_adblock_1 RUNNING pid 99, uptime 0:00:01\n"
            "cicap_adblock_2 RUNNING pid 11, uptime 0:00:10\n"
        ),
    ],
)
def test_control_supervisor_program_rejects_unresolvable_scaled_set(
    monkeypatch, status_output: str
) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    monkeypatch.setenv("SQUID_WORKERS", "2")
    calls: list[list[str]] = []

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        assert args[3] == "status"
        return _cp(0, stdout=status_output)

    monkeypatch.setattr(runtime_module.subprocess, "run", fake_run)
    runtime = _runtime_shell()
    runtime._invalidate_health_cache = lambda: None

    result = runtime.test_control_supervisor_program("cicap_adblock", action="stop")

    assert result["ok"] is False
    assert result["detail"]
    assert calls == [["supervisorctl", "-c", "/etc/supervisord.conf", "status"]]


def test_control_supervisor_program_controls_complete_scaled_set(monkeypatch) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    monkeypatch.setenv("SQUID_WORKERS", "2")
    calls: list[list[str]] = []

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        if args[3] == "status":
            return _cp(
                3,
                stdout=(
                    "cicap_adblock_1 STOPPED Jul 03 09:42 PM\n"
                    "cicap_adblock_2 RUNNING pid 11, uptime 0:00:10\n"
                ),
            )
        return _cp(0, stdout=f"{args[4]}: stopped\n")

    monkeypatch.setattr(runtime_module.subprocess, "run", fake_run)
    runtime = _runtime_shell()
    runtime._invalidate_health_cache = lambda: None

    result = runtime.test_control_supervisor_program("cicap_adblock", action="stop")

    assert result["ok"] is True
    assert [call[4] for call in calls[1:]] == [
        "cicap_adblock_1",
        "cicap_adblock_2",
    ]


def test_control_supervisor_program_preserves_legacy_unsuffixed_name(
    monkeypatch,
) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    monkeypatch.delenv("SQUID_WORKERS", raising=False)
    monkeypatch.delenv("WORKERS", raising=False)
    calls: list[list[str]] = []

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        if args[3] == "status":
            return _cp(3, stdout="cicap_av STOPPED Jul 03 09:42 PM\n")
        return _cp(0, stdout="cicap_av: started\n")

    monkeypatch.setattr(runtime_module.subprocess, "run", fake_run)
    runtime = _runtime_shell()
    runtime._invalidate_health_cache = lambda: None
    runtime._supervisor_program_status = lambda *_args, **_kwargs: (
        True,
        "cicap_av RUNNING",
    )

    result = runtime.test_control_supervisor_program("cicap_av", action="start")

    assert result["ok"] is True
    assert calls[-1][3:] == ["start", "cicap_av"]


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


def test_test_control_supervisor_start_uses_one_total_monotonic_budget(
    monkeypatch,
) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    elapsed = {"value": 0.0}
    resolve_timeouts: list[float] = []
    command_timeouts: list[float] = []
    status_timeouts: list[float] = []

    monkeypatch.setattr(runtime_module.time, "monotonic", lambda: elapsed["value"])

    runtime = _runtime_shell()
    runtime._invalidate_health_cache = lambda: None

    def resolve(_program, timeout_seconds=10):
        resolve_timeouts.append(timeout_seconds)
        elapsed["value"] += 0.4
        return ["cicap_adblock_1", "cicap_adblock_2"], "scaled helpers"

    def fake_run(_args, **kwargs):
        command_timeouts.append(kwargs["timeout"])
        elapsed["value"] += 0.4
        return _cp(0, stdout="started")

    def status(_program, timeout_seconds=10, **_kwargs):
        status_timeouts.append(timeout_seconds)
        return True, "helpers RUNNING"

    runtime._resolve_supervisor_program_names = resolve
    runtime._supervisor_program_status = status
    monkeypatch.setattr(runtime_module.subprocess, "run", fake_run)

    result = runtime.test_control_supervisor_program(
        "cicap_adblock", action="start", timeout_seconds=2
    )

    assert result["ok"] is True
    assert "scaled helpers" in result["detail"]
    assert "helpers RUNNING" in result["detail"]
    assert resolve_timeouts == pytest.approx([2.0])
    assert command_timeouts == pytest.approx([1.6, 1.2])
    assert status_timeouts == pytest.approx([0.8])


def test_test_control_supervisor_start_skips_status_when_total_budget_expires(
    monkeypatch,
) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    elapsed = {"value": 0.0}
    status_called = False
    monkeypatch.setattr(runtime_module.time, "monotonic", lambda: elapsed["value"])

    runtime = _runtime_shell()
    runtime._invalidate_health_cache = lambda: None

    def resolve(_program, timeout_seconds=10):
        elapsed["value"] += 0.5
        return ["cicap_av_1", "cicap_av_2"], "scaled helpers"

    def fake_run(_args, **_kwargs):
        elapsed["value"] += 0.75
        return _cp(0, stdout="started")

    def status(*_args, **_kwargs):
        nonlocal status_called
        status_called = True
        return True, "helpers RUNNING"

    runtime._resolve_supervisor_program_names = resolve
    runtime._supervisor_program_status = status
    monkeypatch.setattr(runtime_module.subprocess, "run", fake_run)

    result = runtime.test_control_supervisor_program(
        "cicap_av", action="start", timeout_seconds=2
    )

    assert result["ok"] is False
    assert status_called is False
    assert "Timed out before verifying cicap_av status." in result["detail"]


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


def test_wait_for_supervisor_stop_uses_monotonic_deadline_during_wall_clock_jumps(
    monkeypatch,
) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    elapsed = {"value": 0.0}
    timeouts: list[float] = []
    wall_times = iter((100.0, 10_000.0, -10_000.0, 20_000.0, -20_000.0))

    def fake_run(_args, **kwargs):
        timeouts.append(kwargs["timeout"])
        return _cp(0, stdout="squid RUNNING pid 123, uptime 0:00:01")

    monkeypatch.setattr(runtime_module.time, "time", lambda: next(wall_times))
    monkeypatch.setattr(runtime_module.time, "monotonic", lambda: elapsed["value"])
    monkeypatch.setattr(
        runtime_module.time,
        "sleep",
        lambda seconds: elapsed.__setitem__("value", elapsed["value"] + seconds),
    )
    monkeypatch.setattr(runtime_module.subprocess, "run", fake_run)

    ok, detail = _runtime_shell()._wait_for_supervisor_program_stopped(
        "squid", timeout_seconds=2.0
    )

    assert ok is False
    assert "RUNNING" in detail
    assert len(timeouts) == 4
    assert all(timeout > 0 for timeout in timeouts)
    assert timeouts == pytest.approx([2.0, 1.5, 1.0, 0.5])


def test_restart_supervisor_program_returns_false_after_retries(monkeypatch) -> None:
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


def test_restart_supervisor_program_uses_one_total_monotonic_budget(
    monkeypatch,
) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    elapsed = {"value": 0.0}
    timeouts: list[float] = []
    calls: list[str] = []

    def fake_run(args, **kwargs):
        action = args[3]
        calls.append(action)
        timeouts.append(kwargs["timeout"])
        elapsed["value"] += min(0.2, kwargs["timeout"])
        if action == "stop":
            return _cp(0, stdout="service: stopped")
        if action == "status":
            return _cp(3, stdout="service FATAL")
        return _cp(1, stderr="service: ERROR (abnormal termination)")

    monkeypatch.setattr(runtime_module.time, "monotonic", lambda: elapsed["value"])
    monkeypatch.setattr(
        runtime_module.time,
        "sleep",
        lambda seconds: elapsed.__setitem__(
            "value", elapsed["value"] + min(seconds, 2.0 - elapsed["value"])
        ),
    )
    monkeypatch.setattr(runtime_module.subprocess, "run", fake_run)

    runtime = _runtime_shell()
    runtime._wait_for_supervisor_program_stopped = (
        lambda _program, timeout_seconds=30.0: (True, "service STOPPED")
    )

    ok, detail = runtime._restart_supervisor_program("service", timeout_seconds=2)

    assert ok is False
    assert "abnormal termination" in detail
    assert calls == ["stop", "start", "status"]
    assert elapsed["value"] == pytest.approx(2.0)
    assert timeouts == pytest.approx([2.0, 1.8, 0.6])
    assert all(timeout > 0 for timeout in timeouts)


def test_restart_adblock_service_uses_injected_restarter() -> None:
    runtime = _runtime_shell()
    runtime.services = SimpleNamespace(
        adblock_service_restarter=lambda: (True, "custom restarter")
    )

    assert runtime._restart_adblock_service() == (True, "custom restarter")


def test_restart_adblock_health_wait_uses_monotonic_deadline_during_wall_clock_jumps(
    monkeypatch,
) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    elapsed = {"value": 0.0}
    probes = {"count": 0}
    runtime = _runtime_shell()
    runtime.services = SimpleNamespace(adblock_service_restarter=None)
    runtime._restart_supervisor_program = lambda *_args, **_kwargs: (True, "restarted")

    monkeypatch.setattr(
        runtime_module.time,
        "time",
        lambda: 10**9 if probes["count"] % 2 else -(10**9),
    )
    monkeypatch.setattr(runtime_module.time, "monotonic", lambda: elapsed["value"])
    monkeypatch.setattr(
        runtime_module.time,
        "sleep",
        lambda _seconds: elapsed.__setitem__("value", elapsed["value"] + 5.0),
    )

    def unhealthy(**_kwargs):
        probes["count"] += 1
        return {"ok": False, "detail": "icap not ready"}

    monkeypatch.setattr(runtime_module, "_check_icap_adblock", unhealthy)

    ok, detail = runtime._restart_adblock_service()

    assert ok is False
    assert "icap not ready" in detail
    assert probes["count"] == 3


def test_restart_adblock_service_stops_program_after_restart_loop(monkeypatch) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    calls: list[list[str]] = []
    monkeypatch.setattr(runtime_module.time, "sleep", lambda _seconds: None)

    stop_calls = 0

    def fake_run(args, **_kwargs):
        nonlocal stop_calls
        calls.append(list(args))
        if "stop" in args:
            stop_calls += 1
            return _cp(0, stdout="cicap_adblock: stopped")
        if "status" in args:
            if stop_calls > 1:
                return _cp(3, stdout="cicap_adblock STOPPED Aug 10 01:00 AM")
            return _cp(3, stdout="cicap_adblock BACKOFF exited too quickly")
        if "start" in args:
            return _cp(0, stdout="cicap_adblock: started")
        pytest.fail(f"unexpected supervisor call: {args}")

    monkeypatch.setattr(runtime_module.subprocess, "run", fake_run)

    runtime = _runtime_shell()
    runtime.services = SimpleNamespace(adblock_service_restarter=None)

    ok, detail = runtime._restart_adblock_service()

    assert ok is False
    assert "BACKOFF" in detail
    assert "Fail-safe stop confirmed for cicap_adblock." in detail
    assert calls[-2:] == [
        [
            "supervisorctl",
            "-c",
            "/etc/supervisord.conf",
            "status",
            "cicap_adblock",
        ],
        [
            "supervisorctl",
            "-c",
            "/etc/supervisord.conf",
            "status",
            "cicap_adblock",
        ],
    ]


def test_restart_adblock_service_surfaces_unverified_fail_safe_stop(
    monkeypatch,
) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    stop_calls = 0
    monkeypatch.setattr(runtime_module.time, "sleep", lambda _seconds: None)

    def fake_run(args, **_kwargs):
        nonlocal stop_calls
        if "stop" in args:
            stop_calls += 1
            if stop_calls == 2:
                timeout_detail = "supervisor stop timed out"
                raise TimeoutError(timeout_detail)
            return _cp(0, stdout="cicap_adblock: stopped")
        if "start" in args:
            return _cp(1, stderr="cicap_adblock: ERROR (abnormal termination)")
        if "status" in args:
            return _cp(3, stdout="other_program STOPPED Aug 10 01:00 AM")
        pytest.fail(f"unexpected supervisor call: {args}")

    monkeypatch.setattr(runtime_module.subprocess, "run", fake_run)
    runtime = _runtime_shell()
    wait_results = iter(
        [
            (True, "cicap_adblock STOPPED Aug 10 01:00 AM"),
            (True, "cicap_adblock STOPPED Aug 10 01:00 AM"),
        ]
    )
    runtime._wait_for_supervisor_program_stopped = (
        lambda _program, timeout_seconds=30.0: next(wait_results)
    )
    runtime._supervisor_program_status_exact = (
        lambda _program, timeout_seconds=30, accepted_states=("RUNNING",): (
            False,
            "cicap_adblock BACKOFF exited too quickly",
        )
    )
    runtime.services = SimpleNamespace(adblock_service_restarter=None)

    ok, detail = runtime._restart_adblock_service()

    assert ok is False
    assert stop_calls == 2
    assert "Fail-safe stop command for cicap_adblock failed." in detail
    assert "timed out" not in detail
    assert "Unable to verify fail-safe stop for cicap_adblock." in detail


def test_restart_adblock_service_reports_scaled_worker_failure_without_squid(
    monkeypatch,
) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    calls: list[list[str]] = []
    started: set[str] = set()
    monkeypatch.setattr(runtime_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setenv("SQUID_WORKERS", "2")

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        action = args[3]
        program = args[4] if len(args) > 4 else None
        assert program != "squid"
        if action == "status" and program is None:
            return _cp(
                0,
                stdout=(
                    "cicap_adblock_1 RUNNING pid 10, uptime 0:00:11\n"
                    "cicap_adblock_2 RUNNING pid 11, uptime 0:00:10\n"
                ),
            )
        if program == "cicap_adblock":
            return _cp(2, stdout="cicap_adblock: ERROR (no such process)\n")
        if action == "stop":
            started.discard(str(program))
            return _cp(0, stdout=f"{program}: stopped")
        if action == "status":
            if program == "cicap_adblock_2" and str(program) in started:
                return _cp(3, stdout="cicap_adblock_2 BACKOFF exited too quickly")
            state = (
                "RUNNING pid 42, uptime 0:00:01"
                if str(program) in started
                else "STOPPED Jul 03 09:42 PM"
            )
            return _cp(0, stdout=f"{program} {state}\n")
        if action == "start" and program:
            started.add(str(program))
            if program == "cicap_adblock_2":
                return _cp(1, stderr="cicap_adblock_2: ERROR (abnormal termination)")
        return _cp(0, stdout=f"{program}: {action}ped\n")

    monkeypatch.setattr(runtime_module.subprocess, "run", fake_run)

    runtime = _runtime_shell()
    runtime.services = SimpleNamespace(adblock_service_restarter=None)

    ok, detail = runtime._restart_adblock_service()

    assert ok is False
    assert "cicap_adblock_1" in detail
    assert "cicap_adblock_2 BACKOFF" in detail
    assert not any(call[3:] == ["stop", "squid"] for call in calls)
    assert any(call[3:] == ["stop", "cicap_adblock_1"] for call in calls)
    assert any(call[3:] == ["start", "cicap_adblock_1"] for call in calls)
    assert any(call[3:] == ["stop", "cicap_adblock_2"] for call in calls)
    assert any(call[3:] == ["start", "cicap_adblock_2"] for call in calls)
    assert sum(call[3:] == ["stop", "cicap_adblock_1"] for call in calls) == 2
    assert sum(call[3:] == ["stop", "cicap_adblock_2"] for call in calls) == 2
    assert not any(call[3:] == ["stop", "cicap_adblock"] for call in calls)
    assert "Fail-safe stop confirmed for cicap_adblock_1." in detail
    assert "Fail-safe stop confirmed for cicap_adblock_2." in detail


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


@pytest.mark.parametrize("stop_failure", ["nonzero", "exception"])
def test_ssl_db_reinitialize_preserves_database_when_squid_stop_is_unverified(
    monkeypatch,
    tmp_path,
    stop_failure,
) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    ssl_db = tmp_path / "ssl_db" / "store"
    ssl_db.mkdir(parents=True)
    sentinel = ssl_db / "sentinel.pem"
    sentinel.write_text("live database", encoding="utf-8")
    calls: list[list[str]] = []

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        if args == ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "squid"]:
            if stop_failure == "exception":
                msg = "supervisor unavailable"
                raise OSError(msg)
            return _cp(1, stdout="squid: ERROR (failed to stop)")
        if args == ["squid", "-k", "shutdown"]:
            return _cp(1, stdout="shutdown signal failed")
        if args == ["sh", "/scripts/init_ssl_db.sh"]:
            msg = "initializer must not run while Squid may be running"
            raise AssertionError(msg)
        return _cp(0, stdout="ok")

    runtime = _runtime_shell()
    runtime.services = SimpleNamespace(ssl_db_reinitializer=None)
    runtime.ssl_db_dir = str(ssl_db)
    runtime.controller = SimpleNamespace(
        restart_squid=lambda: (_ for _ in ()).throw(
            AssertionError("restart must not run after an unverified stop")
        ),
    )
    runtime._supervisor_program_status = lambda *_args, **_kwargs: (
        False,
        "squid RUNNING pid 42, uptime 0:10:00",
    )

    monkeypatch.setattr(runtime_module, "subprocess", SimpleNamespace(run=fake_run))
    monkeypatch.setattr(
        runtime_module.pathlib.Path,
        "exists",
        lambda self: str(self) == "/scripts/init_ssl_db.sh" or self == sentinel,
    )

    ok, detail = runtime._reinitialize_ssl_db_and_restart()

    assert ok is False
    assert "could not be verified stopped" in detail
    assert "squid RUNNING" in detail
    assert sentinel.read_text(encoding="utf-8") == "live database"
    assert ["sh", "/scripts/init_ssl_db.sh"] not in calls


def test_ssl_db_reinitialize_restores_squid_when_recursive_deletion_fails(
    monkeypatch,
    tmp_path,
) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    ssl_db = tmp_path / "ssl_db" / "store"
    ssl_db.mkdir(parents=True)
    calls: list[list[str]] = []

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        if args == ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "squid"]:
            return _cp(0, stdout="squid: stopped")
        return _cp(0, stdout="unexpected follow-on command")

    def failing_rmtree(path, *, ignore_errors=False):
        assert str(path) == str(ssl_db)
        error = PermissionError("permission denied while removing stale ssl_db")
        if not ignore_errors:
            raise error

    runtime = _runtime_shell()
    runtime.services = SimpleNamespace(ssl_db_reinitializer=None)
    runtime.ssl_db_dir = str(ssl_db)
    runtime.controller = SimpleNamespace(
        restart_squid=lambda: (True, "squid restarted for recovery"),
        _wait_for_http_listener=lambda *, timeout: True,
    )
    statuses = iter(
        [
            (True, "squid STOPPED Jul 18 02:18 AM"),
            (True, "squid RUNNING pid 42, uptime 0:00:01"),
        ],
    )
    runtime._supervisor_program_status = lambda *_args, **_kwargs: next(statuses)

    monkeypatch.setattr(runtime_module, "subprocess", SimpleNamespace(run=fake_run))
    monkeypatch.setattr(runtime_module.shutil, "rmtree", failing_rmtree)
    monkeypatch.setattr(
        runtime_module.pathlib.Path,
        "exists",
        lambda self: str(self) == "/scripts/init_ssl_db.sh",
    )

    ok, detail = runtime._reinitialize_ssl_db_and_restart()

    assert ok is False
    assert "Failed to clear ssl_db directory" in detail
    assert "permission denied while removing stale ssl_db" in detail
    assert "squid restarted for recovery" in detail
    assert "Squid service recovery succeeded" in detail
    assert calls == [
        ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "squid"],
    ]


def test_init_ssl_db_permission_repair_fails_closed_on_chown_error(
    tmp_path,
) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    script = (repo_root / "scripts" / "init_ssl_db.sh").read_text(encoding="utf-8")
    function = script[script.index("repair_ssl_db_permissions() {") :]
    function = function[: function.index("\n}\n") + 3]

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in {
        "chmod": "exit 0",
        "getent": "exit 0",
        "chown": 'echo "chown: simulated ownership denial" >&2; exit 1',
    }.items():
        command = bin_dir / name
        command.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
        command.chmod(0o755)

    ssl_db = tmp_path / "ssl_db" / "store"
    (ssl_db / "certs").mkdir(parents=True)
    result = run_test_process(
        ["sh", "-c", f"{function}\nrepair_ssl_db_permissions"],
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
            "SSL_DB_DIR": str(ssl_db),
        },
    )

    assert result.returncode != 0
    assert "simulated ownership denial" in result.stderr
    assert "Failed to recursively set squid:squid ownership" in result.stderr


def test_ssl_db_reinitialize_tolerates_already_absent_database(
    monkeypatch,
    tmp_path,
) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    ssl_db = tmp_path / "ssl_db" / "store"
    calls: list[list[str]] = []

    def fake_run(args, **kwargs):
        calls.append(list(args))
        if args == ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "squid"]:
            return _cp(0, stdout="squid: stopped")
        if args == ["sh", "/scripts/init_ssl_db.sh"]:
            target = Path(str((kwargs.get("env") or {})["SSL_DB_DIR"]))
            (target / "certs").mkdir(parents=True)
            return _cp(0, stdout="initialized")
        return _cp(0, stdout="ok")

    runtime = _runtime_shell()
    runtime.services = SimpleNamespace(ssl_db_reinitializer=None)
    runtime.ssl_db_dir = str(ssl_db)
    runtime.controller = SimpleNamespace(restart_squid=lambda: (True, "restarted"))
    runtime._supervisor_program_status = lambda *_args, **_kwargs: (
        True,
        "squid STOPPED Jul 18 02:18 AM",
    )

    monkeypatch.setattr(runtime_module, "subprocess", SimpleNamespace(run=fake_run))
    monkeypatch.setattr(
        runtime_module.pathlib.Path,
        "exists",
        lambda self: str(self) == "/scripts/init_ssl_db.sh",
    )

    ok, detail = runtime._reinitialize_ssl_db_and_restart()

    assert ok is True
    assert "initialized" in detail
    assert "restarted" in detail
    assert ["sh", "/scripts/init_ssl_db.sh"] in calls
    assert ssl_db.stat().st_mode & 0o777 == 0o700
    assert (ssl_db / "certs").stat().st_mode & 0o777 == 0o750


def test_ssl_db_reinitialize_restores_squid_when_permission_repair_fails(
    monkeypatch,
    tmp_path,
) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    ssl_db = tmp_path / "ssl_db" / "store"
    calls: list[list[str]] = []

    def fake_run(args, **kwargs):
        calls.append(list(args))
        if args == ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "squid"]:
            return _cp(0, stdout="squid: stopped")
        if args == ["sh", "/scripts/init_ssl_db.sh"]:
            target = Path(str((kwargs.get("env") or {})["SSL_DB_DIR"]))
            (target / "certs").mkdir(parents=True)
            return _cp(0, stdout="initialized")
        return _cp(0, stdout="ok")

    runtime = _runtime_shell()
    runtime.services = SimpleNamespace(ssl_db_reinitializer=None)
    runtime.ssl_db_dir = str(ssl_db)
    runtime.controller = SimpleNamespace(
        restart_squid=lambda: (False, "primary recovery restart failed"),
        _wait_for_http_listener=lambda *, timeout: False,
    )
    statuses = iter(
        [
            (True, "squid STOPPED Jul 18 02:18 AM"),
            (False, "squid BACKOFF Exited too quickly"),
            (False, "squid BACKOFF Exited too quickly"),
        ],
    )
    runtime._supervisor_program_status = lambda *_args, **_kwargs: next(statuses)

    original_chmod = runtime_module.pathlib.Path.chmod

    def fail_ssl_db_chmod(path, mode, *, follow_symlinks=True):
        if path == ssl_db:
            msg = "permission denied while securing ssl_db"
            raise PermissionError(msg)
        return original_chmod(path, mode, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(runtime_module, "subprocess", SimpleNamespace(run=fake_run))
    monkeypatch.setattr(runtime_module.pathlib.Path, "chmod", fail_ssl_db_chmod)
    monkeypatch.setattr(
        runtime_module.pathlib.Path,
        "exists",
        lambda self: str(self) == "/scripts/init_ssl_db.sh",
    )

    ok, detail = runtime._reinitialize_ssl_db_and_restart()

    assert ok is False
    assert "Failed to repair ssl_db permissions" in detail
    assert "permission denied while securing ssl_db" in detail
    assert "primary recovery restart failed" in detail
    assert "Squid service recovery failed" in detail
    assert calls == [
        ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "squid"],
        ["sh", "/scripts/init_ssl_db.sh"],
        ["supervisorctl", "-c", "/etc/supervisord.conf", "start", "squid"],
    ]


def test_ssl_db_reinitialize_recovers_when_restart_reports_stopped_squid(
    monkeypatch,
    tmp_path,
) -> None:
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
            (True, "squid STOPPED Jul 18 02:18 AM"),
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
    import proxy.runtime as runtime_module  # type: ignore

    ssl_db = tmp_path / "ssl_db" / "store"

    def fake_run(args, **kwargs):
        if args == ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "squid"]:
            return _cp(0, stdout="squid: stopped")
        if args == ["sh", "/scripts/init_ssl_db.sh"]:
            target = Path(str((kwargs.get("env") or {})["SSL_DB_DIR"]))
            (target / "certs").mkdir(parents=True)
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
    statuses = iter(
        [
            (True, "squid STOPPED Jul 18 02:18 AM"),
            (False, "squid BACKOFF Exited too quickly"),
            (False, "squid BACKOFF Exited too quickly"),
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


def test_runtime_self_heal_rolls_back_when_listener_probe_raises() -> None:
    runtime = _runtime_shell()
    rollback_reasons = []
    runtime.controller = SimpleNamespace(
        get_status=lambda: (b"squid ok", b""),
        _wait_for_http_listener=lambda *, timeout: (_ for _ in ()).throw(
            RuntimeError("private probe failure")
        ),
    )
    runtime.rollback_last_known_good_config = lambda *, reason: (
        rollback_reasons.append(reason)
        or {"ok": True, "rolled_back": True, "detail": "rolled back"}
    )

    result = runtime.self_heal_config_if_needed(reason="test")

    assert result["rolled_back"] is True
    assert rollback_reasons == [
        "Self-heal triggered by test: squid ok; Squid listener probe failed."
    ]
    assert "private probe failure" not in str(result)


def test_runtime_service_self_heal_restarts_unhealthy_adblock(monkeypatch) -> None:
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


def test_runtime_service_self_heal_first_restart_is_not_suppressed_by_uptime(
    monkeypatch,
) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    runtime._adblock_icap_health_failures = 2
    runtime._adblock_icap_last_restart_ts = None
    runtime._supervisor_program_status = lambda program, **_kwargs: (
        True,
        "cicap_adblock RUNNING pid 123, uptime 0:10:00",
    )
    restarts: list[bool] = []
    runtime._restart_adblock_service = lambda: (
        restarts.append(True) or (True, "cicap_adblock restarted")
    )
    monkeypatch.setenv("ADBLOCK_ICAP_SELF_HEAL_FAILURE_THRESHOLD", "3")
    monkeypatch.setenv("ADBLOCK_ICAP_SELF_HEAL_RESTART_COOLDOWN_SECONDS", "600")
    monkeypatch.setattr(runtime_module.time, "monotonic", lambda: 100.0)
    monkeypatch.setattr(
        runtime_module,
        "_check_icap_adblock",
        lambda **_kwargs: {"ok": False, "detail": "temporary timeout"},
    )

    result = runtime.self_heal_runtime_services_if_needed(reason="heartbeat")

    assert result["changed"] is True
    assert restarts == [True]


def test_runtime_service_self_heal_serializes_concurrent_callers(monkeypatch) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    runtime._adblock_icap_health_failures = 0
    runtime._adblock_icap_last_restart_ts = None
    healthy = threading.Event()
    restart_entered = threading.Event()
    release_restart = threading.Event()
    restarts: list[bool] = []
    runtime._supervisor_program_status = lambda program, **_kwargs: (
        True,
        "cicap_adblock RUNNING pid 123, uptime 0:10:00",
    )

    def restart():
        restarts.append(True)
        restart_entered.set()
        assert release_restart.wait(timeout=2)
        healthy.set()
        return True, "cicap_adblock restarted"

    runtime._restart_adblock_service = restart
    monkeypatch.setenv("ADBLOCK_ICAP_SELF_HEAL_FAILURE_THRESHOLD", "1")
    monkeypatch.setenv("ADBLOCK_ICAP_SELF_HEAL_RESTART_COOLDOWN_SECONDS", "0")
    monkeypatch.setattr(
        runtime_module,
        "_check_icap_adblock",
        lambda **_kwargs: {
            "ok": healthy.is_set(),
            "detail": "healthy" if healthy.is_set() else "not listening",
        },
    )

    results: list[dict[str, object]] = []
    first = threading.Thread(
        target=lambda: results.append(
            runtime.self_heal_runtime_services_if_needed(reason="heartbeat")
        )
    )
    second = threading.Thread(
        target=lambda: results.append(
            runtime.self_heal_runtime_services_if_needed(reason="api")
        )
    )
    first.start()
    assert restart_entered.wait(timeout=2)
    second.start()
    release_restart.set()
    first.join(timeout=2)
    second.join(timeout=2)

    assert not first.is_alive()
    assert not second.is_alive()
    assert restarts == [True]
    assert sorted(result["changed"] for result in results) == [False, True]


def test_runtime_service_self_heal_waits_for_starting_adblock(monkeypatch) -> None:
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
            return SimpleNamespace(
                revision_id=9,
                config_sha256="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )

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


def test_sync_from_db_forced_noop_records_apply_for_current_config() -> None:
    runtime = _runtime_shell()
    recorded: list[tuple[object, int, bool, str]] = []
    registry_marks: list[tuple[object, bool, str, str]] = []

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
            return SimpleNamespace(application_id=55)

        def get_active_revision(self, _proxy_id):
            msg = "forced no-op should not load active config"
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
    runtime._current_adblock_enabled = lambda: True
    runtime._ensure_policy_runtime_config = lambda: (True, "", False)
    runtime._reload_for_policy_update = lambda **_kwargs: (_ for _ in ()).throw(
        AssertionError("forced no-op should not reload policy includes"),
    )

    result = runtime._sync_from_db_unlocked(force=True, operations=[])

    assert result["ok"] is True
    assert result["changed"] is False
    assert result["config_changed"] is False
    assert result["policy_changed"] is False
    assert result["adblock_changed"] is False
    assert result["application_id"] == 55
    assert result["detail"].endswith(
        "Proxy is already using the active config revision.",
    )
    assert recorded == [("default", 9, True, "proxy")]
    assert registry_marks == [
        (
            "default",
            True,
            "Proxy is already using the active config revision.",
            "current-sha",
        ),
    ]
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


def test_policy_reload_icap_wait_uses_monotonic_deadline_during_wall_clock_jumps(
    monkeypatch,
) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    elapsed = {"value": 0.0}
    probes = {"count": 0}

    class Controller:
        def _run(self, _args, **_kwargs):
            return _cp(0, stdout="reconfigured")

        def _wait_for_http_listener(self, *, timeout) -> bool:
            return True

    runtime.controller = Controller()
    monkeypatch.setattr(
        runtime_module.time,
        "time",
        lambda: -(10**9) if probes["count"] % 2 else 10**9,
    )
    monkeypatch.setattr(runtime_module.time, "monotonic", lambda: elapsed["value"])
    monkeypatch.setattr(
        runtime_module.time,
        "sleep",
        lambda _seconds: elapsed.__setitem__("value", elapsed["value"] + 5.0),
    )

    def unhealthy(**_kwargs):
        probes["count"] += 1
        return {"ok": False, "detail": "icap still warming"}

    monkeypatch.setattr(runtime_module, "_check_icap_adblock", unhealthy)

    ok, detail = runtime._reload_for_policy_update(wait_for_adblock_icap=True)

    assert ok is False
    assert "icap still warming" in detail
    assert probes["count"] == 3


def test_reload_for_policy_update_accepts_missing_pid_when_listener_healthy(
    monkeypatch,
) -> None:
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


def test_squid_controller_config_transactions_are_exclusive_and_ordered(
    tmp_path,
    monkeypatch,
) -> None:
    from services.squid_core import SquidController  # type: ignore

    squid_conf = tmp_path / "squid.conf"
    persisted_conf = tmp_path / "persisted.conf"
    squid_conf.write_text("workers 1\n# old\n", encoding="utf-8")
    controller = SquidController(str(squid_conf))
    controller.persisted_squid_conf_path = str(persisted_conf)
    controller.normalize_config_text = lambda text: text
    controller.validate_config_text = lambda _text: (True, "validated")

    entered = threading.Event()
    release = threading.Event()
    events: list[str] = []
    active = 0
    max_active = 0

    def materialize(config_text, **_kwargs):
        nonlocal active, max_active
        marker = "first" if "first" in config_text else "second"
        active += 1
        max_active = max(max_active, active)
        events.append(f"materialize:{marker}")
        if marker == "first":
            entered.set()
            assert release.wait(timeout=2.0)
        active -= 1
        return True, "runtime current"

    controller._materialize_clamav_runtime_files_locked = materialize
    controller._reconfigure_squid_locked = lambda **_kwargs: (
        events.append("reload") or (True, "reconfigured")
    )
    original_persist = controller._persist_good_config
    controller._persist_good_config = lambda text: (
        events.append("persist") or original_persist(text)
    )

    results: list[tuple[bool, str]] = []
    first = threading.Thread(
        target=lambda: results.append(
            controller.apply_config_text("workers 1\n# first\n"),
        ),
        daemon=True,
    )
    second = threading.Thread(
        target=lambda: results.append(
            controller.apply_config_text("workers 1\n# second\n"),
        ),
        daemon=True,
    )
    first.start()
    assert entered.wait(timeout=1.0)
    second.start()
    assert "materialize:second" not in events
    release.set()
    first.join(timeout=2.0)
    second.join(timeout=2.0)

    assert not first.is_alive()
    assert not second.is_alive()
    assert max_active == 1
    assert events == [
        "materialize:first",
        "reload",
        "persist",
        "materialize:second",
        "reload",
        "persist",
    ]
    assert all(ok for ok, _detail in results)
    assert "# second" in squid_conf.read_text(encoding="utf-8")
    assert "# second" in persisted_conf.read_text(encoding="utf-8")


def test_squid_controller_apply_restores_config_and_runtime_after_mutation_error(
    tmp_path,
) -> None:
    from services.squid_core import SquidController  # type: ignore

    squid_conf = tmp_path / "squid.conf"
    persisted_conf = tmp_path / "persisted.conf"
    squid_conf.write_text("workers 1\n# current\n", encoding="utf-8")
    persisted_conf.write_text("workers 1\n# current\n", encoding="utf-8")
    controller = SquidController(str(squid_conf))
    controller.persisted_squid_conf_path = str(persisted_conf)
    controller.normalize_config_text = lambda text: text
    controller.validate_config_text = lambda _text: (True, "validated")
    state = {"runtime": "current"}

    def fail_after_runtime_mutation(_text, **_kwargs):
        state["runtime"] = "candidate"
        return False, "runtime mutation failed"

    controller._materialize_clamav_runtime_files_locked = fail_after_runtime_mutation
    controller._snapshot_runtime_file = lambda _path: state["runtime"]
    controller._snapshot_managed_icap_runtime_files = lambda: {
        "runtime": state["runtime"],
    }
    controller._restore_runtime_file_snapshot = lambda _path, snapshot: state.update(
        runtime=snapshot,
    )
    controller._restore_managed_icap_runtime_files = lambda snapshot: state.update(
        runtime=snapshot["runtime"],
    )
    controller._supervisor_reread_update = lambda: (True, "runtime restored")

    def restore_after_runtime_failure(**_kwargs):
        squid_conf.write_text("workers 1\n# current\n", encoding="utf-8")
        return False, "rolled back"

    controller._restore_last_known_good_config_locked = restore_after_runtime_failure

    ok, detail = controller.apply_config_text("workers 1\n# candidate\n")

    assert ok is False
    assert "rolled back" in detail
    assert state["runtime"] == "current"
    assert squid_conf.read_text(encoding="utf-8") == "workers 1\n# current\n"
    assert persisted_conf.read_text(encoding="utf-8") == "workers 1\n# current\n"


def test_squid_controller_apply_persist_failure_rolls_back_active_transaction(
    tmp_path,
) -> None:
    from services.squid_core import SquidController  # type: ignore

    squid_conf = tmp_path / "squid.conf"
    persisted_conf = tmp_path / "persisted.conf"
    squid_conf.write_text("workers 1\n# current\n", encoding="utf-8")
    persisted_conf.write_text("workers 1\n# current\n", encoding="utf-8")
    controller = SquidController(str(squid_conf))
    controller.persisted_squid_conf_path = str(persisted_conf)
    controller.normalize_config_text = lambda text: text
    controller.validate_config_text = lambda _text: (True, "validated")
    controller._materialize_clamav_runtime_files_locked = lambda *_args, **_kwargs: (
        True,
        "runtime current",
    )
    controller._reconfigure_squid_locked = lambda **_kwargs: (True, "reconfigured")
    controller._persist_good_config = lambda _text: (_ for _ in ()).throw(
        OSError("persist failed"),
    )
    rollback_calls: list[str] = []

    def rollback(*, reason, fallback_config):
        rollback_calls.append(reason)
        squid_conf.write_text(fallback_config, encoding="utf-8")
        return False, "restored pre-change config after persist failure"

    controller._restore_last_known_good_config_locked = rollback

    ok, detail = controller.apply_config_text("workers 1\n# candidate\n")

    assert ok is False
    assert rollback_calls
    assert rollback_calls[0]
    assert "restored pre-change" in detail
    assert squid_conf.read_text(encoding="utf-8") == "workers 1\n# current\n"
    assert persisted_conf.read_text(encoding="utf-8") == "workers 1\n# current\n"


def test_squid_controller_atomic_write_preserves_existing_file_mode(tmp_path) -> None:
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
    from services.squid_core import SquidController  # type: ignore

    target = tmp_path / "conf.d" / "20-icap.conf"

    controller = SquidController(str(tmp_path / "squid.conf"))
    controller._atomic_write_file(str(target), "include\n")

    assert target.read_text(encoding="utf-8") == "include\n"
    assert target.stat().st_mode & 0o777 == 0o644


@pytest.mark.parametrize(
    "method_name",
    [
        "materialize_clamav_runtime_files",
        "reconfigure_squid",
        "restart_squid",
        "clear_disk_cache",
    ],
)
@pytest.mark.parametrize("journal_content", ["dirty", "{not-json"])
def test_public_squid_mutators_refuse_dirty_or_corrupt_journal(
    tmp_path,
    monkeypatch,
    method_name,
    journal_content,
) -> None:
    from services.squid_core import SquidController  # type: ignore
    from services.squid_transaction import SquidTransactionJournal  # type: ignore

    active = tmp_path / "squid.conf"
    persisted = tmp_path / "persisted.conf"
    journal_path = tmp_path / "transaction.json"
    active.write_text("workers 1\n", encoding="utf-8")
    persisted.write_text("workers 1\n", encoding="utf-8")
    monkeypatch.setenv("SQUID_TRANSACTION_JOURNAL_PATH", str(journal_path))
    controller = SquidController(str(active))
    controller.persisted_squid_conf_path = str(persisted)
    if journal_content == "dirty":
        SquidTransactionJournal(
            journal_path,
            active_config=active,
            persisted_config=persisted,
        ).begin("prior", intended_phase="ready")
    else:
        journal_path.write_text(journal_content, encoding="utf-8")
    controller._run = lambda *_args, **_kwargs: pytest.fail("mutation executed")

    method = getattr(controller, method_name)
    result = (
        method("workers 1\n")
        if method_name == "materialize_clamav_runtime_files"
        else method()
    )

    assert result[0] is False
    assert "journal" in result[1].lower()


def test_apply_uses_structured_restart_evidence_not_detail_prose(tmp_path) -> None:
    from services.squid_core import (  # type: ignore
        SquidController,
        SquidRuntimeMaterializationResult,
    )

    active = tmp_path / "squid.conf"
    persisted = tmp_path / "persisted.conf"
    active.write_text("workers 1\n# old\n", encoding="utf-8")
    controller = SquidController(str(active))
    controller.persisted_squid_conf_path = str(persisted)
    controller.normalize_config_text = lambda text: text
    controller.validate_config_text = lambda _text: (True, "validated")
    controller._materialize_clamav_runtime_files_locked = lambda *_a, **_k: (
        SquidRuntimeMaterializationResult(
            True,
            "Runtime topology converged without legacy restart wording.",
            squid_restarted=True,
            changed=True,
        )
    )
    controller._reconfigure_squid_locked = lambda **_kwargs: pytest.fail(
        "structured restart evidence should suppress reconfigure"
    )

    ok, detail = controller.apply_config_text("workers 1\n# new\n")

    assert ok is True
    assert "legacy restart wording" in detail


def test_transaction_manifest_covers_worker_expansion_and_shrink(tmp_path) -> None:
    from services.squid_core import SquidController  # type: ignore

    active = tmp_path / "squid.conf"
    active.write_text("workers 1\n", encoding="utf-8")
    controller = SquidController(str(active))
    controller._icap_include_path = lambda: tmp_path / "20-icap.conf"
    controller._virus_scan_config_path = lambda: tmp_path / "virus.conf"
    controller._managed_icap_runtime_paths = list
    controller._render_icap_supervisor_files = lambda *, workers, config_text=None: {
        tmp_path / f"worker-{workers}.conf": "contents"
    }

    paths = set(controller._transaction_runtime_paths("workers 4\n"))

    assert {tmp_path / f"worker-{worker}.conf" for worker in range(1, 5)} <= paths


def test_runtime_icap_materialization_matches_startup_parity_contract(
    tmp_path,
    monkeypatch,
    request,
) -> None:
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
    from services.squid_core import SquidController  # type: ignore

    controller = SquidController.__new__(SquidController)
    calls: list[object] = []

    controller.squid_conf_path = str(tmp_path / "squid.conf")
    controller.persisted_squid_conf_path = str(tmp_path / "persisted.conf")
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
        calls.append(("restart_squid_locked", kwargs))
        return (
            True,
            "Squid HTTP listener is accepting connections and ICAP readiness is green.",
        )

    controller._restart_squid_locked = restart_squid

    ok, detail = controller.materialize_clamav_runtime_files(
        "workers 1\nhttp_port 3128\n",
        adblock_enabled=True,
    )

    assert ok is True
    assert (
        "restart_squid_locked",
        {"ready_timeout": 75.0, "require_http_response": False},
    ) in calls
    assert "Squid restarted after ICAP supervisor update." in detail


def test_squid_controller_validation_timeout_returns_actionable_detail(
    tmp_path,
) -> None:
    from services.squid_core import SquidController  # type: ignore

    def fake_run(args, **_kwargs) -> NoReturn:
        raise subprocess.TimeoutExpired(args, timeout=15)

    controller = SquidController(str(tmp_path / "squid.conf"), cmd_run=fake_run)

    ok, detail = controller.validate_config_text("workers 1\n")

    assert ok is False
    assert detail == "Squid config validation timed out after 15 seconds."


def test_squid_controller_rollback_fails_closed_when_validation_times_out(
    tmp_path,
) -> None:
    from services.squid_core import SquidController  # type: ignore

    squid_conf = tmp_path / "squid.conf"
    persisted_conf = tmp_path / "persisted.conf"
    squid_conf.write_text("workers 1\n# current\n", encoding="utf-8")
    persisted_conf.write_text("workers 1\n# prior\n", encoding="utf-8")

    controller = SquidController(str(squid_conf))
    controller.persisted_squid_conf_path = str(persisted_conf)
    controller.validate_config_text = lambda _text: (
        False,
        "Squid config validation timed out after 15 seconds.",
    )
    controller.restart_squid = lambda: (_ for _ in ()).throw(
        AssertionError("unvalidated rollback material must not be started"),
    )

    ok, detail = controller.restore_last_known_good_config(reason="operator rollback")

    assert ok is False
    assert "could not be validated; rollback was not applied" in detail
    assert "timed out" in detail
    assert squid_conf.read_text(encoding="utf-8") == "workers 1\n# current\n"
    assert persisted_conf.read_text(encoding="utf-8") == "workers 1\n# prior\n"


def test_squid_controller_extracts_all_http_listener_ports(tmp_path) -> None:
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


def test_sync_adblock_state_changed_artifact_refreshes_helpers_without_squid_stop(
    tmp_path,
    monkeypatch,
) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    compiled = tmp_path / "compiled"
    compiled.mkdir()
    (compiled / ".artifact-sha256").write_text("old-sha", encoding="utf-8")
    _write_adblock_lookup_metadata(compiled / "request_lookup.sqlite", count_rules=0)
    recorded: list[dict[str, object]] = []
    supervisor_calls: list[list[str]] = []
    started: set[str] = set()
    monkeypatch.delenv("SQUID_WORKERS", raising=False)
    monkeypatch.delenv("WORKERS", raising=False)

    class Artifacts:
        compiled_dir = str(compiled)

        def get_active_artifact_metadata(self):
            return SimpleNamespace(revision_id=43, artifact_sha256="new-sha")

        def get_active_artifact_summary(self):
            return SimpleNamespace(report={})

        def get_active_artifact(self):
            return SimpleNamespace(
                revision_id=43,
                artifact_sha256="new-sha",
                archive_blob=b"archive",
            )

        def record_apply_result(self, proxy_id, revision_id, **kwargs):
            recorded.append(
                {"proxy_id": proxy_id, "revision_id": revision_id, **kwargs}
            )
            return SimpleNamespace(application_id=43)

    class Store:
        def init_db(self) -> None:
            pass

        def get_cache_flush_requested(self) -> bool:
            return False

    class Controller:
        def restart_squid(self, **_kwargs) -> NoReturn:
            msg = "changed adblock artifact must not restart Squid"
            raise AssertionError(msg)

        def _restart_squid_locked(self, **_kwargs) -> NoReturn:
            msg = "changed adblock artifact must not restart Squid"
            raise AssertionError(msg)

        def _run(self, args, **_kwargs) -> NoReturn:
            msg = f"changed adblock artifact must not stop Squid: {args}"
            raise AssertionError(msg)

    def fake_materialize(directory, *, archive_blob, artifact_sha256) -> None:
        root = Path(directory)
        root.mkdir(parents=True, exist_ok=True)
        (root / ".artifact-sha256").write_text(artifact_sha256, encoding="utf-8")
        (root / "request_lookup.sqlite").unlink(missing_ok=True)
        _write_adblock_lookup_metadata(root / "request_lookup.sqlite", count_rules=0)

    def fake_run(args, **_kwargs):
        supervisor_calls.append(list(args))
        action = args[3]
        program = args[4] if len(args) > 4 else None
        assert program != "squid"
        if action == "status" and program is None:
            return _cp(0, stdout="")
        if action == "stop":
            started.discard(program)
            return _cp(0, stdout=f"{program}: stopped")
        if action == "status":
            state = (
                "RUNNING pid 42, uptime 0:00:01"
                if program in started
                else "STOPPED Jul 25 10:25 PM"
            )
            return _cp(0, stdout=f"{program} {state}\n")
        if action == "start":
            started.add(program)
            return _cp(0, stdout=f"{program}: started")
        raise AssertionError(args)

    monkeypatch.setattr(runtime_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(runtime_module.subprocess, "run", fake_run)
    monkeypatch.setattr(
        runtime_module,
        "materialize_archive_to_directory",
        fake_materialize,
    )
    monkeypatch.setattr(
        runtime_module,
        "_check_icap_adblock",
        lambda **_kwargs: {"ok": True, "detail": "adblock ICAP healthy"},
    )

    runtime = _runtime_shell()
    runtime.controller = Controller()
    runtime.services = SimpleNamespace(
        current_adblock_sha_reader=lambda: "old-sha",
        adblock_service_restarter=None,
    )
    runtime.adblock_artifacts = Artifacts()
    runtime.adblock_store = Store()
    runtime.adblock_compiled_dir = str(compiled)

    result = runtime.sync_adblock_state(force=True)

    assert result["ok"] is True
    assert result["artifact_changed"] is True
    assert result["current_adblock_artifact_sha256"] == "new-sha"
    assert recorded[-1]["ok"] is True
    assert not any(call[3:] == ["stop", "squid"] for call in supervisor_calls)
    assert not any("squid" in call for call in supervisor_calls)
    assert [call[3:] for call in supervisor_calls] == [
        ["stop", "cicap_adblock"],
        ["status", "cicap_adblock"],
        ["start", "cicap_adblock"],
        ["status", "cicap_adblock"],
    ]


def test_sync_adblock_state_cache_flush_refreshes_helpers_without_squid_stop(
    monkeypatch,
) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    recorded: list[dict[str, object]] = []
    supervisor_calls: list[list[str]] = []
    started: set[str] = set()
    monkeypatch.delenv("SQUID_WORKERS", raising=False)
    monkeypatch.delenv("WORKERS", raising=False)

    class Artifacts:
        def get_active_artifact_metadata(self):
            return SimpleNamespace(revision_id=44, artifact_sha256="same-sha")

        def get_active_artifact(self) -> NoReturn:
            msg = "cache flush should not fetch the active artifact archive"
            raise AssertionError(msg)

        def record_apply_result(self, proxy_id, revision_id, **kwargs):
            recorded.append(
                {"proxy_id": proxy_id, "revision_id": revision_id, **kwargs}
            )
            return SimpleNamespace(application_id=44)

    class Store:
        def init_db(self) -> None:
            pass

        def get_cache_flush_requested(self) -> bool:
            return True

        def mark_cache_flushed(self, *, size=0) -> None:
            recorded.append({"cache_flushed_size": size})

    class Controller:
        def restart_squid(self, **_kwargs) -> NoReturn:
            msg = "adblock cache flush must not restart Squid"
            raise AssertionError(msg)

        def _restart_squid_locked(self, **_kwargs) -> NoReturn:
            msg = "adblock cache flush must not restart Squid"
            raise AssertionError(msg)

        def _run(self, args, **_kwargs) -> NoReturn:
            msg = f"adblock cache flush must not stop Squid: {args}"
            raise AssertionError(msg)

    def fake_run(args, **_kwargs):
        supervisor_calls.append(list(args))
        action = args[3]
        program = args[4] if len(args) > 4 else None
        assert program != "squid"
        if action == "status" and program is None:
            return _cp(0, stdout="")
        if action == "stop":
            started.discard(program)
            return _cp(0, stdout=f"{program}: stopped")
        if action == "status":
            state = (
                "RUNNING pid 42, uptime 0:00:01"
                if program in started
                else "STOPPED Jul 25 10:25 PM"
            )
            return _cp(0, stdout=f"{program} {state}\n")
        if action == "start":
            started.add(program)
            return _cp(0, stdout=f"{program}: started")
        raise AssertionError(args)

    monkeypatch.setattr(runtime_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(runtime_module.subprocess, "run", fake_run)
    monkeypatch.setattr(
        runtime_module,
        "_check_icap_adblock",
        lambda **_kwargs: {"ok": True, "detail": "adblock ICAP healthy"},
    )

    runtime = _runtime_shell()
    runtime.controller = Controller()
    runtime.services = SimpleNamespace(
        current_adblock_sha_reader=lambda: "same-sha",
        adblock_service_restarter=None,
    )
    runtime.adblock_artifacts = Artifacts()
    runtime.adblock_store = Store()

    result = runtime.sync_adblock_state(force=False)

    assert result["ok"] is True
    assert result["artifact_changed"] is False
    assert result["cache_flushed"] is True
    assert recorded[-1]["ok"] is True
    assert not any(call[3:] == ["stop", "squid"] for call in supervisor_calls)
    assert not any("squid" in call for call in supervisor_calls)


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


def test_sync_adblock_state_refreshes_stale_apply_for_current_artifact() -> None:
    recorded = []

    class Artifacts:
        def get_active_artifact_metadata(self):
            return SimpleNamespace(revision_id=42, artifact_sha256="same-sha")

        def get_active_artifact(
            self,
        ) -> NoReturn:  # pragma: no cover - should not be reached
            msg = "current artifact should not be fetched for a ledger refresh"
            raise AssertionError(msg)

        def latest_apply(self, _proxy_id, *, revision_id=None):
            assert revision_id == 42
            return SimpleNamespace(
                application_id=10,
                revision_id=42,
                ok=False,
                artifact_sha256="same-sha",
            )

        def record_apply_result(self, proxy_id, revision_id, **kwargs):
            recorded.append(
                {"proxy_id": proxy_id, "revision_id": revision_id, **kwargs}
            )
            return SimpleNamespace(application_id=12)

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

    assert result["ok"] is True
    assert result["changed"] is False
    assert result["application_id"] == 12
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


def test_collect_clamav_health_uses_bounded_cache_and_force_refreshes() -> None:
    runtime = _runtime_shell()
    runtime.health_cache_ttl_seconds = 60.0
    runtime._health_cache_lock = threading.Lock()
    runtime._clamav_health_cache_ts = 0.0
    runtime._clamav_health_cache_value = None
    runtime._current_config_sha = lambda: "config-sha"
    calls = {"runtime_services": 0}

    def runtime_services_builder(**_kwargs):
        calls["runtime_services"] += 1
        return {
            "clamd": {"ok": True, "detail": "clamd healthy"},
            "av_icap": {"ok": True, "detail": "av healthy"},
            "clamav": {"ok": True, "detail": "clamav healthy"},
        }

    runtime.runtime_services_builder = runtime_services_builder

    first = runtime.collect_clamav_health()
    second = runtime.collect_clamav_health()
    forced = runtime.collect_clamav_health(force=True)

    assert first is second
    assert forced is not first
    assert first["health_scope"] == "clamav"
    assert first["current_config_sha"] == "config-sha"
    assert calls["runtime_services"] == 2


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


def test_squid_transaction_health_reports_recovery_required(
    tmp_path, monkeypatch
) -> None:
    import proxy.runtime as runtime_module  # type: ignore
    from proxy.runtime import ProxyRuntime  # type: ignore

    active = tmp_path / "active.conf"
    persisted = tmp_path / "persisted.conf"
    active.write_text("candidate\n", encoding="utf-8")
    persisted.write_text("last known good\n", encoding="utf-8")
    journal_path = tmp_path / "transaction.json"
    journal = runtime_module.SquidTransactionJournal(
        journal_path,
        active_config=active,
        persisted_config=persisted,
    )
    journal.begin("apply_config_text", intended_phase="ready")
    monkeypatch.setenv("SQUID_TRANSACTION_JOURNAL_PATH", str(journal_path))

    runtime = ProxyRuntime.__new__(ProxyRuntime)
    runtime.controller = SimpleNamespace(
        squid_conf_path=str(active),
        persisted_squid_conf_path=str(persisted),
    )

    result = ProxyRuntime._squid_transaction_health(runtime)

    assert result["ok"] is False
    assert result["ready"] is False
    assert result["status"] == "in_progress"
    assert result["operation"] == "apply_config_text"
    assert result["transaction_id"]
    assert "reconciliation is required" in result["detail"]


@pytest.mark.parametrize(
    ("listener_result", "expected_ok", "expected_detail"),
    [
        (True, True, "explicit:3128"),
        (False, False, "Squid listener(s) not accepting connections."),
    ],
)
def test_squid_listener_health_reports_probe_result_truthfully(
    listener_result, expected_ok, expected_detail
) -> None:
    runtime = _runtime_shell()
    runtime.controller = SimpleNamespace(
        _http_listener_details=lambda: ({"port": 3128, "mode": "explicit"},),
        _wait_for_http_listener=lambda *, timeout: listener_result,
    )

    result = runtime._squid_listener_health(timeout=0.5)

    assert result["ok"] is expected_ok
    assert expected_detail in result["detail"]
    assert result["listeners"] == [{"port": 3128, "mode": "explicit"}]
    assert result["ports"] == [3128]


@pytest.mark.parametrize("failure_stage", ["discovery", "probe"])
def test_navigation_health_degrades_when_listener_inspection_raises(
    failure_stage,
) -> None:
    secret = "postgresql://operator:do-not-leak@example.invalid/runtime"

    def listener_details():
        if failure_stage == "discovery":
            raise RuntimeError(secret)
        return ({"port": 3128, "mode": "explicit"},)

    def listener_probe(*, timeout):
        if failure_stage == "probe":
            raise RuntimeError(secret)
        return True

    runtime = _runtime_shell()
    runtime.health_cache_ttl_seconds = 0.0
    runtime._health_cache_lock = threading.Lock()
    runtime.controller = SimpleNamespace(
        get_status=lambda: (b"squid ok", b""),
        _http_listener_details=listener_details,
        _wait_for_http_listener=listener_probe,
    )
    runtime._current_config_sha = lambda: "config-sha"
    runtime._supervisor_programs_health = lambda: {"ok": True, "detail": "ok"}

    result = runtime.collect_navigation_health(force=True)

    listeners = result["services"]["squid_listeners"]
    assert result["ok"] is False
    assert result["status"] == "degraded"
    assert listeners["ok"] is False
    assert "failed; listener health is unavailable" in listeners["detail"]
    assert secret not in str(result)


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
    assert result["services"]["squid_transaction"]["ready"] is True


def test_collect_navigation_health_degrades_when_squid_transaction_is_dirty() -> None:
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
    runtime._squid_transaction_health = lambda: {
        "ok": False,
        "ready": False,
        "status": "recovery_required",
        "detail": "Squid transaction reconciliation is required before mutations may proceed.",
        "transaction_id": "transaction-1",
    }

    result = runtime.collect_navigation_health(force=True)

    assert result["ok"] is False
    assert result["status"] == "degraded"
    assert result["services"]["squid_transaction"]["ready"] is False
    assert result["services"]["squid_transaction"]["transaction_id"] == (
        "transaction-1"
    )


def test_navigation_health_cache_invalidates_when_transaction_becomes_dirty() -> None:
    runtime = _runtime_shell()
    transaction = {
        "ok": True,
        "ready": True,
        "status": "complete",
        "detail": "reconciled",
    }
    runtime._squid_transaction_health = lambda: dict(transaction)
    runtime.health_cache_ttl_seconds = 60.0
    runtime._health_cache_lock = threading.Lock()
    runtime._navigation_health_cache_value = None
    runtime._navigation_health_cache_ts = 0.0
    runtime.controller = SimpleNamespace(
        get_status=lambda: (b"squid ok", b""),
        _http_listener_details=lambda: ({"port": 3128, "mode": "explicit"},),
        _wait_for_http_listener=lambda *, timeout: True,
    )
    runtime._current_config_sha = lambda: "unchanged-sha"
    runtime._supervisor_programs_health = lambda: {"ok": True, "detail": "ok"}

    assert runtime.collect_navigation_health()["ok"] is True
    transaction.update(
        ok=False,
        ready=False,
        status="unreadable",
        detail="journal corrupt",
    )
    degraded = runtime.collect_navigation_health()

    assert degraded["ok"] is False
    assert degraded["services"]["squid_transaction"]["status"] == "unreadable"


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


def test_local_runtime_service_health_bounds_non_cooperative_probe_workers(
    monkeypatch,
) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    executor = runtime_module.ThreadPoolExecutor(
        max_workers=3,
        thread_name_prefix="test-proxy-health",
    )
    release = threading.Event()
    started = 0
    started_lock = threading.Lock()

    def stuck_probe(**_kwargs):
        nonlocal started
        with started_lock:
            started += 1
        release.wait(timeout=10.0)
        return {"ok": True, "detail": "late"}

    monkeypatch.setattr(runtime_module, "_LOCAL_HEALTH_EXECUTOR", executor)
    monkeypatch.setattr(runtime_module, "_check_icap_adblock", stuck_probe)
    monkeypatch.setattr(runtime_module, "_check_icap_av", stuck_probe)
    monkeypatch.setattr(runtime_module, "_check_clamd", stuck_probe)
    monkeypatch.setattr(
        runtime_module,
        "_check_forwarding",
        lambda **_kwargs: {"ok": True, "detail": "forwarding ok"},
    )

    try:
        for _ in range(2):
            result = runtime_module.build_local_runtime_services(
                icap_timeout=0.01,
                tcp_timeout=0.01,
            )
            assert all(not result[name]["ok"] for name in ("icap", "av_icap", "clamd"))

        assert started == 3
        assert len(executor._threads) == 3
    finally:
        release.set()
        executor.shutdown(wait=True, cancel_futures=True)


def test_supervisor_programs_health_uses_single_status_call(monkeypatch) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    monkeypatch.delenv("SQUID_WORKERS", raising=False)
    monkeypatch.delenv("WORKERS", raising=False)
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


def test_adblock_artifact_refresh_keeps_squid_listener_running() -> None:
    runtime = _runtime_shell()
    calls: list[object] = []

    class Controller:
        def _supervisor_program_running(self, program):
            msg = f"adblock refresh should not inspect {program} supervisor state"
            raise AssertionError(msg)

        def _run(self, args, **_kwargs):
            msg = f"adblock refresh should not run Squid command: {args}"
            raise AssertionError(msg)

        def _decode_completed(self, proc):
            return (proc.stdout or b"").decode().strip()

        def _wait_for_http_listener_absent(self, *, timeout):
            msg = "adblock refresh should not wait for the Squid listener to close"
            raise AssertionError(msg)

        def _wait_for_icap_readiness(self, *, timeout):
            msg = "helper refresh performs its own adblock ICAP health gate"
            raise AssertionError(msg)

        def restart_squid(self, *, ready_timeout):
            msg = "adblock refresh must not call public Squid restart"
            raise AssertionError(msg)

        def _restart_squid_locked(self, *, ready_timeout):
            msg = "adblock refresh must not call locked Squid restart"
            raise AssertionError(msg)

    runtime.controller = Controller()
    runtime._restart_adblock_service = lambda: (
        calls.append("adblock_restart") or (True, "adblock restarted")
    )

    ok, detail = runtime._refresh_adblock_service_without_squid_restart()

    assert ok is True
    assert calls == ["adblock_restart"]
    assert "adblock restarted" in detail


def test_adblock_refresh_uses_lifecycle_lock_without_squid_restart(
    monkeypatch,
) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    lock_state = {"held": False}

    @contextlib.contextmanager
    def detecting_lifecycle_lock():
        if lock_state["held"]:
            msg = "recursive Squid lifecycle lock acquisition would deadlock"
            raise AssertionError(msg)
        lock_state["held"] = True
        calls.append("lifecycle_enter")
        try:
            yield
        finally:
            calls.append("lifecycle_exit")
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
            msg = f"adblock refresh should not inspect {program} supervisor state"
            raise AssertionError(msg)

        def _run(self, args, **_kwargs):
            msg = f"adblock refresh should not run Squid command: {args}"
            raise AssertionError(msg)

        def _decode_completed(self, proc):
            return (proc.stdout or b"").decode().strip()

        def _wait_for_http_listener_absent(self, *, timeout):
            msg = "adblock refresh should not wait for the Squid listener to close"
            raise AssertionError(msg)

        def restart_squid(self, *, ready_timeout):
            msg = "adblock refresh must not call public Squid restart"
            raise AssertionError(msg)

        def _restart_squid_locked(self, *, ready_timeout):
            msg = "adblock refresh must not call locked Squid restart"
            raise AssertionError(msg)

    runtime.controller = Controller()

    def refresh_helper() -> tuple[bool, str]:
        assert lock_state["held"] is True
        calls.append("adblock_restart")
        return True, "adblock restarted"

    runtime._restart_adblock_service = refresh_helper

    def invoke_restart() -> None:
        ok, detail = runtime._refresh_adblock_service_without_squid_restart()
        result["ok"] = ok
        result["detail"] = detail

    thread = threading.Thread(target=invoke_restart, daemon=True)
    thread.start()
    thread.join(timeout=1.0)

    assert not thread.is_alive()
    assert result == {
        "ok": True,
        "detail": "adblock restarted",
    }
    assert calls == ["lifecycle_enter", "adblock_restart", "lifecycle_exit"]


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
            msg = f"adblock refresh should not inspect {program} supervisor state"
            raise AssertionError(msg)

        def _run(self, args, **_kwargs):
            msg = f"adblock refresh should not run Squid command: {args}"
            raise AssertionError(msg)

        def _decode_completed(self, proc):
            return (proc.stdout or b"").decode().strip()

        def _wait_for_http_listener_absent(self, *, timeout):
            msg = "adblock refresh should not wait for the Squid listener to close"
            raise AssertionError(msg)

        def _wait_for_icap_readiness(self, *, timeout):
            msg = "Squid restart wrapper should own the ICAP readiness gate"
            raise AssertionError(msg)

        def restart_squid(self, *, ready_timeout):
            msg = "public restart_squid must not be called while lifecycle lock is held"
            raise AssertionError(msg)

        def _restart_squid_locked(self, *, ready_timeout):
            msg = "adblock refresh must not call locked Squid restart"
            raise AssertionError(msg)

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
                runtime._refresh_adblock_service_without_squid_restart()
            )
            result = {**result, "ok": ok_restart, "detail": restart_detail}
        return result

    runtime._restart_adblock_service = lambda: (
        calls.append("adblock_restart") or (True, "adblock restarted")
    )
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
        "adblock_restart",
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

    assert "from services.squid_listeners import" in healthcheck
    assert "Squid listener(s) not accepting connections" in healthcheck


def test_packaged_proxy_healthcheck_normalizes_forwarding_canary_path_like_runtime() -> (
    None
):
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
    assert (
        _entrypoint_forwarding_canary_path(FORWARDING_CANARY_PATH="/custom-canary")
        == "/custom-canary"
    )


@pytest.mark.parametrize(
    "unsafe_path",
    [" /custom-canary", "/custom canary", "/custom\tcanary", "/custom\x7fcanary"],
    ids=["leading-space", "embedded-space", "tab", "delete-control"],
)
def test_packaged_proxy_scripts_reject_unsafe_forwarding_canary_path(
    unsafe_path: str,
) -> None:
    default_path = "/__docker_proxy_forwarding_canary"
    default_url = f"http://127.0.0.1:18080{default_path}?probe=squid-respmod"

    assert (
        _healthcheck_forwarding_canary_url(FORWARDING_CANARY_PATH=unsafe_path)
        == default_url
    )
    assert (
        _entrypoint_forwarding_canary_path(FORWARDING_CANARY_PATH=unsafe_path)
        == default_path
    )


def test_packaged_proxy_healthcheck_normalizes_forwarding_canary_listener_port() -> (
    None
):
    repo_root = Path(__file__).resolve().parents[2]
    healthcheck = (repo_root / "docker" / "healthcheck.sh").read_text(
        encoding="utf-8",
    )

    assert 'has_listen_socket "$(forwarding_canary_port)"' in healthcheck
    assert (
        _healthcheck_forwarding_canary_port(FORWARDING_CANARY_PORT="18081") == "18081"
    )
    assert (
        _healthcheck_forwarding_canary_port(FORWARDING_CANARY_PORT="not-a-port")
        == "18080"
    )
    assert _healthcheck_forwarding_canary_port(FORWARDING_CANARY_PORT="0") == "18080"
    assert (
        _healthcheck_forwarding_canary_port(FORWARDING_CANARY_PORT="65536") == "18080"
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
    assert "ADBLOCK_BYPASS=on" in entrypoint
    assert 'env_enabled "${ADBLOCK_ICAP_REQUIRED:-}"' in entrypoint
    assert "ADBLOCK_BYPASS=off" in entrypoint
    assert "bypass=${ADBLOCK_BYPASS}" in entrypoint


def test_runtime_adblock_supervisor_config_matches_startup_readiness_contract() -> None:
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


def test_runtime_icap_include_honors_explicit_required_adblock_mode(
    monkeypatch,
) -> None:
    from services.squid_core import SquidController  # type: ignore

    monkeypatch.setenv("ADBLOCK_ICAP_REQUIRED", "strict")

    include = SquidController()._render_icap_include("workers 1\n")

    assert "icap://127.0.0.1:14000/adblockreq bypass=off" in include


def test_runtime_adblock_routing_defaults_off_and_honors_explicit_opt_in(
    monkeypatch,
) -> None:
    from services.squid_core import SquidController  # type: ignore

    monkeypatch.delenv("ADBLOCK_ENABLED", raising=False)
    assert SquidController()._adblock_routing_enabled is False

    monkeypatch.setenv("ADBLOCK_ENABLED", "1")
    assert SquidController()._adblock_routing_enabled is True

    monkeypatch.setenv("ADBLOCK_ENABLED", "0")
    assert SquidController()._adblock_routing_enabled is False


def test_runtime_security_flags_fail_safe_on_malformed_values(monkeypatch) -> None:
    from services.squid_core import SquidController, _clamav_required_from_env

    monkeypatch.setenv("CLAMAV_REQUIRED", "typo")
    monkeypatch.setenv("ADBLOCK_ENABLED", "typo")
    monkeypatch.setenv("ADBLOCK_ICAP_REQUIRED", "typo")

    controller = SquidController()
    include = controller._render_icap_include("workers 1\n")

    assert _clamav_required_from_env() is True
    assert controller._adblock_routing_enabled is True
    assert "icap://127.0.0.1:14000/adblockreq bypass=off" in include


def test_packaged_security_flags_fail_safe_on_malformed_values() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    entrypoint = (repo_root / "docker" / "entrypoint.sh").read_text(encoding="utf-8")
    healthcheck = (repo_root / "docker" / "healthcheck.sh").read_text(encoding="utf-8")

    assert 'env_enabled "$CLAMAV_REQUIRED_RAW" 1' in entrypoint
    assert 'ADBLOCK_ENABLED_RAW="${ADBLOCK_ENABLED:-0}"' in entrypoint
    assert 'env_enabled "$ADBLOCK_ENABLED_RAW" 1' in entrypoint
    assert 'env_enabled "${ADBLOCK_ICAP_REQUIRED:-}" 1' in entrypoint
    assert 'env_enabled "${CLAMAV_REQUIRED:-}" 1' in healthcheck
    assert 'env_enabled "${ADBLOCK_ICAP_REQUIRED:-}" 1' in healthcheck


def test_packaged_startup_file_policy_keeps_upload_scanning_off() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    entrypoint = (repo_root / "docker" / "entrypoint.sh").read_text(encoding="utf-8")
    generated_policy = entrypoint.split(
        'echo "acl file_security_upload_methods method POST PUT PATCH"', 1
    )[1].split("} > /etc/squid/conf.d/20-icap.conf", 1)[0]

    assert "adaptation_access av_req_set deny all" in generated_policy
    assert "adaptation_access av_req_set allow file_security_upload_methods" not in (
        generated_policy
    )
    assert "http_access deny file_security_risky_path" not in generated_policy
    assert "http_access deny file_security_executable_path" not in generated_policy
    assert "http_access deny file_security_executable_mime" not in generated_policy


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


def test_squid_reload_treats_successful_stderr_warnings_as_detail(tmp_path) -> None:
    from services.squid_core import SquidController  # type: ignore

    controller = SquidController.__new__(SquidController)
    controller.squid_conf_path = str(tmp_path / "squid.conf")
    controller.persisted_squid_conf_path = str(tmp_path / "persisted.conf")
    controller._run = lambda *_args, **_kwargs: _cp(
        0, stdout="", stderr="WARNING: benign squid warning"
    )
    controller._wait_for_http_listener = lambda **_kwargs: True

    stdout, stderr = controller.reload_squid()

    assert stderr == b""
    assert b"WARNING: benign squid warning" in stdout


def test_squid_reload_preserves_nonzero_reconfigure_failure(tmp_path) -> None:
    from services.squid_core import SquidController  # type: ignore

    controller = SquidController.__new__(SquidController)
    controller.squid_conf_path = str(tmp_path / "squid.conf")
    controller.persisted_squid_conf_path = str(tmp_path / "persisted.conf")
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
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    monkeypatch.setattr(runtime_module, "get_proxy_id", lambda: "edge-a")
    op = SimpleNamespace(operation_id=5, target_kind="", target_ref="")
    calls: list[tuple[str, object]] = []

    class Ledger:
        def requeue_stale_applying(self, proxy_id, **kwargs) -> None:
            calls.append(("requeue", (proxy_id, kwargs)))

        def claim_pending(self, proxy_id, *, limit, operation_id=None, **kwargs):
            calls.append(("claim", (proxy_id, limit, operation_id, kwargs)))
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
        ("requeue", ("edge-a", {"allow_alias": False})),
        ("claim", ("edge-a", 100, None, {"allow_alias": False})),
        ("mark", (5, "applied", "runtime reconciled")),
    ]


def test_sync_from_db_claims_runtime_operations_with_exact_live_identity(
    monkeypatch,
) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    monkeypatch.setattr(runtime_module, "get_proxy_id", lambda: "edge-a")
    op = SimpleNamespace(operation_id=5, target_kind="", target_ref="")
    calls: list[tuple[str, object]] = []

    class Ledger:
        def requeue_stale_applying(self, proxy_id, **kwargs) -> None:
            calls.append(("requeue", (proxy_id, kwargs)))

        def claim_pending(self, proxy_id, *, limit, operation_id=None, **kwargs):
            calls.append(("claim", (proxy_id, limit, operation_id, kwargs)))
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
        ("requeue", ("edge-a", {"allow_alias": False})),
        ("claim", ("edge-a", 100, None, {"allow_alias": False})),
        ("mark", (5, "applied", "runtime reconciled")),
    ]


def test_sync_from_db_old_runtime_alias_cannot_mutate_or_fail_new_proxy_operations(
    monkeypatch,
) -> None:
    from services.proxy_write_guard import ProxyLifecycleWriteError

    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    monkeypatch.setattr(runtime_module, "get_proxy_id", lambda: "edge-old")
    calls: list[tuple[str, object]] = []

    class Ledger:
        def requeue_stale_applying(self, proxy_id, **kwargs) -> None:
            calls.append(("requeue", (proxy_id, kwargs)))
            assert kwargs == {"allow_alias": False}
            msg = (
                "Proxy 'edge-old' was renamed to 'edge-new'; "
                "stale proxy-scoped writes are blocked."
            )
            raise ProxyLifecycleWriteError(msg)

        def claim_pending(self, *_args, **_kwargs):
            calls.append(("claim", None))
            msg = "stale runtime must fail before claiming operations"
            raise AssertionError(msg)

        def mark_status(self, *_args, **_kwargs) -> None:
            calls.append(("mark", None))
            msg = "stale runtime must not fail claimed new operations"
            raise AssertionError(msg)

    monkeypatch.setattr(runtime_module, "get_operation_ledger", Ledger)

    def sync_unlocked(**_kwargs):
        calls.append(("sync", None))
        return {"ok": True, "detail": "plain reconciliation without operations"}

    runtime._sync_from_db_unlocked = sync_unlocked

    result = runtime.sync_from_db(force=False)

    assert result["ok"] is True
    assert calls == [
        ("requeue", ("edge-old", {"allow_alias": False})),
        ("sync", None),
    ]


def test_sync_from_db_routes_claimed_operation_force_to_artifact_sync(
    monkeypatch,
) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    monkeypatch.setattr(runtime_module, "get_proxy_id", lambda: "edge-a")
    op = SimpleNamespace(operation_id=5, target_kind="", target_ref="", force=True)
    observed: list[tuple[bool, bool]] = []

    class Ledger:
        def requeue_stale_applying(self, _proxy_id, **kwargs) -> None:
            assert kwargs == {"allow_alias": False}

        def claim_pending(self, _proxy_id, *, limit, operation_id=None, **kwargs):
            assert kwargs == {"allow_alias": False}
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


def test_sync_from_db_does_not_force_artifacts_for_cache_clear(
    monkeypatch,
) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    monkeypatch.setattr(runtime_module, "get_proxy_id", lambda: "edge-a")
    op = SimpleNamespace(
        operation_id=5,
        operation_type="cache_clear",
        target_kind="",
        force=True,
    )
    observed: list[tuple[bool, bool]] = []

    class Ledger:
        def requeue_stale_applying(self, _proxy_id, **kwargs) -> None:
            assert kwargs == {"allow_alias": False}

        def claim_pending(self, _proxy_id, *, limit, operation_id=None, **kwargs):
            assert kwargs == {"allow_alias": False}
            assert limit == 100
            assert operation_id is None
            return [op]

        def mark_status(self, *_args, **_kwargs) -> None:
            return None

    monkeypatch.setattr(runtime_module, "get_operation_ledger", Ledger)

    def sync_unlocked(*, force=False, artifact_force=None, operations=None):
        observed.append((bool(force), bool(artifact_force)))
        assert operations == [op]
        return {
            "ok": True,
            "detail": "cache cleared",
            "executed_operation_types": ["cache_clear"],
            "cache_cleared": True,
        }

    runtime._sync_from_db_unlocked = sync_unlocked

    result = runtime.sync_from_db(force=False)

    assert result["ok"] is True
    assert observed == [(False, False)]


def test_sync_from_db_logs_operation_ledger_claim_failure(monkeypatch) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    log_calls: list[tuple[str, str, str, str]] = []
    observed: list[tuple[bool, list[object]]] = []

    class Ledger:
        def requeue_stale_applying(self, _proxy_id, **kwargs) -> None:
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
        def requeue_stale_applying(self, proxy_id, **kwargs) -> None:
            assert proxy_id == "edge-a"

        def claim_pending(self, proxy_id, *, limit, operation_id=None, **kwargs):
            assert proxy_id == "edge-a"
            assert kwargs == {"allow_alias": False}
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
        def requeue_stale_applying(self, proxy_id, **kwargs) -> None:
            assert proxy_id == "edge-a"

        def claim_pending(self, proxy_id, *, limit, operation_id=None, **kwargs):
            assert proxy_id == "edge-a"
            assert kwargs == {"allow_alias": False}
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
        def requeue_stale_applying(self, _proxy_id, **kwargs) -> None:
            assert kwargs == {"allow_alias": False}

        def claim_pending(self, _proxy_id, *, limit, operation_id=None, **kwargs):
            assert kwargs == {"allow_alias": False}
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
        def requeue_stale_applying(self, _proxy_id, **kwargs) -> None:
            assert kwargs == {"allow_alias": False}

        def claim_pending(self, _proxy_id, *, limit, operation_id=None, **kwargs):
            assert kwargs == {"allow_alias": False}
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
        def requeue_stale_applying(self, proxy_id, **kwargs) -> None:
            assert proxy_id == "edge-a"

        def claim_pending(self, proxy_id, *, limit, operation_id=None, **kwargs):
            assert proxy_id == "edge-a"
            assert kwargs == {"allow_alias": False}
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
        def requeue_stale_applying(self, proxy_id, **kwargs) -> None:
            assert proxy_id == "edge-a"

        def claim_pending(self, proxy_id, *, limit, operation_id=None, **kwargs):
            assert proxy_id == "edge-a"
            assert kwargs == {"allow_alias": False}
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
        "certificate_bundle_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
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
    assert (
        result["certificate_bundle_sha256"]
        == "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    )
    assert calls == [
        (
            5,
            "applied",
            "Proxy is already using the active certificate bundle.",
        )
    ]


def test_sync_from_db_fails_certificate_operation_with_hash_mismatch(
    monkeypatch,
) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    monkeypatch.setattr(runtime_module, "get_proxy_id", lambda: "edge-a")
    op = SimpleNamespace(
        operation_id=5,
        operation_type="certificate_apply",
        target_kind="certificate_revision",
        target_ref="12",
        request_hash="eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    )
    calls: list[tuple[int, str, str]] = []

    class Ledger:
        def requeue_stale_applying(self, _proxy_id, **kwargs) -> None:
            assert kwargs == {"allow_alias": False}

        def claim_pending(self, _proxy_id, *, limit, operation_id=None, **kwargs):
            assert kwargs == {"allow_alias": False}
            assert limit == 100
            assert operation_id is None
            return [op]

        def mark_status(self, operation_id, *, status, detail) -> None:
            calls.append((operation_id, status, detail))

    monkeypatch.setattr(runtime_module, "get_operation_ledger", Ledger)
    runtime._sync_from_db_unlocked = (
        lambda *, force=False, artifact_force=None, operations=None: {
            "ok": True,
            "certificate_revision_id": 12,
            "certificate_bundle_sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "detail": "runtime reconciled with mismatched certificate hash",
            "executed_operation_types": ["certificate_apply"],
        }
    )

    result = runtime.sync_from_db(force=False)

    assert result["ok"] is True
    assert calls[0][0:2] == (5, "failed")
    assert "queued revision 12 hash eeeeeeeeeeee" in calls[0][2]
    assert "differs from applied certificate bundle evidence" in calls[0][2]


def test_sync_from_db_fails_certificate_operation_without_hash_evidence(
    monkeypatch,
) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    monkeypatch.setattr(runtime_module, "get_proxy_id", lambda: "edge-a")
    op = SimpleNamespace(
        operation_id=5,
        operation_type="certificate_revert",
        target_kind="certificate_revision",
        target_ref="12",
        request_hash="eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    )
    calls: list[tuple[int, str, str]] = []

    class Ledger:
        def requeue_stale_applying(self, _proxy_id, **kwargs) -> None:
            assert kwargs == {"allow_alias": False}

        def claim_pending(self, _proxy_id, *, limit, operation_id=None, **kwargs):
            assert kwargs == {"allow_alias": False}
            assert limit == 100
            assert operation_id is None
            return [op]

        def mark_status(self, operation_id, *, status, detail) -> None:
            calls.append((operation_id, status, detail))

    monkeypatch.setattr(runtime_module, "get_operation_ledger", Ledger)
    runtime._sync_from_db_unlocked = (
        lambda *, force=False, artifact_force=None, operations=None: {
            "ok": True,
            "certificate_revision_id": 12,
            "detail": "runtime reconciled without certificate hash evidence",
            "executed_operation_types": ["certificate_revert"],
        }
    )

    result = runtime.sync_from_db(force=False)

    assert result["ok"] is True
    assert calls[0][0:2] == (5, "failed")
    assert "certificate bundle SHA evidence is unavailable" in calls[0][2]


def test_sync_from_db_marks_stale_certificate_revision_superseded(monkeypatch) -> None:
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
        def requeue_stale_applying(self, proxy_id, **kwargs) -> None:
            assert proxy_id == "edge-a"

        def claim_pending(self, proxy_id, *, limit, operation_id=None, **kwargs):
            assert proxy_id == "edge-a"
            assert kwargs == {"allow_alias": False}
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
        "certificate_bundle_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
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
        def requeue_stale_applying(self, proxy_id, **kwargs) -> None:
            assert proxy_id == "edge-a"

        def claim_pending(self, proxy_id, *, limit, operation_id=None, **kwargs):
            assert proxy_id == "edge-a"
            assert kwargs == {"allow_alias": False}
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
        "certificate_bundle_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
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
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    monkeypatch.setattr(runtime_module, "get_proxy_id", lambda: "edge-a")
    op = SimpleNamespace(
        operation_id=5,
        operation_type="policy_sync",
        target_kind="policy_state",
        target_ref=POLICY_SHA_A,
    )
    calls: list[tuple[int, str, str]] = []

    class Ledger:
        def requeue_stale_applying(self, _proxy_id, **kwargs) -> None:
            assert kwargs == {"allow_alias": False}

        def claim_pending(self, _proxy_id, *, limit, operation_id=None, **kwargs):
            assert kwargs == {"allow_alias": False}
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
            "policy_sha256": POLICY_SHA_A,
        }

    runtime._sync_from_db_unlocked = sync_unlocked
    runtime._current_policy_sha = lambda: POLICY_SHA_OLD

    result = runtime.sync_from_db(force=False)

    assert result["ok"] is True
    assert calls == [
        (
            5,
            "failed",
            (
                "policy state sync did not converge selected-proxy runtime state; "
                f"queued policy state {POLICY_SHA_A[:12]} differs from current policy state {POLICY_SHA_OLD[:12]}.\n"
                "runtime reconciled"
            ),
        )
    ]


def test_sync_from_db_policy_operation_uses_selected_proxy_current_policy_sha(
    monkeypatch,
) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    monkeypatch.setattr(runtime_module, "get_proxy_id", lambda: "edge-a")
    edge_a = SimpleNamespace(
        operation_id=5,
        operation_type="policy_sync",
        target_kind="policy_state",
        target_ref=POLICY_SHA_A,
    )
    edge_b = SimpleNamespace(
        operation_id=6,
        operation_type="policy_sync",
        target_kind="policy_state",
        target_ref=POLICY_SHA_B,
    )
    calls: list[tuple[int, str, str]] = []

    class Ledger:
        def requeue_stale_applying(self, _proxy_id, **kwargs) -> None:
            assert kwargs == {"allow_alias": False}

        def claim_pending(self, _proxy_id, *, limit, operation_id=None, **kwargs):
            assert kwargs == {"allow_alias": False}
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
            "policy_sha256": POLICY_SHA_A,
            "current_policy_sha": POLICY_SHA_A,
        }

    runtime._sync_from_db_unlocked = sync_unlocked
    runtime._current_policy_sha = lambda: POLICY_SHA_B

    result = runtime.sync_from_db(force=False)

    assert result["ok"] is True
    assert calls[0] == (5, "applied", "runtime reconciled")
    assert calls[1][0:2] == (6, "superseded")
    assert f"queued policy state {POLICY_SHA_B[:12]} was not applied" in calls[1][2]


def test_operation_completion_requires_exact_pac_target_and_current_runtime() -> None:
    from proxy import runtime as runtime_module

    op = SimpleNamespace(
        operation_type="pac_refresh",
        target_kind="pac_state",
        target_ref=PAC_SHA_A,
    )

    assert runtime_module._operation_completion_status(
        op,
        default_status="applied",
        detail="runtime reconciled",
        result={
            "executed_operation_types": ["pac_refresh"],
            "state_sha256": PAC_SHA_A,
            "current_state_sha256": PAC_SHA_A,
        },
    ) == ("applied", "runtime reconciled")

    uppercase_op = SimpleNamespace(
        operation_type="pac_refresh",
        target_kind="pac_state",
        target_ref=PAC_SHA_A.upper(),
    )
    assert runtime_module._operation_completion_status(
        uppercase_op,
        default_status="applied",
        detail="runtime reconciled",
        result={
            "executed_operation_types": ["pac_refresh"],
            "state_sha256": PAC_SHA_A,
            "current_state_sha256": PAC_SHA_A,
        },
    ) == ("applied", "runtime reconciled")

    malformed_status, malformed_detail = runtime_module._operation_completion_status(
        SimpleNamespace(
            operation_type="pac_refresh",
            target_kind="pac_state",
            target_ref="pac-a",
        ),
        default_status="applied",
        detail="runtime reconciled",
        result={
            "executed_operation_types": ["pac_refresh"],
            "state_sha256": PAC_SHA_A,
            "current_state_sha256": PAC_SHA_A,
        },
    )
    assert malformed_status == "failed"
    assert "valid queued PAC state target" in malformed_detail

    status, detail = runtime_module._operation_completion_status(
        op,
        default_status="applied",
        detail="runtime reconciled",
        result={
            "executed_operation_types": ["pac_refresh"],
            "state_sha256": PAC_SHA_B,
            "current_state_sha256": PAC_SHA_B,
        },
    )
    assert status == "superseded"
    assert f"queued PAC state {PAC_SHA_A[:12]}" in detail

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
            "state_sha256": PAC_SHA_A,
            "current_state_sha256": PAC_SHA_OLD,
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
        request_hash="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )

    assert runtime_module._operation_completion_status(
        op,
        default_status="applied",
        detail="runtime reconciled",
        result={
            "executed_operation_types": ["adblock_refresh"],
            "revision_id": 7,
            "artifact_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "current_adblock_artifact_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        },
    ) == ("applied", "runtime reconciled")

    status, detail = runtime_module._operation_completion_status(
        op,
        default_status="applied",
        detail="runtime reconciled",
        result={
            "executed_operation_types": ["adblock_refresh"],
            "revision_id": 8,
            "artifact_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "current_adblock_artifact_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
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
            "artifact_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "current_adblock_artifact_sha256": "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccurrent-mismatch",
        },
    )
    assert mismatch_status == "failed"
    assert "queued artifact aaaaaaaaaaaa" in mismatch_detail


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
            "artifact_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "current_adblock_artifact_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
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
            "artifact_sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        },
    )
    assert status == "superseded"
    assert "queued settings version 12" in detail


def test_operation_completion_requires_selected_proxy_adblock_runtime_target() -> None:
    from proxy import runtime as runtime_module

    op = SimpleNamespace(
        operation_type="adblock_refresh",
        target_kind="adblock_runtime_enabled",
        target_ref="0",
        request_hash="",
    )

    assert runtime_module._operation_completion_status(
        op,
        default_status="applied",
        detail="runtime reconciled",
        result={
            "executed_operation_types": ["adblock_refresh"],
            "adblock_runtime_enabled": "0",
        },
    ) == ("applied", "runtime reconciled")

    status, detail = runtime_module._operation_completion_status(
        op,
        default_status="applied",
        detail="runtime reconciled",
        result={
            "executed_operation_types": ["adblock_refresh"],
            "adblock_runtime_enabled": "1",
        },
    )
    assert status == "superseded"
    assert "queued adblock runtime enablement 0" in detail


def test_operation_completion_rejects_mismatched_supported_target_kind() -> None:
    from proxy import runtime as runtime_module

    op = SimpleNamespace(
        operation_type="policy_sync",
        target_kind="pac_state",
        target_ref="pac-a",
    )

    status, detail = runtime_module._operation_completion_status(
        op,
        default_status="applied",
        detail="runtime reconciled",
        result={
            "executed_operation_types": ["policy_sync"],
            "state_sha256": "pac-a",
            "current_state_sha256": "pac-a",
        },
    )

    assert status == "failed"
    assert "operation 'policy_sync' cannot target 'pac_state'" in detail
    assert "expected policy_state" in detail
    assert "runtime reconciled" in detail


def test_operation_completion_supports_revert_config_revision_target() -> None:
    from proxy import runtime as runtime_module

    op = SimpleNamespace(
        operation_type="revert",
        target_kind="config_revision",
        target_ref="9",
        request_hash="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )

    assert runtime_module._operation_completion_status(
        op,
        default_status="applied",
        detail="runtime reconciled",
        result={
            "executed_operation_types": ["revert"],
            "revision_id": 9,
            "active_revision_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        },
    ) == ("applied", "runtime reconciled")

    bad_status, bad_detail = runtime_module._operation_completion_status(
        SimpleNamespace(operation_type="revert", target_kind="", target_ref="9"),
        default_status="applied",
        detail="runtime reconciled",
        result={"executed_operation_types": ["revert"]},
    )
    assert bad_status == "failed"
    assert "operation 'revert' cannot target 'no target'" in bad_detail


def test_operation_completion_normalizes_and_rejects_request_hash_evidence() -> None:
    from proxy import runtime as runtime_module

    uppercase = SimpleNamespace(
        operation_type="certificate_apply",
        target_kind="certificate_revision",
        target_ref="12",
        request_hash="A" * 64,
    )

    assert runtime_module._operation_completion_status(
        uppercase,
        default_status="applied",
        detail="runtime reconciled",
        result={
            "executed_operation_types": ["certificate_apply"],
            "certificate_revision_id": 12,
            "certificate_bundle_sha256": "a" * 64,
            "current_certificate_sha": "a" * 64,
        },
    ) == ("applied", "runtime reconciled")

    malformed = SimpleNamespace(
        operation_type="certificate_apply",
        target_kind="certificate_revision",
        target_ref="12",
        request_hash="a" * 65,
    )
    status, detail = runtime_module._operation_completion_status(
        malformed,
        default_status="applied",
        detail="runtime reconciled",
        result={
            "executed_operation_types": ["certificate_apply"],
            "certificate_revision_id": 12,
            "certificate_bundle_sha256": "a" * 64,
            "current_certificate_sha": "a" * 64,
        },
    )

    assert status == "failed"
    assert "queued request_hash evidence is invalid" in detail


def test_sync_from_db_marks_unsupported_operation_failed(monkeypatch) -> None:
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
        def requeue_stale_applying(self, _proxy_id, **kwargs) -> None:
            assert kwargs == {"allow_alias": False}

        def claim_pending(self, _proxy_id, *, limit, operation_id=None, **kwargs):
            assert kwargs == {"allow_alias": False}
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


def test_sync_from_db_marks_mismatched_supported_operation_failed(monkeypatch) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    monkeypatch.setattr(runtime_module, "get_proxy_id", lambda: "edge-a")
    op = SimpleNamespace(
        operation_id=5,
        operation_type="pac_refresh",
        target_kind="policy_state",
        target_ref="policy-sha",
    )
    calls: list[tuple[int, str, str]] = []

    class Ledger:
        def requeue_stale_applying(self, _proxy_id, **kwargs) -> None:
            assert kwargs == {"allow_alias": False}

        def claim_pending(self, _proxy_id, *, limit, operation_id=None, **kwargs):
            assert kwargs == {"allow_alias": False}
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
    assert result["incompatible_operation_targets"] == ["pac_refresh:policy_state"]
    assert calls[0][0:2] == (5, "failed")
    assert "operation 'pac_refresh' cannot target 'policy_state'" in calls[0][2]


def test_sync_from_db_requires_operation_execution_evidence(monkeypatch) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    runtime = _runtime_shell()
    monkeypatch.setattr(runtime_module, "get_proxy_id", lambda: "edge-a")
    op = SimpleNamespace(operation_id=5, operation_type="cache_clear")
    calls: list[tuple[int, str, str]] = []

    class Ledger:
        def requeue_stale_applying(self, _proxy_id, **kwargs) -> None:
            assert kwargs == {"allow_alias": False}

        def claim_pending(self, _proxy_id, *, limit, operation_id=None, **kwargs):
            assert kwargs == {"allow_alias": False}
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
    runtime._reload_for_policy_update = lambda **_kwargs: (
        True,
        "Squid reconfigured for policy update.",
    )
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


def test_sync_from_db_builds_adblock_artifact_for_build_operation() -> None:
    runtime = _runtime_shell()
    build_calls: list[dict[str, object]] = []
    cleared_refresh: list[bool] = []

    runtime.ensure_registered = lambda: None
    runtime.bootstrap_revision_if_missing = lambda: None
    runtime._invalidate_health_cache = lambda: None
    runtime.sync_certificate_bundle = lambda force=False: {"ok": True, "changed": False}
    runtime.sync_policy_state = lambda force=False: {
        "ok": True,
        "changed": False,
        "reload_required": False,
    }
    runtime.sync_pac_state = lambda force=False: {"ok": True, "changed": False}
    runtime.sync_adblock_state = lambda force=False: {
        "ok": True,
        "changed": True,
        "revision_id": 10,
        "adblock_settings_version": 12,
        "artifact_sha256": "artifact-new",
        "current_adblock_artifact_sha256": "artifact-new",
        "detail": "Adblock artifact applied.",
    }
    runtime._ensure_policy_runtime_config = lambda: (True, "", False)
    runtime._reload_for_policy_update = lambda **_kwargs: (
        True,
        "Squid reconfigured for policy update.",
    )
    runtime._current_config_sha = lambda: "current-sha"
    runtime._current_adblock_artifact_sha = lambda: "artifact-new"
    runtime.controller = SimpleNamespace(
        set_adblock_icap_revision_token=lambda _token: None,
    )
    runtime.registry = SimpleNamespace(mark_apply_result=lambda *args, **kwargs: None)
    runtime.adblock_store = SimpleNamespace(
        get_refresh_requested=lambda: 1,
        clear_refresh_requested=lambda: cleared_refresh.append(True),
    )
    runtime.adblock_artifacts = SimpleNamespace(
        build_active_artifact=lambda **kwargs: (
            build_calls.append(dict(kwargs))
            or {
                "ok": True,
                "changed": True,
                "detail": "Activated adblock artifact revision 10.",
                "revision": SimpleNamespace(
                    revision_id=10,
                    settings_version=12,
                    artifact_sha256="artifact-new",
                ),
            }
        )
    )
    runtime.revisions = SimpleNamespace(
        get_active_revision_metadata=lambda _proxy_id: SimpleNamespace(
            revision_id=9,
            config_sha256="current-sha",
        ),
        latest_apply=lambda _proxy_id: None,
    )

    result = runtime._sync_from_db_unlocked(
        force=False,
        artifact_force=True,
        operations=[
            SimpleNamespace(
                operation_type="adblock_refresh",
                target_kind="adblock_artifact_build",
                target_ref="12",
                force=True,
            )
        ],
    )

    assert result["ok"] is True
    assert result["adblock_settings_version"] == 12
    assert result["artifact_sha256"] == "artifact-new"
    assert result["executed_operation_types"] == ["adblock_refresh"]
    assert "Activated adblock artifact revision 10." in result["detail"]
    assert build_calls == [
        {
            "refresh_lists": True,
            "created_by": "proxy-runtime",
            "source_kind": "background",
        }
    ]
    assert cleared_refresh == [True]


def test_sync_from_db_skips_cleared_adblock_build_and_applies_active_revision() -> None:
    runtime = _runtime_shell()
    adblock_calls: list[bool] = []

    runtime.ensure_registered = lambda: None
    runtime.bootstrap_revision_if_missing = lambda: None
    runtime._invalidate_health_cache = lambda: None
    runtime.sync_certificate_bundle = lambda force=False: {"ok": True, "changed": False}
    runtime.sync_policy_state = lambda force=False: {
        "ok": True,
        "changed": False,
        "reload_required": False,
    }
    runtime.sync_pac_state = lambda force=False: {"ok": True, "changed": False}

    def sync_adblock_state(*, force=False):
        adblock_calls.append(force)
        return {
            "ok": True,
            "changed": True,
            "revision_id": 44,
            "application_id": 73,
            "adblock_settings_version": 15,
            "artifact_sha256": "manual-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "current_adblock_artifact_sha256": "manual-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "detail": "Adblock artifact applied.",
        }

    runtime.sync_adblock_state = sync_adblock_state
    runtime._ensure_policy_runtime_config = lambda: (True, "", False)
    runtime._reload_for_policy_update = lambda **_kwargs: (
        True,
        "Squid reconfigured for policy update.",
    )
    runtime._current_config_sha = lambda: "current-sha"
    runtime._current_adblock_artifact_sha = lambda: (
        "manual-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )
    runtime.controller = SimpleNamespace(
        set_adblock_icap_revision_token=lambda _token: None,
    )
    runtime.registry = SimpleNamespace(mark_apply_result=lambda *args, **kwargs: None)
    runtime.adblock_store = SimpleNamespace(
        get_refresh_requested=lambda: 0,
        clear_refresh_requested=lambda: (_ for _ in ()).throw(
            AssertionError("cleared build operation should not clear refresh again")
        ),
    )
    runtime.adblock_artifacts = SimpleNamespace(
        build_active_artifact=lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("cleared adblock build operation must not rebuild")
        )
    )
    runtime.revisions = SimpleNamespace(
        get_active_revision_metadata=lambda _proxy_id: SimpleNamespace(
            revision_id=9,
            config_sha256="current-sha",
        ),
        latest_apply=lambda _proxy_id: None,
    )

    result = runtime._sync_from_db_unlocked(
        force=False,
        artifact_force=True,
        operations=[
            SimpleNamespace(
                operation_type="adblock_refresh",
                target_kind="adblock_artifact_build",
                target_ref="14",
                force=True,
            )
        ],
    )

    assert result["ok"] is True
    assert result["adblock_revision_id"] == 44
    assert result["adblock_application_id"] == 73
    assert (
        result["artifact_sha256"]
        == "manual-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )
    assert result["adblock_settings_version"] == 15
    assert result["executed_operation_types"] == ["adblock_refresh"]
    assert "build request was already cleared" in result["detail"]
    assert adblock_calls == [True]


def test_sync_certificate_bundle_rolls_back_material_after_restart_failure(
    tmp_path,
) -> None:
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
    assert (
        "Last-known certificate bundle before failed apply: oldsha" in result["detail"]
    )


def test_sync_certificate_bundle_retry_after_unknown_rollback_rematerializes(
    monkeypatch,
) -> None:
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
        target_kind="pac_state",
        target_ref="pac-sha",
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
        [
            SimpleNamespace(
                force=True,
                operation_type="config_apply",
                target_kind="config_revision",
            )
        ]
    )
    pac_operation = SimpleNamespace(
        force=True,
        operation_type="pac_refresh",
        target_kind="pac_state",
    )
    assert not runtime_module._operations_request_config_force([pac_operation])
    assert runtime_module._operations_request_force([pac_operation])
    assert runtime_module._operations_request_reconciliation_force([pac_operation])
    cache_operation = SimpleNamespace(
        force=True,
        operation_type="cache_clear",
        target_kind="",
    )
    assert runtime_module._operations_request_force([cache_operation])
    assert not runtime_module._operations_request_reconciliation_force(
        [cache_operation]
    )
