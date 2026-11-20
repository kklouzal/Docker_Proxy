"""Squid work left unfinished by an exited process is resumed.

A cache clear stops Squid first; if the management API running it is killed
or stopped half-way, the journal stays ``in_progress`` while nobody holds the
lifecycle lock, and ``SquidController.recover_interrupted_transaction`` (run
by the proxy agent) must finish the job so Squid ends up running again.
"""

from __future__ import annotations

import json
import os
import re
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

# Builds a controller whose commands are fakes; "stop squid" can block so the
# caller is caught half-way through a cache clear.
_FAKE_CONTROLLER = """
import json, os, time
from pathlib import Path
from types import SimpleNamespace
from services import squidctl

def fake_controller(cache_dir, calls_path, block_marker=None):
    def run(args, **kwargs):
        with open(calls_path, "a", encoding="utf-8") as calls:
            calls.write(json.dumps(list(args)) + "\\n")
        if list(args[-2:]) == ["stop", "squid"]:
            if block_marker:
                Path(block_marker).write_text("stopping", encoding="utf-8")
                time.sleep(120)
            return SimpleNamespace(returncode=0, stdout=b"squid: stopped\\n", stderr=b"")
        if list(args[:3]) == ["squid", "--foreground", "-z"]:
            return SimpleNamespace(returncode=0, stdout=b"squid -z OK\\n", stderr=b"")
        raise AssertionError(f"unexpected command: {args!r}")

    controller = squidctl.SquidController(cmd_run=run)
    controller.get_current_config = lambda: f"cache_dir rock {cache_dir} 100\\n"
    controller._wait_for_http_listener_absent = lambda *, timeout: True
    controller._wait_for_squid_pidfile_stale_or_absent = lambda *, timeout: True
    controller._remove_stale_squid_pidfile = lambda **_kwargs: ""

    def restart(**_kwargs):
        with open(calls_path, "a", encoding="utf-8") as calls:
            calls.write(json.dumps(["restart"]) + "\\n")
        return True, "Squid restarted."

    controller._restart_squid_locked = restart
    return controller
"""

# The real management server serving a cache clear (proxy.app replaced).
_SERVER = (
    _FAKE_CONTROLLER
    + """
import sys, types
controller = fake_controller(os.environ["CACHE_DIR"], os.environ["CALLS"], os.environ["MARKER"])

def app(environ, start_response):
    ok, detail = controller.clear_disk_cache()
    start_response("200 OK", [("Content-Length", "0")])
    return []

sys.modules["proxy.app"] = types.SimpleNamespace(app=app)
import logging
logging.basicConfig(level=logging.INFO)
from proxy import management_server
management_server.BIND_HOST = "127.0.0.1"
management_server.BIND_PORT = 0
management_server.main()
"""
)


@pytest.fixture
def squid_env(tmp_path, monkeypatch):
    lock_dir = tmp_path / "lock"
    lock_dir.mkdir(mode=0o700)
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    (cache_dir / "rock").write_text("cached", encoding="utf-8")
    env = {
        "SQUID_LIFECYCLE_LOCK_DIR": str(lock_dir),
        "SQUID_TRANSACTION_JOURNAL_PATH": str(tmp_path / "squid-transaction.json"),
        "PERSISTED_SQUID_CONF_PATH": str(tmp_path / "persisted-squid.conf"),
        "CACHE_DIR": str(cache_dir),
        "CALLS": str(tmp_path / "calls.jsonl"),
        "MARKER": str(tmp_path / "stopping"),
    }
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    return SimpleNamespace(tmp=tmp_path, **{k.lower(): Path(v) for k, v in env.items()})


def _parent_controller(squid_env):
    namespace: dict[str, object] = {}
    exec(_FAKE_CONTROLLER, namespace)  # ruff: ignore[exec-builtin] -- shared fake source
    return namespace["fake_controller"](
        str(squid_env.cache_dir), str(squid_env.tmp / "recovery-calls.jsonl")
    )


def _journal(squid_env) -> dict:
    return json.loads(squid_env.squid_transaction_journal_path.read_text("utf-8"))


def _wait_for(path: Path, process: subprocess.Popen) -> None:
    deadline = time.monotonic() + 20
    while not path.exists():
        assert process.poll() is None, process.communicate()
        assert time.monotonic() < deadline
        time.sleep(0.05)


def _start_server(squid_env) -> tuple[subprocess.Popen, int]:
    process = subprocess.Popen(
        [sys.executable, "-c", _SERVER],
        cwd=REPO_ROOT,
        env={
            **os.environ,
            "PYTHONPATH": f"{REPO_ROOT}{os.pathsep}{REPO_ROOT / 'web'}",
            "WEB_GRACEFUL_TIMEOUT": "1",
        },
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + 20
    for line in process.stderr:
        match = re.search(r"Management listener at http://[^:]+:(\d+)", line)
        if match:
            return process, int(match.group(1))
        assert time.monotonic() < deadline
    pytest.fail("management server did not start")


@pytest.mark.parametrize("stop_signal", [signal.SIGKILL, signal.SIGTERM])
def test_cache_clear_cut_off_with_its_server_is_finished(squid_env, stop_signal):
    process, port = _start_server(squid_env)
    client = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        client.sendall(b"POST /clear HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
        _wait_for(squid_env.marker, process)  # Squid is being stopped
        recovery = _parent_controller(squid_env)
        # The owner is alive and holds the lifecycle lock: hands off.
        assert recovery.lifecycle_owner_active() is True
        assert recovery.recover_interrupted_transaction() is None

        process.send_signal(stop_signal)
        # SIGTERM: the graceful drain gives up after WEB_GRACEFUL_TIMEOUT.
        assert process.wait(timeout=20) is not None
    finally:
        client.close()
        process.kill()
        process.communicate()

    journal = _journal(squid_env)
    assert (journal["status"], journal["operation"]) == (
        "in_progress",
        "clear_disk_cache",
    )
    assert recovery.lifecycle_owner_active() is False

    ok, detail = recovery.recover_interrupted_transaction()

    assert ok is True, detail
    calls = [
        json.loads(line)
        for line in (squid_env.tmp / "recovery-calls.jsonl")
        .read_text("utf-8")
        .splitlines()
    ]
    assert calls[-2:] == [
        ["squid", "--foreground", "-z", "-f", recovery.squid_conf_path],
        ["restart"],
    ]
    assert not (squid_env.cache_dir / "rock").exists()
    journal = _journal(squid_env)
    assert (journal["status"], journal["operation"]) == (
        "recovered",
        "recover_clear_disk_cache",
    )
    # Nothing is left to recover.
    assert recovery.recover_interrupted_transaction() is None


def test_other_interrupted_mutations_get_the_last_known_good_rollback(
    squid_env, monkeypatch
):
    from services.squid_transaction import SquidTransactionJournal  # type: ignore

    recovery = _parent_controller(squid_env)
    SquidTransactionJournal(
        squid_env.squid_transaction_journal_path,
        active_config=recovery.squid_conf_path,
        persisted_config=squid_env.persisted_squid_conf_path,
    ).begin("apply_config_text", intended_phase="runtime_ready_and_lkg_persisted")
    reasons: list[str] = []
    monkeypatch.setattr(
        recovery,
        "_restore_last_known_good_config_locked",
        lambda *, reason: reasons.append(reason) or (True, "rolled back"),
    )

    assert recovery.recover_interrupted_transaction() == (True, "rolled back")
    assert "apply_config_text" in reasons[0]


def test_failed_cache_clear_recovery_is_left_for_the_rollback_self_heal(squid_env):
    from services.squid_transaction import SquidTransactionJournal  # type: ignore

    recovery = _parent_controller(squid_env)
    SquidTransactionJournal(
        squid_env.squid_transaction_journal_path,
        active_config=recovery.squid_conf_path,
        persisted_config=squid_env.persisted_squid_conf_path,
    ).begin("clear_disk_cache", intended_phase="mutation_terminal")
    recovery._restart_squid_locked = lambda **_kwargs: (False, "Squid did not start.")

    ok, _detail = recovery.recover_interrupted_transaction()

    assert ok is False
    assert _journal(squid_env)["status"] == "recovery_required"
    # recovery_required belongs to the backed-off rollback path, not this one.
    assert recovery.recover_interrupted_transaction() is None
