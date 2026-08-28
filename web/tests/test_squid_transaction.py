from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

WEB_ROOT = Path(__file__).resolve().parents[1]
if str(WEB_ROOT) not in sys.path:
    sys.path.insert(0, str(WEB_ROOT))

from services.squid_transaction import (  # type: ignore  # noqa: E402
    SquidTransactionJournal,
    SquidTransactionRecoveryRequiredError,
    _release_inherited_startup_lock,
    _startup_begin,
    _startup_complete,
    _startup_fail,
    lifecycle_lock_path,
    open_lifecycle_lock,
)


def test_journal_records_config_and_runtime_manifest(tmp_path: Path) -> None:
    active = tmp_path / "etc" / "squid.conf"
    persisted = tmp_path / "state" / "squid.conf"
    runtime = tmp_path / "etc" / "20-icap.conf"
    for path, content in (
        (active, "# active\n"),
        (persisted, "# lkg\n"),
        (runtime, "# runtime\n"),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    journal_path = tmp_path / "state" / "transaction.json"
    journal = SquidTransactionJournal(
        journal_path,
        active_config=active,
        persisted_config=persisted,
        runtime_paths=[runtime],
    )

    journal.begin(
        "apply_config_text",
        intended_phase="runtime_ready_and_lkg_persisted",
        target_config="# candidate\n",
    )
    runtime.write_text("# candidate runtime\n", encoding="utf-8")
    journal.phase("runtime_fragments_materialized")
    journal.complete(detail="ready")

    payload = json.loads(journal_path.read_text(encoding="utf-8"))
    assert payload["status"] == "complete"
    assert payload["phase"] == "complete"
    assert payload["state_before"]["manifest_sha256"]
    assert payload["state_after"]["manifest_sha256"]
    assert {item["role"] for item in payload["state_after"]["files"]} == {
        "active_config",
        "persisted_last_known_good",
        "runtime_fragment",
    }


def test_journal_refuses_to_overwrite_unreconciled_transaction(tmp_path: Path) -> None:
    journal = SquidTransactionJournal(
        tmp_path / "transaction.json",
        active_config=tmp_path / "active.conf",
        persisted_config=tmp_path / "lkg.conf",
    )
    journal.begin("apply", intended_phase="ready")

    with pytest.raises(SquidTransactionRecoveryRequiredError):
        journal.begin("apply", intended_phase="ready")


def test_startup_recovers_dirty_startup_transaction_from_immutable_template(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active = tmp_path / "active.conf"
    persisted = tmp_path / "state" / "missing.conf"
    template = tmp_path / "squid.conf.template"
    active.write_text("partially materialized\n", encoding="utf-8")
    template.write_text("immutable bootstrap\n", encoding="utf-8")
    journal_path = tmp_path / "state" / "transaction.json"
    monkeypatch.setenv("SQUID_TRANSACTION_JOURNAL_PATH", str(journal_path))

    assert _startup_begin(active, persisted, template) == 0
    assert _startup_begin(active, persisted, template) == 0

    payload = json.loads(journal_path.read_text(encoding="utf-8"))
    assert active.read_text(encoding="utf-8") == "immutable bootstrap\n"
    assert payload["operation"] == "startup_reconciliation"
    assert payload["status"] == "recovering"
    assert payload["evidence"]["recovery_source"] == "immutable_bootstrap_template"


def test_startup_recovers_dirty_transaction_from_persisted_lkg(tmp_path: Path) -> None:
    active = tmp_path / "active.conf"
    persisted = tmp_path / "state" / "squid.conf"
    persisted.parent.mkdir(parents=True)
    active.write_text("candidate\n", encoding="utf-8")
    persisted.write_text("last known good\n", encoding="utf-8")
    journal_path = tmp_path / "state" / "transaction.json"
    journal = SquidTransactionJournal(
        journal_path,
        active_config=active,
        persisted_config=persisted,
    )
    journal.begin("apply", intended_phase="ready")

    env = {"SQUID_TRANSACTION_JOURNAL_PATH": str(journal_path)}
    subprocess.run(
        [
            sys.executable,
            str(WEB_ROOT / "services" / "squid_transaction.py"),
            "startup-begin",
            "--active",
            str(active),
            "--persisted",
            str(persisted),
        ],
        check=True,
        env=env,
    )

    payload = json.loads(journal_path.read_text(encoding="utf-8"))
    assert active.read_text(encoding="utf-8") == "last known good\n"
    assert payload["operation"] == "startup_reconciliation"
    assert payload["status"] == "recovering"
    assert payload["previous_transaction_id"]


def test_startup_fails_closed_when_dirty_transaction_has_no_lkg(tmp_path: Path) -> None:
    active = tmp_path / "active.conf"
    persisted = tmp_path / "state" / "missing.conf"
    active.write_text("candidate\n", encoding="utf-8")
    journal_path = tmp_path / "state" / "transaction.json"
    journal = SquidTransactionJournal(
        journal_path,
        active_config=active,
        persisted_config=persisted,
    )
    journal.begin("apply", intended_phase="ready")

    proc = subprocess.run(
        [
            sys.executable,
            str(WEB_ROOT / "services" / "squid_transaction.py"),
            "startup-begin",
            "--active",
            str(active),
            "--persisted",
            str(persisted),
        ],
        check=False,
        env={"SQUID_TRANSACTION_JOURNAL_PATH": str(journal_path)},
    )

    assert proc.returncode != 0


def test_journal_health_exposes_bounded_recovery_evidence(tmp_path: Path) -> None:
    journal = SquidTransactionJournal(
        tmp_path / "transaction.json",
        active_config=tmp_path / "active.conf",
        persisted_config=tmp_path / "lkg.conf",
    )
    journal.begin("apply", intended_phase="ready")

    health = journal.health().as_dict()

    assert health["ok"] is False
    assert health["ready"] is False
    assert health["status"] == "in_progress"
    assert health["transaction_id"]
    assert health["operation"] == "apply"
    assert health["phase"] == "prepared"
    assert health["recovery_status"] == "not_required"
    assert "reconciliation is required" in health["detail"]


def test_startup_complete_releases_inherited_lifecycle_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import fcntl

    lock_path = tmp_path / "lifecycle.lock"
    owner = lock_path.open("a+", encoding="utf-8")
    fcntl.flock(owner.fileno(), fcntl.LOCK_EX)
    inherited_fd = os.dup(owner.fileno())
    monkeypatch.setenv("SQUID_ENTRYPOINT_LOCK_FD", str(inherited_fd))

    _release_inherited_startup_lock()

    contender = lock_path.open("a+", encoding="utf-8")
    try:
        fcntl.flock(contender.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        contender.close()
        owner.close()


def test_startup_fail_leaves_persisted_lkg_byte_exact(tmp_path: Path) -> None:
    active = tmp_path / "active.conf"
    persisted = tmp_path / "state" / "squid.conf"
    persisted.parent.mkdir(parents=True)
    active.write_text("candidate\n", encoding="utf-8")
    lkg = b"# last known good\r\nworkers 2\r\n"
    persisted.write_bytes(lkg)
    journal_path = tmp_path / "transaction.json"
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setenv("SQUID_TRANSACTION_JOURNAL_PATH", str(journal_path))
        assert _startup_begin(active, persisted, active) == 0
        assert _startup_fail(active, persisted, "cache prepare failed") == 1

    assert persisted.read_bytes() == lkg
    payload = json.loads(journal_path.read_text(encoding="utf-8"))
    assert payload["status"] == "recovery_required"
    assert payload["phase"] == "startup_failed"
    assert "cache prepare failed" in payload["detail"]


def test_startup_complete_atomically_replaces_persisted_lkg(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active = tmp_path / "active.conf"
    persisted = tmp_path / "state" / "squid.conf"
    persisted.parent.mkdir(parents=True)
    candidate = b"# validated candidate\nworkers 4\n"
    lkg = b"# last known good\nworkers 2\n"
    active.write_bytes(candidate)
    persisted.write_bytes(lkg)
    journal_path = tmp_path / "transaction.json"
    monkeypatch.setenv("SQUID_TRANSACTION_JOURNAL_PATH", str(journal_path))
    assert _startup_begin(active, persisted, active) == 0

    original_replace = Path.replace
    persisted_replacements: list[Path] = []

    def observe_replace(source: Path, target: Path) -> Path:
        if target == persisted:
            assert persisted.read_bytes() == lkg
            assert source.parent == persisted.parent
            assert source.name.startswith(f".{persisted.name}.")
            persisted_replacements.append(source)
        return original_replace(source, target)

    monkeypatch.setattr(Path, "replace", observe_replace)

    assert _startup_complete(active, persisted) == 0

    assert len(persisted_replacements) == 1
    assert persisted.read_bytes() == candidate
    payload = json.loads(journal_path.read_text(encoding="utf-8"))
    assert payload["status"] == "complete"
    assert payload["phase"] == "complete"


def test_lifecycle_lock_defaults_to_private_runtime_directory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SQUID_LIFECYCLE_LOCK_DIR", raising=False)
    monkeypatch.delenv("PROXY_RUNTIME_LOCK_DIR", raising=False)
    assert lifecycle_lock_path() == Path(
        "/tmp/docker-proxy-runtime/docker-proxy-squid-lifecycle.lock"
    )


def test_lifecycle_lock_rejects_symlink_without_mutating_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock_dir = tmp_path / "locks"
    lock_dir.mkdir(mode=0o700)
    target = tmp_path / "target"
    target.write_text("unchanged", encoding="utf-8")
    (lock_dir / "docker-proxy-squid-lifecycle.lock").symlink_to(target)
    monkeypatch.setenv("SQUID_LIFECYCLE_LOCK_DIR", str(lock_dir))

    with pytest.raises(ValueError, match="safely open"):
        open_lifecycle_lock()

    assert target.read_text(encoding="utf-8") == "unchanged"


def test_lifecycle_lock_rejects_symlinked_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_dir = tmp_path / "real"
    real_dir.mkdir(mode=0o700)
    linked_dir = tmp_path / "linked"
    linked_dir.symlink_to(real_dir, target_is_directory=True)
    monkeypatch.setenv("SQUID_LIFECYCLE_LOCK_DIR", str(linked_dir))

    with pytest.raises(ValueError, match="safely open"):
        open_lifecycle_lock()

    assert not (real_dir / "docker-proxy-squid-lifecycle.lock").exists()


def test_lifecycle_lock_does_not_create_through_symlinked_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_dir = tmp_path / "real"
    real_dir.mkdir(mode=0o700)
    linked_dir = tmp_path / "linked"
    linked_dir.symlink_to(real_dir, target_is_directory=True)
    target_dir = real_dir / "created-through-symlink"
    monkeypatch.setenv(
        "SQUID_LIFECYCLE_LOCK_DIR",
        str(linked_dir / target_dir.name),
    )

    with pytest.raises(ValueError, match="safely open"):
        open_lifecycle_lock()

    assert not target_dir.exists()


def test_lifecycle_lock_rejects_publicly_writable_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock_dir = tmp_path / "locks"
    lock_dir.mkdir(mode=0o777)
    lock_dir.chmod(0o777)
    monkeypatch.setenv("SQUID_LIFECYCLE_LOCK_DIR", str(lock_dir))

    with pytest.raises(ValueError, match="owned by this user and private"):
        open_lifecycle_lock()


def test_real_lock_exec_blocks_python_lifecycle_lock_until_handoff_release(
    tmp_path: Path,
) -> None:
    lock_dir = tmp_path / "squid-lock"
    fallback_dir = tmp_path / "fallback-lock"
    ready = tmp_path / "ready"
    release = tmp_path / "release"
    helper = tmp_path / "holder.py"
    helper.write_text(
        "from pathlib import Path\n"
        "import os, time\n"
        "Path(os.environ['READY']).write_text('ready')\n"
        "while not Path(os.environ['RELEASE']).exists(): time.sleep(0.01)\n",
        encoding="utf-8",
    )
    env = {
        **os.environ,
        "SQUID_LIFECYCLE_LOCK_DIR": str(lock_dir),
        "PROXY_RUNTIME_LOCK_DIR": str(fallback_dir),
        "READY": str(ready),
        "RELEASE": str(release),
    }
    holder = subprocess.Popen(
        [
            sys.executable,
            str(WEB_ROOT / "services" / "squid_transaction.py"),
            "lock-exec",
            sys.executable,
            str(helper),
        ],
        env=env,
    )
    deadline = time.monotonic() + 5
    while not ready.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert ready.exists()

    contender_code = (
        "from services.squid_core import _exclusive_squid_lifecycle_lock\n"
        "with _exclusive_squid_lifecycle_lock(): print('acquired', flush=True)\n"
    )
    contender = subprocess.Popen(
        [sys.executable, "-c", contender_code],
        cwd=WEB_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        with pytest.raises(subprocess.TimeoutExpired):
            contender.communicate(timeout=0.2)
        release.write_text("release", encoding="utf-8")
        assert holder.wait(timeout=5) == 0
        stdout, _ = contender.communicate(timeout=5)
        assert stdout.strip() == "acquired"
        assert (lock_dir / "docker-proxy-squid-lifecycle.lock").exists()
        assert not (fallback_dir / "docker-proxy-squid-lifecycle.lock").exists()
    finally:
        holder.kill()
        contender.kill()
