from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from services.squid_core import SquidController  # type: ignore

_REPO = Path(__file__).resolve().parents[2]
_LOOP_START = (
    'i=0\nwhile [ "$i" -lt "$WORKERS" ]; do\n    instance=$((i + 1))\n    adblock_port='
)
_LOOP_END = '\n{\n    adblock_services=""'


def _entrypoint_supervisor_loop() -> str:
    text = (_REPO / "docker" / "entrypoint.sh").read_text(encoding="utf-8")
    start = text.index(_LOOP_START)
    end = text.index(_LOOP_END, start)
    return text[start:end]


@pytest.mark.parametrize(
    ("clamd_host", "remote", "workers"),
    [("clamd.example.internal", "1", 1), ("127.0.0.1", "0", 2)],
)
def test_runtime_icap_supervisor_files_match_entrypoint_bytes(
    tmp_path: Path,
    monkeypatch,
    clamd_host: str,
    remote: str,
    workers: int,
) -> None:
    # Byte drift between the boot-time files and the runtime renderer makes the
    # first ICAP reconciliation after every boot pause and restart Squid.
    entry_dir = tmp_path / "entrypoint"
    entry_dir.mkdir()
    script = _entrypoint_supervisor_loop().replace("/etc/supervisor.d", str(entry_dir))
    env = {
        "PATH": "/usr/bin:/bin",
        "WORKERS": str(workers),
        "CICAP_PORT": "14000",
        "CICAP_AV_RESP_PORT": "14002" if workers == 1 else "14004",
        "CLAMD_HOST": clamd_host,
        "CLAMD_PORT": "3310",
        "CLAMAV_REQUIRED": "0",
        "CLAMD_HOST_IS_REMOTE": remote,
    }
    subprocess.run(["sh", "-eu", "-c", script], check=True, env=env)

    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    monkeypatch.setenv("SQUID_SUPERVISOR_INCLUDE_DIR", str(runtime_dir))
    monkeypatch.setenv("CICAP_CONFIG_DIR", "/etc/c-icap")
    monkeypatch.setenv("CICAP_RUN_DIR", "/var/run/c-icap")
    monkeypatch.setenv("CICAP_PORT", "14000")
    monkeypatch.delenv("CICAP_AV_PORT", raising=False)
    monkeypatch.delenv("CICAP_AV_RESP_PORT", raising=False)
    monkeypatch.setenv("CLAMD_HOST", clamd_host)
    monkeypatch.setenv("CLAMD_PORT", "3310")
    monkeypatch.delenv("CLAMD_TIMEOUT", raising=False)
    monkeypatch.delenv("CLAMAV_RESPMOD_CLIENT_TIMEOUT", raising=False)
    monkeypatch.delenv("CLAMAV_RESPMOD_MAX_CONNECTIONS", raising=False)
    monkeypatch.delenv("CLAMAV_RESPMOD_MAX_SCANS", raising=False)
    rendered = SquidController()._render_icap_supervisor_files(
        workers=workers,
        config_text="",
    )
    rendered_programs = {
        path.name: content
        for path, content in rendered.items()
        if path.parent == runtime_dir
    }
    entrypoint_programs = {
        path.name: path.read_text(encoding="utf-8")
        for path in sorted(entry_dir.iterdir())
    }

    assert entrypoint_programs == rendered_programs


def test_supervisor_squid_stop_timeout_covers_squid_stopwaitsecs() -> None:
    import configparser

    from services import squid_core  # type: ignore

    parser = configparser.RawConfigParser(inline_comment_prefixes=(";",))
    parser.read(_REPO / "docker" / "supervisord.proxy.conf", encoding="utf-8")
    stopwaitsecs = int(parser.get("program:squid", "stopwaitsecs"))
    # A normal draining stop (shutdown_lifetime + cleanup) must not be
    # misreported as a failed pause, which strands the Squid transaction journal.
    assert stopwaitsecs < squid_core.SUPERVISOR_SQUID_STOP_TIMEOUT_SECONDS


def test_entrypoint_keeps_materialized_adblock_artifact_at_boot(tmp_path: Path) -> None:
    from services import adblock_artifacts  # type: ignore

    text = (_REPO / "docker" / "entrypoint.sh").read_text(encoding="utf-8")
    start = text.index("# Adblock request lookup state.")
    block = text[start : text.index("\nfi\n", start) + 4]
    compiled = tmp_path / "compiled"
    compiled.mkdir()
    calls = tmp_path / "calls"
    script = "CONTROL_PLANE_DB_REACHABLE=1\n" + block.replace(
        "/var/lib/squid-flask-proxy/adblock/compiled", str(compiled)
    ).replace("python3 /app/tools/adblock_compile.py", f"echo compiled >> {calls}")

    # A materialized artifact owns the lookup DB: boot must not recompile it.
    (compiled / adblock_artifacts._ARTIFACT_SHA_FILENAME).write_text("a" * 64)
    subprocess.run(["sh", "-eu", "-c", script], check=True)
    assert not calls.exists()

    # Without an artifact the legacy local-list compile still runs.
    (compiled / adblock_artifacts._ARTIFACT_SHA_FILENAME).unlink()
    subprocess.run(["sh", "-eu", "-c", script], check=True)
    assert calls.read_text().startswith("compiled --lists-dir ")
