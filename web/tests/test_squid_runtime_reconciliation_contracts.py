from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from services.squid_core import SquidController  # type: ignore

_REPO = Path(__file__).resolve().parents[2]
_LOOP_START = 'av_conf="/etc/c-icap/c-icap-av.conf"\n'
_LOOP_END = '\n{\n    echo "icap_service adblock_req '


def _entrypoint_supervisor_loop() -> str:
    text = (_REPO / "docker" / "entrypoint.sh").read_text(encoding="utf-8")
    start = text.index(_LOOP_START)
    end = text.index(_LOOP_END, start)
    return text[start:end]


@pytest.mark.parametrize(
    ("clamd_host", "remote", "squid_workers"),
    [("clamd.example.internal", "1", "1"), ("127.0.0.1", "0", "2")],
)
def test_runtime_icap_supervisor_files_match_entrypoint_bytes(
    tmp_path: Path,
    monkeypatch,
    clamd_host: str,
    remote: str,
    squid_workers: str,
) -> None:
    # Byte drift between the boot-time files and the runtime renderer makes the
    # first ICAP reconciliation after every boot pause and restart Squid.
    entry_dir = tmp_path / "entrypoint"
    entry_dir.mkdir()
    script = (
        _entrypoint_supervisor_loop()
        .replace("/etc/supervisor.d", str(entry_dir))
        # Skip the c-icap config copy; only the supervisor programs compare.
        .replace("/etc/c-icap/c-icap.conf", str(tmp_path / "missing.conf"))
    )
    env = {
        "PATH": "/usr/bin:/bin",
        "CICAP_PORT": "14000",
        "CICAP_AV_PORT": "14001",
        "CICAP_AV_RESP_PORT": "14002",
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
    monkeypatch.setenv("SQUID_WORKERS", squid_workers)
    monkeypatch.setenv("CLAMD_HOST", clamd_host)
    monkeypatch.setenv("CLAMD_PORT", "3310")
    monkeypatch.delenv("CLAMD_TIMEOUT", raising=False)
    monkeypatch.delenv("CLAMAV_RESPMOD_CLIENT_TIMEOUT", raising=False)
    monkeypatch.delenv("CLAMAV_RESPMOD_MAX_CONNECTIONS", raising=False)
    monkeypatch.delenv("CLAMAV_RESPMOD_MAX_SCANS", raising=False)
    rendered = SquidController()._render_icap_supervisor_files(config_text="")
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


def test_entrypoint_never_compiles_adblock_lists_at_boot(tmp_path: Path) -> None:
    # The Admin UI builder compiles artifacts; boot only provides an empty
    # lookup database when no artifact has been materialized yet.
    text = (_REPO / "docker" / "entrypoint.sh").read_text(encoding="utf-8")
    assert "adblock_compile.py" not in text
    start = text.index("# Adblock request lookup state.")
    block = text[start : text.index("\nfi\n", start) + 4]
    compiled = tmp_path / "compiled"
    calls = tmp_path / "calls"
    script = block.replace(
        "/var/lib/squid-flask-proxy/adblock/compiled", str(compiled)
    ).replace("python3 -", f"sh -c 'cat >/dev/null; echo empty-db >> {calls}'")

    subprocess.run(["sh", "-eu", "-c", script], check=True)
    assert calls.read_text() == "empty-db\n"

    # A materialized lookup database is left alone.
    calls.unlink()
    (compiled / "request_lookup.sqlite").write_bytes(b"artifact")
    subprocess.run(["sh", "-eu", "-c", script], check=True)
    assert not calls.exists()
    assert (compiled / "request_lookup.sqlite").read_bytes() == b"artifact"
