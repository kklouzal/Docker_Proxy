from __future__ import annotations

import os
import subprocess
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[2] / "docker" / "squid_logrotate.sh"


def run_logrotate_once(
    tmp_path: Path,
    conf_text: str = "logfile_rotate 3\n",
    *,
    log_name: str = "access-observe.log",
) -> Path:
    log_path = tmp_path / log_name
    conf_path = tmp_path / "squid.conf"
    conf_path.write_text(conf_text, encoding="utf-8")

    env = os.environ.copy()
    env.update(
        {
            "SQUID_LOG_ROTATE_RUN_ONCE": "1",
            "SQUID_LOG_ROTATE_INITIAL_DELAY_SECONDS": "0",
            "SQUID_CONF_PATH": str(conf_path),
            "SQUID_LOG_ROTATE_LOGFILES": str(log_path),
        }
    )
    subprocess.run(["/bin/sh", str(SCRIPT_PATH)], check=True, env=env)
    return log_path


def test_squid_logrotate_copytruncates_observability_logs_without_runtime_rotate() -> None:
    script = SCRIPT_PATH.read_text(encoding="utf-8")

    assert "if ! squid -k rotate" not in script
    assert "squid -k rotate" in script  # comment only: documents why it is avoided.
    assert "/var/log/squid/access-observe.log" in script
    assert "/var/log/squid/icap.log" in script
    assert "/var/log/cicap-access.log" in script
    assert 'cp "$logfile" "${logfile}.1"' in script
    assert ': > "$logfile"' in script


def test_squid_logrotate_advances_numbered_history_instead_of_overwriting_dot_1(
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "access-observe.log"

    for content in ("first\n", "second\n", "third\n"):
        log_path.write_text(content, encoding="utf-8")
        run_logrotate_once(tmp_path)

    assert log_path.read_text(encoding="utf-8") == ""
    assert (tmp_path / "access-observe.log.1").read_text(encoding="utf-8") == "third\n"
    assert (tmp_path / "access-observe.log.2").read_text(encoding="utf-8") == "second\n"
    assert (tmp_path / "access-observe.log.3").read_text(encoding="utf-8") == "first\n"

    log_path.write_text("fourth\n", encoding="utf-8")
    run_logrotate_once(tmp_path)

    assert log_path.read_text(encoding="utf-8") == ""
    assert (tmp_path / "access-observe.log.1").read_text(encoding="utf-8") == "fourth\n"
    assert (tmp_path / "access-observe.log.2").read_text(encoding="utf-8") == "third\n"
    assert (tmp_path / "access-observe.log.3").read_text(encoding="utf-8") == "second\n"
    assert not (tmp_path / "access-observe.log.4").exists()


def test_squid_logrotate_uses_env_rotation_count_override(tmp_path: Path) -> None:
    log_path = tmp_path / "icap.log"
    conf_path = tmp_path / "squid.conf"
    conf_path.write_text("logfile_rotate 10\n", encoding="utf-8")

    env = os.environ.copy()
    env.update(
        {
            "SQUID_LOG_ROTATE_RUN_ONCE": "1",
            "SQUID_LOG_ROTATE_INITIAL_DELAY_SECONDS": "0",
            "SQUID_CONF_PATH": str(conf_path),
            "SQUID_LOG_ROTATE_LOGFILES": str(log_path),
            "SQUID_LOGFILE_ROTATE_COUNT": "2",
        }
    )

    for content in ("one\n", "two\n", "three\n"):
        log_path.write_text(content, encoding="utf-8")
        subprocess.run(["/bin/sh", str(SCRIPT_PATH)], check=True, env=env)

    assert log_path.read_text(encoding="utf-8") == ""
    assert (tmp_path / "icap.log.1").read_text(encoding="utf-8") == "three\n"
    assert (tmp_path / "icap.log.2").read_text(encoding="utf-8") == "two\n"
    assert not (tmp_path / "icap.log.3").exists()


def test_squid_logrotate_zero_retention_still_truncates_active_log(tmp_path: Path) -> None:
    log_path = tmp_path / "cicap-access.log"
    log_path.write_text("active\n", encoding="utf-8")

    run_logrotate_once(tmp_path, "logfile_rotate 0\n", log_name="cicap-access.log")

    assert log_path.read_text(encoding="utf-8") == ""
    assert not (tmp_path / "cicap-access.log.1").exists()
