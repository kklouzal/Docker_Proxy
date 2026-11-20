"""Behavior of the packaged proxy container healthcheck and its entrypoint handoff."""

from __future__ import annotations

import os
import re
import socket
from pathlib import Path

import pytest

from .subprocess_test_utils import run_test_process

REPO_ROOT = Path(__file__).resolve().parents[2]
WEB_ROOT = REPO_ROOT / "web"
ENTRYPOINT = REPO_ROOT / "docker" / "entrypoint.sh"
HEALTHCHECK = REPO_ROOT / "docker" / "healthcheck.sh"


def _shell_function(script: str, name: str) -> str:
    match = re.search(
        rf"^{name}\(\) \{{\n.*?^\}}\n",
        script,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert match is not None, name
    return match.group(0)


def _entrypoint_healthcheck_env_writer() -> str:
    entrypoint = ENTRYPOINT.read_text(encoding="utf-8")
    start = entrypoint.index("shell_quote() {")
    end_marker = 'mv -f "${HEALTHCHECK_ENV_FILE}.tmp" "$HEALTHCHECK_ENV_FILE"\n'
    end = entrypoint.index(end_marker, start) + len(end_marker)
    helpers = "".join(
        _shell_function(entrypoint, name)
        for name in ("env_enabled", "sanitize_bounded_int", "sanitize_port")
    )
    return helpers + entrypoint[start:end]


def _write_healthcheck_env(tmp_path: Path, **env: str) -> dict[str, str]:
    env_file = tmp_path / "run" / "healthcheck.env"
    resolved = {
        "WORKERS": "2",
        "CICAP_PORT": "14000",
        "CICAP_AV_PORT": "14002",
        "CICAP_AV_RESP_PORT": "14004",
        "CLAMD_HOST": "clamd.example",
        "CLAMD_PORT": "3310",
        "CLAMD_HOST_IS_REMOTE": "1",
        "CLAMAV_REQUIRED": "1",
        "ADBLOCK_BYPASS": "on",
        "PAC_HTTP_HOST": "0.0.0.0",  # ruff: ignore[hardcoded-bind-all-interfaces] - entrypoint default bind.
        "PAC_HTTP_PORT": "8080",
        "FORWARDING_CANARY_HOST": "127.0.0.1",
        "FORWARDING_CANARY_PORT": "18081",
        "FORWARDING_CANARY_PATH": "/canary'quote",
        **env,
        "HEALTHCHECK_ENV_FILE": str(env_file),
        "PATH": os.environ["PATH"],
    }
    dump = 'set -a; . "$HEALTHCHECK_ENV_FILE"; env -0'
    result = run_test_process(
        ["sh", "-c", _entrypoint_healthcheck_env_writer() + dump],
        env=resolved,
        capture_output=True,
        check=True,
    )
    assert env_file.exists()
    assert not env_file.with_name("healthcheck.env.tmp").exists()
    sourced = dict(
        item.split("=", 1)
        for item in result.stdout.decode("utf-8").split("\0")
        if "=" in item
    )
    # Values the healthcheck's Python probes read must be exported.
    exported = run_test_process(
        [
            "sh",
            "-c",
            f'. "{env_file}"; python3 -c "import os,sys; sys.stdout.write(os.environ[\'FORWARDING_CANARY_PATH\'])"',
        ],
        env={"PATH": os.environ["PATH"]},
        capture_output=True,
        text=True,
        check=True,
    )
    assert exported.stdout == sourced["FORWARDING_CANARY_PATH"]
    return sourced


def test_entrypoint_records_resolved_values_for_the_healthcheck(tmp_path) -> None:
    values = _write_healthcheck_env(
        tmp_path,
        ADBLOCK_BYPASS="off",
        PROXY_HEALTHCHECK_FORWARDING_REQUIRED="yes",
        SQUID_HTTP_PORT="not-a-port",
        SQUID_ICAP_READY_HEALTH_PROBE_TIMEOUT_SECONDS="0.5",
    )

    assert values["SQUID_WORKERS"] == "2"
    assert values["SQUID_HTTP_PORT"] == "3128"
    assert values["CICAP_AV_PORT"] == "14002"
    assert values["CICAP_AV_RESP_PORT"] == "14004"
    assert values["CLAMD_HOST"] == "clamd.example"
    assert values["CLAMD_HOST_IS_REMOTE"] == "1"
    assert values["CLAMAV_REQUIRED"] == "1"
    assert values["ADBLOCK_ICAP_REQUIRED"] == "1"
    assert values["PROXY_HEALTHCHECK_FORWARDING_REQUIRED"] == "1"
    assert values["PAC_HTTP_PORT"] == "8080"
    assert values["FORWARDING_CANARY_PORT"] == "18081"
    assert values["FORWARDING_CANARY_PATH"] == "/canary'quote"
    assert values["SQUID_ICAP_READY_HEALTH_PROBE_TIMEOUT_SECONDS"] == "0.5"


def test_entrypoint_healthcheck_env_defaults_optional_requirements_off(
    tmp_path,
) -> None:
    values = _write_healthcheck_env(tmp_path, CLAMAV_REQUIRED="0")

    assert values["CLAMAV_REQUIRED"] == "0"
    assert values["ADBLOCK_ICAP_REQUIRED"] == "0"
    assert values["PROXY_HEALTHCHECK_FORWARDING_REQUIRED"] == "0"
    assert "SQUID_ICAP_READY_HEALTH_PROBE_TIMEOUT_SECONDS" not in values


def test_healthcheck_fails_until_the_entrypoint_recorded_its_settings(
    tmp_path,
) -> None:
    result = run_test_process(
        ["sh", str(HEALTHCHECK)],
        env={
            "PATH": os.environ["PATH"],
            "HEALTHCHECK_ENV_FILE": str(tmp_path / "missing.env"),
        },
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert "has not finished startup" in result.stdout


def _healthcheck_probe_script(body: str) -> str:
    healthcheck = HEALTHCHECK.read_text(encoding="utf-8")
    functions = "".join(
        _shell_function(healthcheck, name)
        for name in (
            "refresh_supervisor_status",
            "supervisor_program_running",
            "refresh_listen_ports",
            "has_listen_socket",
        )
    )
    return "SUPERVISORD_CONF=/etc/supervisord.conf\n" + functions + body


def test_healthcheck_reads_supervisor_status_once_and_matches_exact_names(
    tmp_path,
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "calls"
    fake = bin_dir / "supervisorctl"
    fake.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$*" >> "{calls}"\n'
        "printf 'cicap_adblock_1                  STOPPED   Not started\\n'\n"
        "printf 'cicap_adblock_10                 RUNNING   pid 7, uptime 0:01:00\\n'\n"
        "printf 'squid                            RUNNING   pid 8, uptime 0:01:00\\n'\n"
        "exit 3\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    body = (
        "refresh_supervisor_status\n"
        "for p in squid cicap_adblock_1 cicap_adblock_10 cicap_adblock; do\n"
        '  if supervisor_program_running "$p"; then echo "$p=up"; else echo "$p=down"; fi\n'
        "done\n"
    )

    result = run_test_process(
        ["sh", "-c", _healthcheck_probe_script(body)],
        env={"PATH": f"{bin_dir}:{os.environ['PATH']}"},
        capture_output=True,
        text=True,
        check=True,
    )

    assert result.stdout.split() == [
        "squid=up",
        "cicap_adblock_1=down",
        "cicap_adblock_10=up",
        "cicap_adblock=down",
    ]
    assert calls.read_text(encoding="utf-8").splitlines() == [
        "-c /etc/supervisord.conf status"
    ]


@pytest.mark.skipif(not Path("/proc/net/tcp").exists(), reason="needs Linux procfs")
def test_healthcheck_listener_snapshot_sees_listening_ports_only() -> None:
    with socket.socket() as listening, socket.socket() as bound_only:
        listening.bind(("127.0.0.1", 0))
        listening.listen(1)
        bound_only.bind(("127.0.0.1", 0))
        listening_port = listening.getsockname()[1]
        bound_port = bound_only.getsockname()[1]
        body = (
            "refresh_listen_ports\n"
            f"has_listen_socket {listening_port} && echo listening=up || echo listening=down\n"
            f"has_listen_socket {bound_port} && echo bound=up || echo bound=down\n"
        )
        result = run_test_process(
            ["sh", "-c", _healthcheck_probe_script(body)],
            env={"PATH": os.environ["PATH"]},
            capture_output=True,
            text=True,
            check=True,
        )

    assert result.stdout.split() == ["listening=up", "bound=down"]


def test_healthcheck_python_probes_import_from_the_packaged_services_root() -> None:
    healthcheck = HEALTHCHECK.read_text(encoding="utf-8")
    blocks = re.findall(
        r"python3 - <<'(PY|PYHEALTH)'\n(.*?)\n\1\n", healthcheck, flags=re.DOTALL
    )
    assert len(blocks) == 4
    for _tag, source in blocks:
        compile(source, "healthcheck-probe", "exec")
        for module in re.findall(r"^from (services\.\w+) import", source, re.MULTILINE):
            assert (WEB_ROOT / Path(*module.split("."))).with_suffix(".py").exists()
