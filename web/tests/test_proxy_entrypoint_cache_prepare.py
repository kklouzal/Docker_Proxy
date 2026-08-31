from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _cache_prepare_function() -> str:
    entrypoint = (REPO_ROOT / "docker" / "entrypoint.sh").read_text(encoding="utf-8")
    match = re.search(
        r"^run_squid_cache_prepare\(\) \{\n.*?^\}\n",
        entrypoint,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert match is not None
    return match.group(0)


def _fake_squid(tmp_path: Path) -> tuple[Path, Path]:
    argv_path = tmp_path / "argv"
    squid = tmp_path / "squid"
    squid.write_text(
        "#!/bin/sh\n"
        'printf \'%s\\n\' "$@" > "$SQUID_ARGV_PATH"\n'
        'case " $* " in\n'
        "  *' --foreground '*) ;;\n"
        "  *) printf '%s\\n' 'ERROR: safeunlink: Could not delete /var/run/squid.pid' >&2 ;;\n"
        "esac\n"
        'exit "${SQUID_EXIT_STATUS:-0}"\n',
        encoding="utf-8",
    )
    squid.chmod(0o755)
    return squid, argv_path


def _run_cache_prepare(
    tmp_path: Path, *, exit_status: int = 0
) -> subprocess.CompletedProcess[str]:
    _squid, argv_path = _fake_squid(tmp_path)
    env = {
        **os.environ,
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "SQUID_ARGV_PATH": str(argv_path),
        "SQUID_EXIT_STATUS": str(exit_status),
    }
    script = f"{_cache_prepare_function()}\nrun_squid_cache_prepare"
    return subprocess.run(
        ["sh", "-c", script],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_cache_prepare_uses_synchronous_smp_path_without_absent_pid_warning(
    tmp_path: Path,
) -> None:
    result = _run_cache_prepare(tmp_path)

    assert result.returncode == 0
    assert result.stderr == ""
    assert (tmp_path / "argv").read_text(encoding="utf-8").splitlines() == [
        "--foreground",
        "-z",
        "-f",
        "/etc/squid/squid.conf",
    ]


def test_cache_prepare_propagates_real_squid_failure(tmp_path: Path) -> None:
    result = _run_cache_prepare(tmp_path, exit_status=17)

    assert result.returncode == 17
