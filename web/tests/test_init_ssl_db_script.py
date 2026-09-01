from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from .subprocess_test_utils import run_test_process

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "init_ssl_db.sh"


def _validation_function() -> str:
    script = SCRIPT_PATH.read_text(encoding="utf-8")
    start = script.index("normalize_ssl_db_dir() {")
    end = script.index("\n}\n", start) + 3
    return script[start:end]


@pytest.mark.parametrize(
    ("configured", "expected"),
    [
        ("/var/lib/ssl_db/store", "/var/lib/ssl_db/store"),
        ("/var//lib/ssl_db/./store", "/var/lib/ssl_db/store"),
        ("/srv/proxy/ssl-db", "/srv/proxy/ssl-db"),
    ],
)
def test_ssl_db_path_contract_accepts_absolute_database_directories(
    configured: str,
    expected: str,
) -> None:
    result = run_test_process(
        [
            "sh",
            "-c",
            f'{_validation_function()}\nnormalize_ssl_db_dir "$1"',
            "sh",
            configured,
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert result.stdout.strip() == expected


@pytest.mark.parametrize(
    "configured",
    [
        "",
        ".",
        "relative/store",
        "/",
        "/etc",
        "/usr/.",
        "/var//lib",
        "/etc/ssl_db",
        "/usr/ssl_db",
        "/var/ssl_db",
        "/var/lib/ssl_db",
        "/var/lib/ssl_db/../../..",
    ],
)
def test_ssl_db_path_contract_rejects_unsafe_normalized_paths(configured: str) -> None:
    result = run_test_process(
        [
            "sh",
            "-c",
            f'{_validation_function()}\nnormalize_ssl_db_dir "$1"',
            "sh",
            configured,
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0


@pytest.mark.parametrize(
    "configured",
    [
        "relative/store",
        "/",
        "/etc/.",
        "/usr",
        "/var//lib",
        "/etc/ssl_db",
        "/usr/ssl_db",
        "/var/ssl_db",
        "/var/lib/ssl_db",
        "/var/lib/ssl_db/../../..",
    ],
)
def test_init_ssl_db_rejects_unsafe_path_before_filesystem_or_ca_work(
    tmp_path: Path,
    configured: str,
) -> None:
    marker = tmp_path / "unexpected-command"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for command in ("mkdir", "rm", "chown", "chmod", "getent", "ssl_crtd"):
        shim = bin_dir / command
        shim.write_text(
            f"#!/bin/sh\necho {command} >> {marker}\nexit 97\n", encoding="utf-8"
        )
        shim.chmod(0o755)

    result = run_test_process(
        ["sh", str(SCRIPT_PATH)],
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "SSL_DB_DIR": configured,
        },
    )

    assert result.returncode != 0
    assert "Refusing to initialize ssl_db at unsafe path" in result.stderr
    assert not marker.exists()
    assert "generate_ca.sh" not in result.stderr


@pytest.mark.parametrize(
    "configured",
    [
        "relative/store",
        "/",
        "/etc/.",
        "/usr",
        "/var//lib",
        "/etc/ssl_db",
        "/usr/ssl_db",
        "/var/ssl_db",
        "/var/lib/ssl_db",
        "/var/lib/ssl_db/../../..",
    ],
)
def test_runtime_reinitializer_rejects_unsafe_normalized_path_before_stop_or_delete(
    monkeypatch: pytest.MonkeyPatch,
    configured: str,
) -> None:
    from proxy.runtime import ProxyRuntime  # type: ignore

    runtime = object.__new__(ProxyRuntime)
    runtime.ssl_db_dir = configured

    def unexpected(*_args, **_kwargs):
        pytest.fail("destructive/runtime operation must not run")

    runtime.services = SimpleNamespace(ssl_db_reinitializer=unexpected)
    monkeypatch.setattr("proxy.runtime.subprocess.run", unexpected)
    monkeypatch.setattr("proxy.runtime.shutil.rmtree", unexpected)
    monkeypatch.setattr("proxy.runtime.pathlib.Path.mkdir", unexpected)

    ok, detail = runtime._reinitialize_ssl_db_and_restart()

    assert ok is False
    assert "unsafe path" in detail
