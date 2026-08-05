from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

WEB_DIR = Path(__file__).resolve().parents[1]
_SECRET_ENV_NAMES = ("FLASK_SECRET_KEY", "APP_SECRET_KEY", "SECRET_KEY")
_DATABASE_ENV_NAMES = ("DATABASE_URL", "MYSQL_HOST", "MYSQL_DATABASE", "MYSQL_USER")


def _import_admin_app(
    secret_path: Path,
    *,
    configured_secret: str = "",
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    for name in (*_SECRET_ENV_NAMES, *_DATABASE_ENV_NAMES):
        env.pop(name, None)
    env.update(
        DISABLE_BACKGROUND="1",
        FLASK_SECRET_PATH=str(secret_path),
        MYSQL_SCHEMA_MIGRATIONS_DISABLED="1",
    )
    if configured_secret:
        env["FLASK_SECRET_KEY"] = configured_secret

    return subprocess.run(
        [sys.executable, "-c", "import app; print(app.app.secret_key)"],
        cwd=WEB_DIR,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )


def test_admin_startup_fails_when_persistent_session_secret_is_unavailable(
    tmp_path: Path,
) -> None:
    blocking_file = tmp_path / "not-a-directory"
    blocking_file.write_text("block secret directory creation", encoding="utf-8")

    result = _import_admin_app(blocking_file / "flask_secret.key")

    assert result.returncode != 0
    assert "Failed to initialize persistent Flask session secret" in result.stderr


def test_admin_startup_preserves_configured_session_secret_precedence(
    tmp_path: Path,
) -> None:
    blocking_file = tmp_path / "not-a-directory"
    blocking_file.write_text("block secret directory creation", encoding="utf-8")

    result = _import_admin_app(
        blocking_file / "flask_secret.key",
        configured_secret="configured-session-secret",
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "configured-session-secret"


def test_admin_startup_reuses_durable_generated_session_secret(tmp_path: Path) -> None:
    secret_path = tmp_path / "state" / "flask_secret.key"

    first = _import_admin_app(secret_path)
    second = _import_admin_app(secret_path)

    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    assert first.stdout.strip()
    assert second.stdout.strip() == first.stdout.strip()
    assert secret_path.read_text(encoding="utf-8").strip() == first.stdout.strip()
