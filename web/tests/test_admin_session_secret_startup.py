from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import subprocess

import pytest

from .subprocess_test_utils import run_test_process

WEB_DIR = Path(__file__).resolve().parents[1]
_SECRET_ENV_NAMES = ("FLASK_SECRET_KEY", "APP_SECRET_KEY", "SECRET_KEY")
_DATABASE_ENV_NAMES = ("DATABASE_URL", "MYSQL_HOST", "MYSQL_DATABASE", "MYSQL_USER")
_BOOTSTRAP_PROBE = """
import json
import os
import sys

import services.directory_auth as directory_module
import services.auth_store as auth_module
import services.saml_auth as saml_module

failures = set(filter(None, os.environ["ADMIN_BOOTSTRAP_FAILURES"].split(",")))
events = []


class FakeAuthStore:
    def get_or_create_secret_key(self):
        return auth_module.AuthStore().get_or_create_secret_key()

    def bootstrap_admin(self, username, password):
        events.append(f"local:{username}")
        if "local" in failures:
            raise RuntimeError("deterministic local bootstrap failure")

    def any_users(self):
        return False


class FakeDirectoryStore:
    def ensure_default_profiles(self):
        events.append("directory")
        if "directory" in failures:
            raise RuntimeError("deterministic directory bootstrap failure")


class FakeSamlStore:
    def ensure_default_profile(self):
        events.append("saml")
        if "saml" in failures:
            raise RuntimeError("deterministic SAML bootstrap failure")


directory_module.get_directory_auth_store = lambda _secret: FakeDirectoryStore()
auth_module.get_auth_store = lambda: FakeAuthStore()
saml_module.get_saml_auth_store = lambda: FakeSamlStore()

try:
    import app
except BaseException:
    print(f"ADMIN_BOOTSTRAP_EVENTS={json.dumps(events)}", file=sys.stderr)
    raise
else:
    print(app.app.secret_key)
    print(f"ADMIN_BOOTSTRAP_EVENTS={json.dumps(events)}", file=sys.stderr)
"""


def _import_admin_app(
    secret_path: Path,
    *,
    configured_secret: str = "",
    bootstrap_failures: tuple[str, ...] = (),
    bootstrap_username: str | None = None,
    bootstrap_password: str | None = None,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    for name in (
        *_SECRET_ENV_NAMES,
        *_DATABASE_ENV_NAMES,
        "ADMIN_BOOTSTRAP_USERNAME",
        "ADMIN_BOOTSTRAP_PASSWORD",
    ):
        env.pop(name, None)
    env.update(
        DISABLE_BACKGROUND="1",
        FLASK_SECRET_PATH=str(secret_path),
        MYSQL_DATABASE="mock_admin",
        MYSQL_HOST="mock-production-db",
        MYSQL_SCHEMA_MIGRATIONS_DISABLED="1",
        MYSQL_USER="mock_admin",
    )
    if configured_secret:
        env["FLASK_SECRET_KEY"] = configured_secret
    if bootstrap_username is not None:
        env["ADMIN_BOOTSTRAP_USERNAME"] = bootstrap_username
    if bootstrap_password is not None:
        env["ADMIN_BOOTSTRAP_PASSWORD"] = bootstrap_password
    env["ADMIN_BOOTSTRAP_FAILURES"] = ",".join(bootstrap_failures)

    return run_test_process(
        [sys.executable, "-c", _BOOTSTRAP_PROBE],
        cwd=WEB_DIR,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize(
    ("username", "password"),
    [("first-admin", None), (None, "not-retained-bootstrap-password")],
)
def test_admin_startup_rejects_unpaired_local_bootstrap_configuration(
    tmp_path: Path,
    username: str | None,
    password: str | None,
) -> None:
    result = _import_admin_app(
        tmp_path / "flask_secret.key",
        configured_secret="configured-production-secret",
        bootstrap_username=username,
        bootstrap_password=password,
    )

    assert result.returncode != 0
    assert "must either both be set or both be unset" in result.stderr
    assert "not-retained-bootstrap-password" not in result.stderr
    assert "ADMIN_BOOTSTRAP_EVENTS=[]" in result.stderr


def test_admin_startup_consumes_bootstrap_and_propagates_failure(
    tmp_path: Path,
) -> None:
    password = "not-retained-bootstrap-password"
    result = _import_admin_app(
        tmp_path / "flask_secret.key",
        configured_secret="configured-production-secret",
        bootstrap_failures=("local",),
        bootstrap_username="first-admin",
        bootstrap_password=password,
    )

    assert result.returncode != 0
    assert "deterministic local bootstrap failure" in result.stderr
    assert password not in result.stderr
    assert 'ADMIN_BOOTSTRAP_EVENTS=["local:first-admin"]' in result.stderr


def test_admin_startup_fails_when_persistent_session_secret_is_unavailable(
    tmp_path: Path,
) -> None:
    blocking_file = tmp_path / "not-a-directory"
    blocking_file.write_text("block secret directory creation", encoding="utf-8")

    result = _import_admin_app(
        blocking_file / "flask_secret.key",
        bootstrap_failures=("directory", "saml"),
    )

    assert result.returncode != 0
    assert "Failed to initialize persistent Flask session secret" in result.stderr
    assert "Failed to initialize default auth provider profiles" not in result.stderr
    assert "ADMIN_BOOTSTRAP_EVENTS=[]" in result.stderr


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


@pytest.mark.parametrize(
    ("bootstrap_failure", "expected_log", "unexpected_log", "provider_label"),
    [
        (
            "directory",
            "Failed to initialize directory auth provider profiles",
            "Failed to initialize SAML auth provider profile",
            "directory",
        ),
        (
            "saml",
            "Failed to initialize SAML auth provider profile",
            "Failed to initialize directory auth provider profiles",
            "SAML",
        ),
    ],
)
def test_admin_startup_reports_each_auth_provider_bootstrap_failure(
    tmp_path: Path,
    bootstrap_failure: str,
    expected_log: str,
    unexpected_log: str,
    provider_label: str,
) -> None:
    result = _import_admin_app(
        tmp_path / "flask_secret.key",
        configured_secret="configured-production-secret",
        bootstrap_failures=(bootstrap_failure,),
    )

    assert result.returncode != 0
    assert expected_log in result.stderr
    assert unexpected_log not in result.stderr
    assert (
        f"Failed to initialize default auth provider profiles: {provider_label}."
        in result.stderr
    )
    assert 'ADMIN_BOOTSTRAP_EVENTS=["directory", "saml"]' in result.stderr


def test_admin_startup_reports_all_auth_provider_bootstrap_failures_before_exit(
    tmp_path: Path,
) -> None:
    result = _import_admin_app(
        tmp_path / "flask_secret.key",
        configured_secret="configured-production-secret",
        bootstrap_failures=("directory", "saml"),
    )

    assert result.returncode != 0
    assert "Failed to initialize directory auth provider profiles" in result.stderr
    assert "Failed to initialize SAML auth provider profile" in result.stderr
    assert (
        "Failed to initialize default auth provider profiles: directory, SAML."
        in result.stderr
    )
    assert 'ADMIN_BOOTSTRAP_EVENTS=["directory", "saml"]' in result.stderr
