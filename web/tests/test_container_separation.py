from __future__ import annotations

from pathlib import Path

from .mysql_test_utils import REPO_ROOT


def _read(path: str) -> str:
    return (REPO_ROOT / path).read_text(encoding="utf-8")


def test_proxy_dockerfile_copies_only_proxy_runtime_payload() -> None:
    text = _read("docker/Dockerfile.proxy")

    assert "COPY web /app" not in text
    assert "COPY proxy /app/proxy" in text
    assert "COPY web/requirements.txt /app/requirements.txt" in text

    for required in (
        "web/services/certificate_runtime.py",
        "web/services/squid_runtime.py",
        "web/services/proxy_webfilter_store.py",
        "web/tools/pac_http_server.py",
        "web/tools/webfilter_apply.py",
        "web/tools/sslfilter_apply.py",
        "web/tools/webcat_acl.py",
        "scripts/generate_ca.sh",
        "scripts/init_ssl_db.sh",
    ):
        assert required in text

    for excluded_copy in (
        "COPY web/app.py",
        "COPY web/wsgi.py",
        "COPY web/templates",
        "COPY web/static",
        "web/services/auth_store.py",
        "web/services/audit_store.py",
        "web/services/background_guard.py",
        "web/services/housekeeping.py",
        "web/services/proxy_client.py",
        "web/services/squid_config_forms.py",
        "web/services/webfilter_store.py",
        "web/services/cert_manager.py",
        "web/services/squidctl.py",
        "web/tools/webcat_build.py",
        "scripts/reload_squid.sh",
    ):
        assert excluded_copy not in text


def test_admin_dockerfile_still_copies_admin_web_app() -> None:
    text = _read("docker/Dockerfile.admin")
    assert "COPY web /app" in text
