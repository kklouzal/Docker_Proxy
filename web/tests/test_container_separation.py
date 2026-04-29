from __future__ import annotations

from pathlib import Path

from .mysql_test_utils import REPO_ROOT


def _read(path: str) -> str:
    return (REPO_ROOT / path).read_text(encoding="utf-8")


def test_repo_does_not_ship_stale_squid_mime_override() -> None:
    assert not (REPO_ROOT / "squid" / "mime.conf").exists()


def test_proxy_dockerfile_copies_only_proxy_runtime_payload() -> None:
    text = _read("docker/Dockerfile.proxy")

    assert "COPY web /app" not in text
    assert "FROM alpine:${ALPINE_VERSION} AS python_deps" in text
    assert "COPY web/requirements.txt /tmp/deps/requirements.txt" in text
    assert "COPY --from=python_deps /python-deps/ /tmp/python-deps/" in text
    assert "site.getsitepackages()[0]" in text
    assert "COPY proxy /app/proxy" in text
    assert "COPY web/requirements.txt /app/requirements.txt" not in text
    assert "COPY docker/clamd_mod.conf /etc/clamd_mod.conf" not in text

    for required in (
        "web/services/certificate_core.py",
        "web/services/diagnostic_store.py",
        "web/services/squid_core.py",
        "web/services/webfilter_core.py",
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


def test_admin_dockerfile_copies_only_admin_control_plane_payload() -> None:
    text = _read("docker/Dockerfile.admin")
    assert "COPY web /app" not in text
    assert "FROM alpine:${ALPINE_VERSION} AS python_deps" in text
    assert "COPY web/requirements.txt /tmp/deps/requirements.txt" in text
    assert "COPY --from=python_deps /python-deps/ /tmp/python-deps/" in text
    assert "site.getsitepackages()[0]" in text
    for required in (
        "COPY web/app.py /app/app.py",
        "COPY web/wsgi.py /app/wsgi.py",
        "COPY web/static /app/static",
        "COPY web/templates /app/templates",
        "web/services/auth_store.py",
        "web/services/audit_store.py",
        "web/services/background_guard.py",
        "web/services/certificate_core.py",
        "web/services/cert_manager.py",
        "web/services/certificate_bundles.py",
        "web/services/diagnostic_store.py",
        "web/services/proxy_client.py",
        "web/services/squid_core.py",
        "web/services/squidctl.py",
        "web/services/webfilter_core.py",
        "web/services/webfilter_store.py",
        "web/tools/adblock_compile.py",
        "web/tools/webcat_acl.py",
        "web/tools/webcat_build.py",
    ):
        assert required in text

    assert "COPY web/requirements.txt /app/requirements.txt" not in text

    for excluded_copy in (
        "web/services/policy_materializer.py",
        "web/tools/pac_http_server.py",
        "web/tools/webfilter_apply.py",
        "web/tools/sslfilter_apply.py",
        "COPY web/requirements-dev.txt",
    ):
        assert excluded_copy not in text
