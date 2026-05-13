from __future__ import annotations

from .mysql_test_utils import REPO_ROOT

def _read(path: str) -> str:
    return (REPO_ROOT / path).read_text(encoding="utf-8")

def test_proxy_and_admin_dockerfiles_keep_runtime_payloads_separated() -> None:
    proxy = _read("docker/Dockerfile.proxy")
    admin = _read("docker/Dockerfile.admin")
    assert "COPY web /app" not in proxy
    assert "COPY web /app" not in admin
    assert "COPY proxy /app/proxy" in proxy
    assert "COPY web/app.py" not in proxy
    assert "COPY web/templates" not in proxy
    assert "web/services/auth_store.py" not in proxy
    assert "web/services/webfilter_core.py" in proxy
    assert "web/services/domain_normalization.py" in proxy
    assert "web/services/domain_normalization.py" in admin
    assert "COPY web/app.py /app/app.py" in admin
    assert "COPY web/templates /app/templates" in admin
    assert "web/services/policy_materializer.py" not in admin
    assert "web/tools/webfilter_apply.py" not in admin

def test_admin_compose_and_cicap_startup_contracts() -> None:
    compose = _read("docker-compose.common.yml")
    admin_block = compose.split("  proxy:", 1)[0]
    assert "  admin-ui:" in admin_block
    assert "depends_on:" not in admin_block
    entrypoint = _read("docker/entrypoint.sh")
    assert "rm -f /var/run/c-icap/c-icap-adblock.pid; exec /usr/bin/c-icap -N -f /etc/c-icap/c-icap-adblock.conf" in entrypoint
    assert "rm -f /var/run/c-icap/c-icap-av.pid; HOST=" in entrypoint

def test_repo_does_not_ship_stale_squid_mime_override() -> None:
    assert not (REPO_ROOT / "squid" / "mime.conf").exists()
