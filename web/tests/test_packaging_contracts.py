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
    assert "/var/log/squid" not in admin_block

    proxy_block = compose.split("  proxy:", 1)[1]
    assert "- squid_logs:/var/log/squid" in proxy_block
    assert "squid_logs:" in _read("docker-compose.yml")
    assert "squid_logs:" in _read("docker-compose.ghcr.yml")

    live_compose = _read("docker-compose.live-tests.yml")
    assert "- squid_logs_edge_2:/var/log/squid" in live_compose
    assert "squid_logs_edge_2:" in live_compose

    entrypoint = _read("docker/entrypoint.sh")
    assert (
        "rm -f /var/run/c-icap/c-icap-adblock.pid; exec /usr/bin/c-icap -N -f /etc/c-icap/c-icap-adblock.conf"
        in entrypoint
    )
    assert "rm -f /var/run/c-icap/c-icap-av.pid; HOST=" in entrypoint


def test_repo_does_not_ship_stale_squid_mime_override() -> None:
    assert not (REPO_ROOT / "squid" / "mime.conf").exists()


def test_admin_runtime_defaults_keep_mysql_pool_bounded() -> None:
    entrypoint = _read("docker/entrypoint.admin.sh")
    supervisord = _read("docker/supervisord.admin.conf")
    env_example = _read("config/app.env.example")

    assert "--threads ${WEB_THREADS:-2}" in supervisord
    assert "# WEB_THREADS=2" in env_example
    assert 'web_threads="${WEB_THREADS:-2}"' in entrypoint
    assert "web_workers" not in entrypoint
    assert "derived_pool=$((web_threads + 1))" in entrypoint
    assert 'if [ "$derived_pool" -lt 2 ]; then' in entrypoint
    assert 'if [ "$derived_pool" -gt 8 ]; then' in entrypoint


def test_adblock_icap_only_adapts_browsing_methods() -> None:
    entrypoint = _read("docker/entrypoint.sh")

    assert "adaptation_access adblock_req_set allow all" not in entrypoint
    assert "acl icap_adblockable method GET HEAD" in entrypoint
    assert "adaptation_access adblock_req_set allow icap_adblockable" in entrypoint
    assert "adaptation_access adblock_req_set deny all" in entrypoint


def test_linux_container_payloads_are_lf_only() -> None:
    paths = [
        "docker/entrypoint.sh",
        "docker/entrypoint.admin.sh",
        "docker/healthcheck.sh",
        "docker/healthcheck.admin.sh",
        "docker/load-env.sh",
        "docker/squid_logrotate.sh",
        "scripts/generate_ca.sh",
        "scripts/init_ssl_db.sh",
        "docker/supervisord.proxy.conf",
        "docker/supervisord.admin.conf",
        "docker/c-icap.conf",
        "docker/adblock_req.conf",
        "docker/virus_scan.conf",
        "docker/clamd_mod.conf",
    ]

    offenders = [path for path in paths if b"\r\n" in (REPO_ROOT / path).read_bytes()]

    assert offenders == []
