from __future__ import annotations

import os
import subprocess
import sys

from .mysql_test_utils import REPO_ROOT


def _read(path: str) -> str:
    return (REPO_ROOT / path).read_text(encoding="utf-8")


def _entrypoint_listener_normalizer_script() -> str:
    text = _read("docker/entrypoint.sh")
    start_marker = 'SQUID_CFG_PATH="$file_path" python3 - <<\'PY\' || true\n'
    start = text.index(start_marker) + len(start_marker)
    end = text.index("\nPY\n}", start)
    return text[start:end]


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
    assert "derived_pool=$((web_threads + 12))" in entrypoint
    assert 'if [ "$derived_pool" -lt 16 ]; then' in entrypoint
    assert 'if [ "$derived_pool" -gt 32 ]; then' in entrypoint


def test_admin_healthcheck_does_not_queue_behind_wsgi_workers() -> None:
    healthcheck = _read("docker/healthcheck.admin.sh")

    assert "urllib.request" not in healthcheck
    assert "[g]unicorn.*wsgi:app" in healthcheck
    assert "socket.create_connection" in healthcheck


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


def test_compose_exposes_https_intercept_listener_knobs() -> None:
    compose = _read("docker-compose.common.yml")
    env_example = _read("config/app.env.example")
    readme = _read("README.md")

    assert (
        "${PROXY_PUBLIC_HTTPS_INTERCEPT_PORT:-3130}:"
        "${SQUID_HTTPS_INTERCEPT_PORT:-3130}"
    ) in compose
    assert (
        "SQUID_HTTPS_INTERCEPT_ENABLED: ${SQUID_HTTPS_INTERCEPT_ENABLED:-}"
        in compose
    )
    assert (
        "SQUID_HTTPS_INTERCEPT_SPLICE_ONLY: "
        "${SQUID_HTTPS_INTERCEPT_SPLICE_ONLY:-}"
    ) in compose
    assert "# SQUID_HTTPS_INTERCEPT_ENABLED=0" in env_example
    assert "# PROXY_PUBLIC_HTTPS_INTERCEPT_PORT=3130" in env_example
    assert "SQUID_HTTPS_INTERCEPT_ENABLED" in readme


def test_proxy_entrypoint_env_can_materialize_https_intercept_listener(tmp_path) -> None:
    config = tmp_path / "squid.conf"
    config.write_text(
        "http_port 0.0.0.0:3128 ssl-bump \\\n"
        "\tcert=/etc/squid/ssl/certs/ca.crt \\\n"
        "\tkey=/etc/squid/ssl/certs/ca.key \\\n"
        "\tgenerate-host-certificates=on \\\n"
        "\tdynamic_cert_mem_cache_size=256MB\n",
        encoding="utf-8",
    )

    env = os.environ.copy()
    env.update(
        {
            "SQUID_CFG_PATH": str(config),
            "SQUID_HTTPS_INTERCEPT_ENABLED": "1",
            "SQUID_HTTPS_INTERCEPT_PORT": "3130",
        },
    )
    subprocess.run(
        [sys.executable, "-c", _entrypoint_listener_normalizer_script()],
        check=True,
        env=env,
    )

    rendered = config.read_text(encoding="utf-8")
    assert "# BEGIN SQUID-UI HTTPS INTERCEPT LISTENER" in rendered
    assert "https_port 0.0.0.0:3130 intercept ssl-bump" in rendered
    assert "name=https_intercept" in rendered


def test_proxy_entrypoint_env_can_toggle_https_intercept_splice_rule(tmp_path) -> None:
    config = tmp_path / "squid.conf"
    config.write_text(
        "http_port 0.0.0.0:3128 ssl-bump\n"
        "ssl_bump peek step1\n"
        "include /etc/squid/conf.d/10-sslfilter.conf\n"
        "ssl_bump stare step2\n"
        "ssl_bump bump step3\n",
        encoding="utf-8",
    )

    env = os.environ.copy()
    env.update(
        {
            "SQUID_CFG_PATH": str(config),
            "SQUID_HTTPS_INTERCEPT_ENABLED": "1",
            "SQUID_HTTPS_INTERCEPT_PORT": "3130",
            "SQUID_HTTPS_INTERCEPT_SPLICE_ONLY": "1",
        },
    )
    subprocess.run(
        [sys.executable, "-c", _entrypoint_listener_normalizer_script()],
        check=True,
        env=env,
    )

    rendered = config.read_text(encoding="utf-8")
    assert "ssl_bump peek step1" in rendered
    assert "acl https_intercept_listener myportname https_intercept" in rendered
    assert "ssl_bump splice https_intercept_listener" in rendered
    assert rendered.index("ssl_bump peek step1") < rendered.index(
        "ssl_bump splice https_intercept_listener",
    )
    assert rendered.index("ssl_bump splice https_intercept_listener") < rendered.index(
        "include /etc/squid/conf.d/10-sslfilter.conf",
    )

    env["SQUID_HTTPS_INTERCEPT_SPLICE_ONLY"] = "0"
    subprocess.run(
        [sys.executable, "-c", _entrypoint_listener_normalizer_script()],
        check=True,
        env=env,
    )

    rendered = config.read_text(encoding="utf-8")
    assert "ssl_bump splice https_intercept_listener" not in rendered


def test_proxy_entrypoint_env_disabling_https_intercept_removes_managed_splice(
    tmp_path,
) -> None:
    config = tmp_path / "squid.conf"
    config.write_text(
        "http_port 0.0.0.0:3128 ssl-bump\n"
        "ssl_bump peek step1\n"
        "# BEGIN SQUID-UI HTTPS INTERCEPT SPLICE\n"
        "# Splice all traffic arriving on the dedicated HTTPS NAT intercept listener.\n"
        "acl https_intercept_listener myportname https_intercept\n"
        "ssl_bump splice https_intercept_listener\n"
        "# END SQUID-UI HTTPS INTERCEPT SPLICE\n"
        "# BEGIN SQUID-UI HTTPS INTERCEPT LISTENER\n"
        "# HTTPS NAT intercept listener. Requires TCP/443 REDIRECT/DNAT and explicit operator consent.\n"
        "https_port 0.0.0.0:3130 intercept ssl-bump \\\n"
        "\tname=https_intercept \\\n"
        "\tcert=/etc/squid/ssl/certs/ca.crt \\\n"
        "\tkey=/etc/squid/ssl/certs/ca.key \\\n"
        "\tgenerate-host-certificates=on \\\n"
        "\tdynamic_cert_mem_cache_size=128MB\n"
        "# END SQUID-UI HTTPS INTERCEPT LISTENER\n",
        encoding="utf-8",
    )

    env = os.environ.copy()
    env.update(
        {
            "SQUID_CFG_PATH": str(config),
            "SQUID_HTTPS_INTERCEPT_ENABLED": "0",
        },
    )
    subprocess.run(
        [sys.executable, "-c", _entrypoint_listener_normalizer_script()],
        check=True,
        env=env,
    )

    rendered = config.read_text(encoding="utf-8")
    assert "# BEGIN SQUID-UI HTTPS INTERCEPT LISTENER" not in rendered
    assert "# BEGIN SQUID-UI HTTPS INTERCEPT SPLICE" not in rendered
    assert "https_intercept_listener" not in rendered


def test_proxy_entrypoint_env_avoids_listener_port_collisions(tmp_path) -> None:
    config = tmp_path / "squid.conf"
    config.write_text("http_port 0.0.0.0:3130 ssl-bump\n", encoding="utf-8")

    env = os.environ.copy()
    env.update(
        {
            "SQUID_CFG_PATH": str(config),
            "SQUID_INTERCEPT_ENABLED": "1",
            "SQUID_INTERCEPT_PORT": "3131",
            "SQUID_HTTPS_INTERCEPT_ENABLED": "1",
            "SQUID_HTTPS_INTERCEPT_PORT": "3131",
        },
    )
    subprocess.run(
        [sys.executable, "-c", _entrypoint_listener_normalizer_script()],
        check=True,
        env=env,
        timeout=5,
    )

    rendered = config.read_text(encoding="utf-8")
    assert "http_port 0.0.0.0:3130 ssl-bump" in rendered
    assert "http_port 0.0.0.0:3131 intercept" in rendered
    assert "https_port 0.0.0.0:3132 intercept ssl-bump" in rendered
