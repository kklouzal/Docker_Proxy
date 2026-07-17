from __future__ import annotations

import ast
import importlib.util
import os
import re
import subprocess
import sys
from types import SimpleNamespace

from .mysql_test_utils import REPO_ROOT


def _read(path: str) -> str:
    return (REPO_ROOT / path).read_text(encoding="utf-8")


def _load_start_admin_ui_module():
    path = REPO_ROOT / "web" / "tools" / "start_admin_ui.py"
    spec = importlib.util.spec_from_file_location("start_admin_ui_test_module", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _entrypoint_listener_normalizer_script() -> str:
    text = _read("docker/entrypoint.sh")
    start_marker = "SQUID_CFG_PATH=\"$file_path\" python3 - <<'PY' || true\n"
    start = text.index(start_marker) + len(start_marker)
    end = text.index("\nPY\n}", start)
    return text[start:end]


def _entrypoint_shell_block(start_marker: str, end_marker: str) -> str:
    text = _read("docker/entrypoint.sh")
    start = text.index(start_marker)
    end = text.index(end_marker, start)
    return text[start:end]


def _entrypoint_perf_tuning_script() -> str:
    return "\n".join(
        [
            _entrypoint_shell_block(
                "config_has_directive() {",
                "\nif [ -z \"${DB_POOL_MAX_IDLE_SECONDS:-}\" ]; then",
            ),
            _entrypoint_shell_block(
                "replace_or_append_config_line() {",
                "\nnormalize_http_port_listeners() {",
            ),
            _entrypoint_shell_block(
                "apply_squid_perf_tuning() {",
                "\npython3 /app/tools/adblock_compile.py",
            ),
        ],
    )


def _run_entrypoint_perf_tuning(config_path, *, children: int) -> None:
    script = (
        "set -eu\n"
        f"{_entrypoint_perf_tuning_script()}\n"
        "SQUID_WORKERS=4\n"
        "SQUID_CACHE_MEM_MB=256\n"
        f"SQUID_SSLCRTD_CHILDREN={children}\n"
        f"EXPLICIT_SQUID_SSLCRTD_CHILDREN={children}\n"
        "SQUID_MAX_FILEDESCRIPTORS=65536\n"
        "SQUID_DYNAMIC_CERT_MEM_CACHE_MB=256\n"
        "apply_squid_perf_tuning \"$1\"\n"
    )
    subprocess.run(
        ["/bin/sh", "-c", script, "entrypoint-perf-tuning-test", str(config_path)],
        check=True,
    )


def _python_module_imports_services(path: str) -> set[str]:
    tree = ast.parse(_read(path), filename=path)
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            parts = node.module.split(".")
            if len(parts) >= 2 and parts[0] == "services":
                imports.add(f"{parts[1]}.py")
            elif node.module == "services":
                imports.update(
                    f"{alias.name.split('.', 1)[0]}.py"
                    for alias in node.names
                    if alias.name != "*"
                )
        elif isinstance(node, ast.Import):
            for alias in node.names:
                parts = alias.name.split(".")
                if len(parts) >= 2 and parts[0] == "services":
                    imports.add(f"{parts[1]}.py")
    return imports


def _image_payload(dockerfile: str, pattern: str) -> set[str]:
    text = _read(dockerfile)
    return {match.rsplit("/", 1)[-1] for match in re.findall(pattern, text)}


def _proxy_image_payload(pattern: str) -> set[str]:
    return _image_payload("docker/Dockerfile.proxy", pattern)


def test_proxy_and_admin_dockerfiles_keep_runtime_payloads_separated() -> None:
    proxy = _read("docker/Dockerfile.proxy")
    admin = _read("docker/Dockerfile.admin")
    assert "COPY web /app" not in proxy
    assert "COPY web /app" not in admin
    assert "COPY proxy /app/proxy" in proxy
    assert "COPY web/app.py" not in proxy
    assert "COPY web/templates" not in proxy
    assert "web/services/auth_store.py" not in proxy
    assert "web/services/adblock_hosts.py" in proxy
    assert "web/services/webfilter_core.py" in proxy
    assert "web/services/helper_runtime.py" in proxy
    assert "web/services/download_safety.py" in proxy
    assert "web/services/domain_normalization.py" in proxy
    assert "web/services/version_status.py" in proxy
    assert "web/services/proxy_logs.py" in proxy
    assert "web/services/helper_runtime.py" in admin
    assert "web/services/download_safety.py" in admin
    assert "web/services/adblock_hosts.py" in admin
    assert "web/services/domain_normalization.py" in admin
    assert "web/services/version_status.py" in admin
    assert "COPY web/app.py /app/app.py" in admin
    assert "COPY web/templates /app/templates" in admin
    assert "web/services/policy_materializer.py" in admin
    assert "web/tools/webfilter_apply.py" not in admin
    assert "ARG GIT_COMMIT=" in proxy
    assert "ARG GIT_COMMIT=" in admin
    assert "GIT_COMMIT=${GIT_COMMIT}" in proxy
    assert "GIT_COMMIT=${GIT_COMMIT}" in admin


def test_proxy_dockerfile_includes_direct_service_import_dependencies() -> None:
    copied_services = _proxy_image_payload(r"web/services/[\w_]+\.py")
    copied_tools = _proxy_image_payload(r"web/tools/[\w_]+\.py")
    copied_roots = [
        "proxy/agent.py",
        "proxy/app.py",
        "proxy/runtime.py",
        *(f"web/services/{name}" for name in copied_services if name != "__init__.py"),
        *(f"web/tools/{name}" for name in copied_tools),
    ]

    required_services: set[str] = set()
    for path in copied_roots:
        required_services.update(_python_module_imports_services(path))

    assert sorted(required_services - copied_services) == []


def test_admin_dockerfile_includes_direct_service_import_dependencies() -> None:
    copied_services = _image_payload(
        "docker/Dockerfile.admin",
        r"web/services/[\w_]+\.py",
    )
    copied_tools = _image_payload("docker/Dockerfile.admin", r"web/tools/[\w_]+\.py")
    copied_roots = [
        "web/app.py",
        "web/wsgi.py",
        *(f"web/services/{name}" for name in copied_services if name != "__init__.py"),
        *(f"web/tools/{name}" for name in copied_tools),
    ]

    required_services: set[str] = set()
    for path in copied_roots:
        required_services.update(_python_module_imports_services(path))

    assert sorted(required_services - copied_services) == []


def test_ghcr_publish_passes_runtime_version_build_args() -> None:
    workflow = _read(".github/workflows/publish-ghcr.yml")

    assert "APP_VERSION=${{ github.ref_name }}" in workflow
    assert "GIT_COMMIT=${{ github.sha }}" in workflow
    assert "GIT_REF_NAME=${{ github.ref_name }}" in workflow


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
    assert "ADBLOCK_CACHE_TTL: ${ADBLOCK_CACHE_TTL:-}" in proxy_block
    assert "CICAP_AV_RESP_PORT: ${CICAP_AV_RESP_PORT:-}" in proxy_block
    assert (
        "ADBLOCK_ICAP_MAX_BODY_DRAIN_BYTES: ${ADBLOCK_ICAP_MAX_BODY_DRAIN_BYTES:-}"
    ) in proxy_block
    assert "--max-allowed-packet=${MYSQL_MAX_ALLOWED_PACKET:-256M}" in _read(
        "docker-compose.mysql.yml"
    )
    mysql_conf = _read("config/mysql/conf.d/99-docker-proxy-bounded-logs.cnf")
    assert "max_connections=160" in mysql_conf
    assert "max_allowed_packet=256M" in mysql_conf

    live_compose = _read("docker-compose.live-tests.yml")
    assert "- squid_logs_edge_2:/var/log/squid" in live_compose
    assert "squid_logs_edge_2:" in live_compose
    assert live_compose.count('test: ["CMD", "/healthcheck.sh"]') == 2
    assert "squid -k check >/dev/null 2>&1 && python3 -c" not in live_compose
    assert (
        "--max-allowed-packet=${LIVE_TEST_MYSQL_MAX_ALLOWED_PACKET:-256M}"
        in live_compose
    )

    entrypoint = _read("docker/entrypoint.sh")
    assert "python3 /app/tools/adblock_icap_server.py" in entrypoint
    assert (
        "--db /var/lib/squid-flask-proxy/adblock/compiled/request_lookup.sqlite"
        in entrypoint
    )
    assert "python3 /app/tools/clamav_respmod_icap_server.py" in entrypoint
    assert 'av_pid="/var/run/c-icap/c-icap-av-${instance}.pid"' in entrypoint
    assert 'rm -f "${av_pid}"; exec /usr/local/bin/cicap_av_runner.py "${av_conf}"' in entrypoint
    dockerfile = _read("docker/Dockerfile.proxy")
    assert "web/tools/clamav_respmod_icap_server.py" in dockerfile
    assert "COPY --chmod=755 docker/cicap_av_runner.py /usr/local/bin/cicap_av_runner.py" in dockerfile

    env_example = _read("config/app.env.example")
    assert "# CICAP_AV_RESP_PORT=" in env_example
    assert "# ADBLOCK_CACHE_TTL=3600" in env_example
    assert "# ADBLOCK_RULE_CACHE_MAX=50000" in env_example
    assert "# ADBLOCK_ICAP_MAX_BODY_DRAIN_BYTES=8388608" in env_example
    assert "MYSQL_MAX_ALLOWED_PACKET=256M" in env_example


def test_proxy_cicap_build_enables_compression_support_and_strips_artifacts() -> None:
    proxy = _read("docker/Dockerfile.proxy")

    assert "brotli-dev" in proxy
    assert "zstd-dev" in proxy
    assert "brotli-libs" in proxy
    assert "zstd-libs" in proxy
    assert "strip --strip-unneeded" in proxy
    runtime_packages = proxy.split("FROM alpine:${ALPINE_VERSION}", 2)[-1]
    assert " file" not in runtime_packages


def test_repo_does_not_ship_stale_squid_mime_override() -> None:
    assert not (REPO_ROOT / "squid" / "mime.conf").exists()


def test_repo_does_not_ship_stale_generated_clamd_mod_conf() -> None:
    assert not (REPO_ROOT / "docker" / "clamd_mod.conf").exists()


def test_admin_runtime_defaults_keep_mysql_pool_bounded() -> None:
    entrypoint = _read("docker/entrypoint.admin.sh")
    supervisord = _read("docker/supervisord.admin.conf")
    env_example = _read("config/app.env.example")

    assert "command=/usr/local/bin/start-admin-ui.sh" in supervisord
    assert "[unix_http_server]" in supervisord
    assert "[rpcinterface:supervisor]" in supervisord
    assert "[supervisorctl]" in supervisord
    assert "serverurl=unix:///tmp/supervisor.sock" in supervisord
    assert "COPY --chmod=755 docker/start-admin-ui.sh" in _read(
        "docker/Dockerfile.admin"
    )
    launcher = _read("web/tools/start_admin_ui.py")
    assert 'environ.get("WEB_THREADS") or "2"' in launcher
    assert "# WEB_THREADS=2" in env_example
    assert 'web_threads="${WEB_THREADS:-2}"' in entrypoint
    assert "web_workers" not in entrypoint
    assert "derived_pool=$((web_threads + 12))" in entrypoint
    assert 'if [ "$derived_pool" -lt 16 ]; then' in entrypoint
    assert 'if [ "$derived_pool" -gt 32 ]; then' in entrypoint


def test_observability_runtime_env_knobs_are_documented_and_composed() -> None:
    env_names = {
        "DB_POOL_MAX_IDLE_SECONDS",
        "LIVE_STATS_COMMIT_BATCH",
        "LIVE_STATS_COMMIT_INTERVAL_SECONDS",
        "LIVE_STATS_POLL_INTERVAL_SECONDS",
        "LIVE_STATS_MAX_PENDING_ROWS",
        "LIVE_STATS_DB_WRITE_BACKOFF_INITIAL_SECONDS",
        "LIVE_STATS_DB_WRITE_BACKOFF_MAX_SECONDS",
        "LIVE_STATS_DB_WRITE_BACKOFF_JITTER_RATIO",
        "DIAGNOSTIC_COMMIT_BATCH",
        "DIAGNOSTIC_COMMIT_INTERVAL_SECONDS",
        "DIAGNOSTIC_POLL_INTERVAL_SECONDS",
        "DIAGNOSTIC_PENDING_MAX_ROWS",
        "DIAGNOSTIC_DB_WRITE_BACKOFF_INITIAL_SECONDS",
        "DIAGNOSTIC_DB_WRITE_BACKOFF_MAX_SECONDS",
        "DIAGNOSTIC_DB_WRITE_BACKOFF_JITTER_RATIO",
        "TIMESERIES_ROLLUP_INTERVAL_SECONDS",
        "TIMESERIES_STARTUP_JITTER_SECONDS",
        "TIMESERIES_SAMPLE_DB_BACKOFF_INITIAL_SECONDS",
        "TIMESERIES_SAMPLE_DB_BACKOFF_MAX_SECONDS",
        "TIMESERIES_SAMPLE_DB_BACKOFF_JITTER_RATIO",
        "TIMESERIES_ROLLUP_DB_BACKOFF_INITIAL_SECONDS",
        "TIMESERIES_ROLLUP_DB_BACKOFF_MAX_SECONDS",
        "TIMESERIES_ROLLUP_DB_BACKOFF_JITTER_RATIO",
        "SSL_ERRORS_COMMIT_BATCH",
        "SSL_ERRORS_COMMIT_INTERVAL_SECONDS",
        "SSL_ERRORS_POLL_INTERVAL_SECONDS",
        "STATS_CACHE_DIR_SIZE_TTL_SECONDS",
    }
    env_example = _read("config/app.env.example")
    readme = _read("README.md")
    compose = _read("docker-compose.common.yml")
    entrypoint = _read("docker/entrypoint.sh")

    for name in sorted(env_names):
        assert name in env_example
        assert name in readme
        assert name in compose
        assert name in entrypoint


def test_proxy_launcher_env_knobs_are_sanitized_and_documented() -> None:
    env_names = {
        "PAC_HTTP_HOST",
        "PAC_HTTP_PORT",
        "WEB_WORKERS",
        "WEB_THREADS",
        "WEB_TIMEOUT",
        "WEB_GRACEFUL_TIMEOUT",
        "WEB_KEEPALIVE",
    }
    env_example = _read("config/app.env.example")
    readme = _read("README.md")
    compose = _read("docker-compose.common.yml")
    entrypoint = _read("docker/entrypoint.sh")
    supervisord = _read("docker/supervisord.proxy.conf")

    for name in sorted(env_names):
        assert name in env_example
        assert name in readme
        assert name in compose
        assert name in entrypoint
    assert '"${PAC_HTTP_HOST:-0.0.0.0}:${PAC_HTTP_PORT:-80}"' in supervisord
    assert '"${WEB_TIMEOUT:-120}"' in supervisord


def test_admin_ui_https_packaging_contract() -> None:
    compose = _read("docker-compose.common.yml")
    ghcr_compose = _read("docker-compose.ghcr.yml")
    server002_compose = _read("docker-compose.server002.yml")
    admin_block = compose.split("  proxy:", 1)[0]
    startup = _read("docker/start-admin-ui.sh")
    env_example = _read("config/app.env.example")
    readme = _read("README.md")

    assert "- ./squid/ssl/certs:/etc/squid/ssl/certs" in admin_block
    assert "- ./squid/ssl/certs:/etc/squid/ssl/certs:ro" not in admin_block
    assert "ADMIN_UI_HTTPS_ENABLED: ${ADMIN_UI_HTTPS_ENABLED:-0}" in admin_block
    assert "ADMIN_UI_SSL_CERTFILE: ${ADMIN_UI_SSL_CERTFILE:-}" in admin_block
    assert "ADMIN_UI_SSL_KEYFILE: ${ADMIN_UI_SSL_KEYFILE:-}" in admin_block
    assert "file: docker-compose.common.yml" in ghcr_compose
    assert "service: admin-ui" in ghcr_compose
    assert "image: ghcr.io/kklouzal/docker_proxy-admin-ui:main" in ghcr_compose
    assert "file: docker-compose.common.yml" in server002_compose
    assert "service: admin-ui" in server002_compose
    assert "exec python3 /app/tools/start_admin_ui.py" in startup
    assert "web/tools/start_admin_ui.py" in _read("docker/Dockerfile.admin")
    launcher = _read("web/tools/start_admin_ui.py")
    assert 'DEFAULT_CERTFILE = "/etc/squid/ssl/certs/admin-ui.crt"' in launcher
    assert 'DEFAULT_KEYFILE = "/etc/squid/ssl/certs/admin-ui.key"' in launcher
    assert '"--certfile", config.certfile, "--keyfile", config.keyfile' in launcher
    assert "# ADMIN_UI_HTTPS_ENABLED=0" in env_example
    assert "ADMIN_UI_SSL_CERTFILE and ADMIN_UI_SSL_KEYFILE are internal bootstrap" in env_example
    assert "prefer a server certificate whose subject/SAN matches" not in readme
    assert "dedicated Admin UI server leaf certificate" in readme
    assert "Admin UI container read-only" not in readme
    assert "mount is writable" in readme
    assert "saved DB setting is the source of truth" in readme
    assert "standalone admin-UI deployments must keep that same mount available" in readme


def test_admin_ui_startup_can_import_services_from_tools_launcher_path() -> None:
    script = """
import importlib.util
import pathlib
import sys

path = pathlib.Path("start_admin_ui.py").resolve()
spec = importlib.util.spec_from_file_location("start_admin_ui_launcher_test", path)
assert spec is not None
assert spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
config = module.resolve_admin_ui_https_config({"ADMIN_UI_HTTPS_ENABLED": "0"})
assert config.source == "env"
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=REPO_ROOT / "web" / "tools",
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "No module named 'services'" not in result.stderr
    assert "failed to prepare Admin UI HTTPS settings loader" not in result.stderr


def test_admin_ui_startup_adds_tls_args_only_when_enabled() -> None:
    module = _load_start_admin_ui_module()

    config = module.resolve_admin_ui_https_config(
        {"ADMIN_UI_HTTPS_ENABLED": "0"},
        settings_loader=lambda: None,
    )
    args = module.build_gunicorn_argv({}, config)
    assert args[:5] == ["python3", "-m", "gunicorn", "-b", "0.0.0.0:5000"]
    assert "--certfile" not in args
    assert "--keyfile" not in args

    config = module.resolve_admin_ui_https_config(
        {
            "ADMIN_UI_HTTPS_ENABLED": "yes",
            "ADMIN_UI_SSL_CERTFILE": "/certs/admin.crt",
            "ADMIN_UI_SSL_KEYFILE": "/certs/admin.key",
        },
        settings_loader=lambda: None,
    )
    args = module.build_gunicorn_argv({"WEB_THREADS": "4"}, config)
    assert "--threads" in args
    assert args[args.index("--threads") + 1] == "4"
    assert args[args.index("--certfile") + 1] == "/certs/admin.crt"
    assert args[args.index("--keyfile") + 1] == "/certs/admin.key"


def test_admin_ui_startup_uses_saved_https_settings_after_first_save() -> None:
    module = _load_start_admin_ui_module()

    config = module.resolve_admin_ui_https_config(
        {
            "ADMIN_UI_HTTPS_ENABLED": "1",
            "ADMIN_UI_SSL_CERTFILE": "/env/admin.crt",
            "ADMIN_UI_SSL_KEYFILE": "/env/admin.key",
        },
        settings_loader=lambda: SimpleNamespace(
            enabled=False,
            certfile="/db/admin.crt",
            keyfile="/db/admin.key",
            updated_ts=7,
        ),
    )

    assert config.source == "db"
    assert config.enabled is False
    assert config.certfile == ""
    assert config.keyfile == ""

    enabled = module.resolve_admin_ui_https_config(
        {
            "ADMIN_UI_HTTPS_ENABLED": "0",
            "ADMIN_UI_SSL_CERTFILE": "/env/admin.crt",
            "ADMIN_UI_SSL_KEYFILE": "/env/admin.key",
        },
        settings_loader=lambda: SimpleNamespace(
            enabled=True,
            certfile="/old/custom.crt",
            keyfile="/old/custom.key",
            updated_ts=8,
        ),
    )

    assert enabled.source == "db"
    assert enabled.enabled is True
    assert enabled.certfile == "/etc/squid/ssl/certs/admin-ui.crt"
    assert enabled.keyfile == "/etc/squid/ssl/certs/admin-ui.key"


def test_admin_ui_startup_materializes_missing_db_leaf_from_active_bundle(
    monkeypatch,
) -> None:
    module = _load_start_admin_ui_module()
    settings = SimpleNamespace(
        enabled=True,
        certfile="/etc/squid/ssl/certs/ca.crt",
        keyfile="/etc/squid/ssl/certs/ca.key",
        san_tokens="proxyadmin.example.com\n192.0.2.10",
        updated_by="admin",
    )
    saved: dict[str, object] = {}

    class _Store:
        def get_admin_ui_https_settings(self):
            return settings

        def get_active_bundle(self):
            return SimpleNamespace(cert_pem="CERT", key_pem="KEY")

        def set_admin_ui_https_settings(self, **kwargs):
            saved.update(kwargs)

    def _materialize(ca_dir, bundle, *, san_tokens):
        assert ca_dir == "/etc/squid/ssl/certs"
        assert bundle.cert_pem == "CERT"
        assert "proxyadmin.example.com" in san_tokens
        assert "192.0.2.10" in san_tokens
        assert "admin-public.example.test" in san_tokens
        return SimpleNamespace(
            certfile="/etc/squid/ssl/certs/admin-ui.crt",
            keyfile="/etc/squid/ssl/certs/admin-ui.key",
        )

    from services import certificate_bundles, certificate_core

    store = _Store()

    def _get_store():
        return store

    monkeypatch.setattr(certificate_bundles, "get_certificate_bundles", _get_store)
    monkeypatch.setattr(
        certificate_core,
        "materialize_admin_ui_server_certificate",
        _materialize,
    )

    recovered = module._try_materialize_saved_admin_ui_leaf(
        {"ADMIN_UI_PUBLIC_HOST": "admin-public.example.test"},
    )

    assert recovered is not None
    assert recovered.enabled is True
    assert recovered.certfile == "/etc/squid/ssl/certs/admin-ui.crt"
    assert recovered.keyfile == "/etc/squid/ssl/certs/admin-ui.key"
    assert saved["certfile"] == "/etc/squid/ssl/certs/admin-ui.crt"
    assert saved["keyfile"] == "/etc/squid/ssl/certs/admin-ui.key"
    assert saved["san_tokens"] == settings.san_tokens


def test_admin_ui_startup_db_https_missing_material_falls_back_to_http(
    monkeypatch,
) -> None:
    module = _load_start_admin_ui_module()
    exec_calls: list[tuple[str, list[str]]] = []

    monkeypatch.setattr(
        module,
        "resolve_admin_ui_https_config",
        lambda _environ: module.AdminUiHttpsRuntimeConfig(
            enabled=True,
            certfile="/missing/ca.crt",
            keyfile="/missing/ca.key",
            source="db",
        ),
    )
    monkeypatch.setattr(
        module.os,
        "execvp",
        lambda executable, argv: exec_calls.append((executable, argv)),
    )

    assert module.main() == 1
    assert exec_calls
    assert "--certfile" not in exec_calls[0][1]
    assert "--keyfile" not in exec_calls[0][1]
    assert module.os.environ["ADMIN_UI_EFFECTIVE_HTTPS_ENABLED"] == "0"
    assert module.os.environ["ADMIN_UI_EFFECTIVE_HTTPS_SOURCE"] == "db-missing-material"
    assert "not valid TLS material" in module.os.environ["ADMIN_UI_EFFECTIVE_HTTPS_ERROR"]


def test_admin_ui_startup_db_https_empty_material_falls_back_to_http(
    monkeypatch,
    tmp_path,
) -> None:
    module = _load_start_admin_ui_module()
    certfile = tmp_path / "ca.crt"
    keyfile = tmp_path / "ca.key"
    certfile.write_bytes(b"")
    keyfile.write_bytes(b"")
    exec_calls: list[tuple[str, list[str]]] = []

    monkeypatch.setattr(
        module,
        "resolve_admin_ui_https_config",
        lambda _environ: module.AdminUiHttpsRuntimeConfig(
            enabled=True,
            certfile=str(certfile),
            keyfile=str(keyfile),
            source="db",
        ),
    )
    monkeypatch.setattr(
        module.os,
        "execvp",
        lambda executable, argv: exec_calls.append((executable, argv)),
    )

    assert module.main() == 1
    assert exec_calls
    assert "--certfile" not in exec_calls[0][1]
    assert module.os.environ["ADMIN_UI_EFFECTIVE_HTTPS_SOURCE"] == "db-missing-material"
    assert "not valid TLS material" in module.os.environ["ADMIN_UI_EFFECTIVE_HTTPS_ERROR"]


def test_admin_ui_startup_env_https_missing_material_fails(monkeypatch) -> None:
    module = _load_start_admin_ui_module()
    exec_calls: list[tuple[str, list[str]]] = []

    monkeypatch.setattr(
        module,
        "resolve_admin_ui_https_config",
        lambda _environ: module.AdminUiHttpsRuntimeConfig(
            enabled=True,
            certfile="/missing/ca.crt",
            keyfile="/missing/ca.key",
            source="env",
        ),
    )
    monkeypatch.setattr(
        module.os,
        "execvp",
        lambda executable, argv: exec_calls.append((executable, argv)),
    )

    assert module.main() == 1
    assert exec_calls == []


def test_admin_ui_startup_env_https_invalid_material_fails(
    monkeypatch,
    tmp_path,
) -> None:
    module = _load_start_admin_ui_module()
    certfile = tmp_path / "ca.crt"
    keyfile = tmp_path / "ca.key"
    certfile.write_text("not a certificate\n", encoding="utf-8")
    keyfile.write_text("not a private key\n", encoding="utf-8")
    exec_calls: list[tuple[str, list[str]]] = []

    monkeypatch.setattr(
        module,
        "resolve_admin_ui_https_config",
        lambda _environ: module.AdminUiHttpsRuntimeConfig(
            enabled=True,
            certfile=str(certfile),
            keyfile=str(keyfile),
            source="env",
        ),
    )
    monkeypatch.setattr(
        module.os,
        "execvp",
        lambda executable, argv: exec_calls.append((executable, argv)),
    )

    assert module.main() == 1
    assert exec_calls == []


def test_admin_ui_startup_falls_back_to_env_before_saved_setting_or_db_failure() -> None:
    module = _load_start_admin_ui_module()

    seeded = module.resolve_admin_ui_https_config(
        {"ADMIN_UI_HTTPS_ENABLED": "yes"},
        settings_loader=lambda: SimpleNamespace(
            enabled=False,
            certfile="",
            keyfile="",
            updated_ts=0,
        ),
    )
    failed = module.resolve_admin_ui_https_config(
        {"ADMIN_UI_HTTPS_ENABLED": "yes"},
        settings_loader=lambda: (_ for _ in ()).throw(RuntimeError("db down")),
    )

    assert seeded.source == "env"
    assert seeded.enabled is True
    assert seeded.certfile == "/etc/squid/ssl/certs/admin-ui.crt"
    assert seeded.keyfile == "/etc/squid/ssl/certs/admin-ui.key"
    assert failed.source == "env"
    assert failed.enabled is True


def test_admin_healthcheck_does_not_queue_behind_wsgi_workers() -> None:
    healthcheck = _read("docker/healthcheck.admin.sh")

    assert "urllib.request" not in healthcheck
    assert "[g]unicorn.*wsgi:app" in healthcheck
    assert "socket.create_connection" in healthcheck
    assert 'os.environ.get("ADMIN_UI_BIND")' in healthcheck
    assert 'os.environ.get("ADMIN_UI_PORT")' in healthcheck
    assert '("127.0.0.1", _health_port())' in healthcheck
    assert '("127.0.0.1", 5000)' not in healthcheck
    assert "whether gunicorn is currently speaking HTTP or HTTPS" in healthcheck


def test_admin_healthcheck_resolves_runtime_port_from_launcher_env() -> None:
    healthcheck = _read("docker/healthcheck.admin.sh")
    script = healthcheck.split("python3 - <<'PY'\n", 1)[1].split("\nPY", 1)[0]

    harness = (
        "import json\n"
        "captures = []\n"
        "class _Connection:\n"
        "    def __enter__(self):\n"
        "        return self\n"
        "    def __exit__(self, exc_type, exc, tb):\n"
        "        return False\n"
        "def _capture(address, timeout):\n"
        "    captures.append([address[0], address[1], timeout])\n"
        "    return _Connection()\n"
    )
    script = script.replace(
        "import socket\n",
        "import socket\nsocket.create_connection = _capture\n",
        1,
    )

    cases = [
        ({}, 5000),
        ({"ADMIN_UI_PORT": "8443"}, 8443),
        ({"ADMIN_UI_BIND": "0.0.0.0:9443", "ADMIN_UI_PORT": "8443"}, 9443),
        ({"ADMIN_UI_BIND": "127.0.0.1:7443"}, 7443),
        ({"ADMIN_UI_BIND": "[::]:6443"}, 6443),
        ({"ADMIN_UI_BIND": ":5443"}, 5443),
        ({"ADMIN_UI_BIND": "4443"}, 4443),
    ]

    for env_overrides, expected_port in cases:
        env = {
            key: value
            for key, value in os.environ.items()
            if key not in {"ADMIN_UI_BIND", "ADMIN_UI_PORT"}
        }
        env.update(env_overrides)
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                f"{harness}\n{script}\nprint(json.dumps(captures[-1]))",
            ],
            check=True,
            env=env,
            capture_output=True,
            text=True,
        )
        assert result.stdout.strip() == f'["127.0.0.1", {expected_port}, 2]'


def test_admin_healthcheck_tcp_failure_exits_without_traceback() -> None:
    healthcheck = _read("docker/healthcheck.admin.sh")
    script = healthcheck.split("python3 - <<'PY'\n", 1)[1].split("\nPY", 1)[0]
    script = script.replace(
        "import socket\n",
        (
            "import socket\n"
            "def _raise_connection_error(*_args, **_kwargs):\n"
            "    raise ConnectionRefusedError('refused')\n"
            "socket.create_connection = _raise_connection_error\n"
        ),
        1,
    )

    result = subprocess.run(
        [sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert "Traceback" not in result.stderr


def test_adblock_icap_adapts_browsing_and_connect_methods() -> None:
    entrypoint = _read("docker/entrypoint.sh")

    assert "adaptation_access adblock_req_set allow all" not in entrypoint
    assert (
        "acl icap_adblockable method GET HEAD CONNECT POST OPTIONS PUT PATCH DELETE"
        in entrypoint
    )
    assert "adaptation_access adblock_req_set allow icap_adblockable" in entrypoint
    assert "adaptation_access adblock_req_set deny all" in entrypoint


def test_entrypoint_bootstrap_av_policy_matches_schema_safety_guards() -> None:
    entrypoint = _read("docker/entrypoint.sh")

    assert "acl file_security_range_request req_header Range .+" in entrypoint
    assert "acl file_security_partial_response http_status 206" in entrypoint
    assert (
        "adaptation_access av_resp_set deny file_security_range_request" in entrypoint
    )
    assert (
        "adaptation_access av_resp_set deny file_security_partial_response"
        in entrypoint
    )


def test_proxy_entrypoint_mirrors_auth_cache_guard_to_persisted_config() -> None:
    entrypoint = _read("docker/entrypoint.sh")

    assert "ensure_auth_cookie_cache_deny /etc/squid/squid.conf" in entrypoint
    assert 'ensure_auth_cookie_cache_deny "$PERSISTED_SQUID_CONF_PATH"' in entrypoint


def test_linux_container_payloads_are_lf_only() -> None:
    paths = [
        "docker/entrypoint.sh",
        "docker/entrypoint.admin.sh",
        "docker/healthcheck.sh",
        "docker/cicap_av_runner.py",
        "web/tools/clamav_respmod_icap_server.py",
        "docker/healthcheck.admin.sh",
        "docker/load-env.sh",
        "docker/squid_logrotate.sh",
        "scripts/generate_ca.sh",
        "scripts/init_ssl_db.sh",
        "docker/supervisord.proxy.conf",
        "docker/supervisord.admin.conf",
        "docker/c-icap.conf",
        "docker/virus_scan.conf",
    ]

    offenders = [path for path in paths if b"\r\n" in (REPO_ROOT / path).read_bytes()]

    assert offenders == []


def test_compose_exposes_https_intercept_listener_knobs() -> None:
    compose = _read("docker-compose.common.yml")
    env_example = _read("config/app.env.example")
    readme = _read("README.md")

    assert (
        "${PROXY_PUBLIC_HTTPS_INTERCEPT_PORT:-3130}:${SQUID_HTTPS_INTERCEPT_PORT:-3130}"
    ) in compose
    assert (
        "SQUID_HTTPS_INTERCEPT_ENABLED: ${SQUID_HTTPS_INTERCEPT_ENABLED:-}" in compose
    )
    assert (
        "SQUID_HTTPS_INTERCEPT_SPLICE_ONLY: ${SQUID_HTTPS_INTERCEPT_SPLICE_ONLY:-}"
    ) in compose
    assert "# SQUID_HTTPS_INTERCEPT_ENABLED=0" in env_example
    assert "# PROXY_PUBLIC_HTTPS_INTERCEPT_PORT=3130" in env_example
    assert "SQUID_HTTPS_INTERCEPT_ENABLED" in readme


def test_proxy_entrypoint_perf_tuning_preserves_sslcrtd_child_options(tmp_path) -> None:
    config = tmp_path / "squid.conf"
    config.write_text(
        "workers 4\n"
        "cache_mem 256 MB\n"
        "sslcrtd_children 4 startup=3 idle=2 queue-size=96\n"
        "max_filedescriptors 65536\n",
        encoding="utf-8",
    )

    _run_entrypoint_perf_tuning(config, children=2)

    rendered = config.read_text(encoding="utf-8")
    assert "sslcrtd_children 2 startup=3 idle=2 queue-size=96" in rendered
    assert "sslcrtd_children 2\n" not in rendered


def test_proxy_entrypoint_perf_tuning_synthesizes_sslcrtd_child_options(tmp_path) -> None:
    config = tmp_path / "squid.conf"
    config.write_text("workers 4\ncache_mem 256 MB\n", encoding="utf-8")

    _run_entrypoint_perf_tuning(config, children=2)

    rendered = config.read_text(encoding="utf-8")
    assert "sslcrtd_children 2 startup=2 idle=1 queue-size=32" in rendered


def test_proxy_entrypoint_env_can_materialize_https_intercept_listener(
    tmp_path,
) -> None:
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
