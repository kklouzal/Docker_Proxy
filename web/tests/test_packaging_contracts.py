from __future__ import annotations

import ast
import importlib.util
import os
import re
import sys
from types import SimpleNamespace

import pytest

from .mysql_test_utils import REPO_ROOT
from .subprocess_test_utils import run_test_process


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


def _assert_staged_wsgi_import(
    stage,
    *,
    entrypoint_module: str,
    application_module: str,
) -> None:
    script = f"""
import importlib
from flask import Flask

entrypoint = importlib.import_module({entrypoint_module!r})
application_module = importlib.import_module({application_module!r})
assert isinstance(entrypoint.app, Flask)
assert entrypoint.app is application_module.app
assert entrypoint.application is entrypoint.app
"""
    result = run_test_process(
        [sys.executable, "-c", script],
        cwd=stage,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


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
                '\nif [ -z "${DB_POOL_MAX_IDLE_SECONDS:-}" ]; then',
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
        'apply_squid_perf_tuning "$1"\n'
    )
    run_test_process(
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
            imports.update(
                f"{alias.name.split('.')[1]}.py"
                for alias in node.names
                if alias.name.startswith("services.")
            )
    return imports


def _local_python_modules() -> dict[str, str]:
    modules: dict[str, str] = {}
    for directory, package in (
        ("proxy", "proxy"),
        ("web/services", "services"),
        ("web/tools", "tools"),
    ):
        for path in sorted((REPO_ROOT / directory).glob("*.py")):
            suffix = "" if path.name == "__init__.py" else f".{path.stem}"
            modules[f"{package}{suffix}"] = str(path.relative_to(REPO_ROOT))
    return modules


def _local_imports(module: str, path: str, local_modules: set[str]) -> set[str]:
    tree = ast.parse(_read(path), filename=path)
    imports: set[str] = set()
    for node in ast.walk(tree):
        candidates: set[str] = set()
        if isinstance(node, ast.Import):
            candidates.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                package = module.rsplit(".", 1)[0]
                parts = package.split(".")
                base = ".".join(parts[: len(parts) - node.level + 1])
                imported = ".".join(filter(None, (base, node.module or "")))
            else:
                imported = node.module or ""
            candidates.add(imported)
            candidates.update(
                ".".join(filter(None, (imported, alias.name)))
                for alias in node.names
                if alias.name != "*"
            )
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "import_module"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            # Repository dynamic imports use importlib.import_module with literals.
            candidates.add(node.args[0].value)
        imports.update(candidates & local_modules)
    return imports


def _missing_local_import_closure(
    roots: set[str], packaged: set[str]
) -> tuple[set[str], set[str]]:
    modules = _local_python_modules()
    reachable: set[str] = set()
    pending = list(roots)
    while pending:
        module = pending.pop()
        if module in reachable:
            continue
        assert module in modules, f"unknown local runtime entrypoint: {module}"
        reachable.add(module)
        pending.extend(
            _local_imports(module, modules[module], set(modules)) - reachable
        )
    return reachable - packaged, reachable


def _image_payload(dockerfile: str, pattern: str) -> set[str]:
    text = _read(dockerfile)
    return {match.rsplit("/", 1)[-1] for match in re.findall(pattern, text)}


def _proxy_image_payload(pattern: str) -> set[str]:
    return _image_payload("docker/Dockerfile.proxy", pattern)


def _workflow_build_arg_blocks(workflow: str) -> list[dict[str, str]]:
    blocks: list[dict[str, str]] = []
    for raw_block in re.findall(r"build-args:\s*\|\n((?: {12}\S.*\n)+)", workflow):
        block: dict[str, str] = {}
        for raw_line in raw_block.splitlines():
            line = raw_line.strip()
            if not line or "=" not in line:
                continue
            key, value = line.split("=", 1)
            block[key] = value
        blocks.append(block)
    return blocks


def _workflow_job_body(workflow: str, job_name: str) -> str:
    match = re.search(
        rf"^  {re.escape(job_name)}:\n(?P<body>(?:    .*\n|\n)+?)(?=^  [\w-]+:|\Z)",
        workflow,
        flags=re.MULTILINE,
    )
    assert match is not None
    return match.group("body")


def _dockerfile_stages(dockerfile: str) -> list[str]:
    text = _read(dockerfile)
    return [
        "FROM " + stage for stage in re.split(r"^FROM ", text, flags=re.MULTILINE)[1:]
    ]


def test_alpine_package_installs_use_retry_helper_for_runtime_images() -> None:
    helper = _read("docker/apk-install.sh")

    assert 'apk add --no-cache "$@"' in helper
    assert "APK_INSTALL_RETRIES:-4" in helper
    assert "APK_INSTALL_RETRY_DELAY_SECONDS:-5" in helper

    for dockerfile in ("docker/Dockerfile.admin", "docker/Dockerfile.proxy"):
        text = _read(dockerfile)
        assert (
            "COPY --chmod=755 docker/apk-install.sh /usr/local/bin/apk-install" in text
        )

        for stage in _dockerfile_stages(dockerfile):
            if "apk add --no-cache" not in stage and "apk-install" not in stage:
                continue
            assert (
                "COPY --chmod=755 docker/apk-install.sh /usr/local/bin/apk-install"
                in stage
            )
            assert "RUN apk-install" in stage

        assert "RUN apk add --no-cache" not in text


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
    assert "web/services/observability_queries.py" not in proxy
    assert "web/services/report_schedule_recipients.py" in proxy
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


def test_proxy_wsgi_imports_packaged_proxy_application(tmp_path) -> None:
    dockerfile = _read("docker/Dockerfile.proxy")
    supervisord = _read("docker/supervisord.proxy.conf")
    package = tmp_path / "proxy"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "app.py").write_text(
        'from flask import Flask\napp = Flask("packaged-proxy-app")\n',
        encoding="utf-8",
    )
    (package / "wsgi.py").write_text(_read("proxy/wsgi.py"), encoding="utf-8")

    assert "WORKDIR /app" in dockerfile
    assert "COPY proxy /app/proxy" in dockerfile
    assert "directory=/app" in supervisord
    assert "proxy.wsgi:app" in supervisord
    _assert_staged_wsgi_import(
        tmp_path,
        entrypoint_module="proxy.wsgi",
        application_module="proxy.app",
    )


def test_admin_wsgi_imports_flat_packaged_application(tmp_path) -> None:
    dockerfile = _read("docker/Dockerfile.admin")
    supervisord = _read("docker/supervisord.admin.conf")
    launcher = _load_start_admin_ui_module()
    (tmp_path / "app.py").write_text(
        'from flask import Flask\napp = Flask("packaged-admin-app")\n',
        encoding="utf-8",
    )
    (tmp_path / "wsgi.py").write_text(_read("web/wsgi.py"), encoding="utf-8")

    assert "WORKDIR /app" in dockerfile
    assert "COPY web/app.py /app/app.py" in dockerfile
    assert "COPY web/wsgi.py /app/wsgi.py" in dockerfile
    assert "directory=/app" in supervisord
    assert "wsgi:app" in launcher.build_gunicorn_argv(
        {},
        launcher.AdminUiHttpsRuntimeConfig(
            enabled=False,
            certfile="",
            keyfile="",
            source="test",
        ),
    )
    _assert_staged_wsgi_import(
        tmp_path,
        entrypoint_module="wsgi",
        application_module="app",
    )


PROXY_PYTHON_RUNTIME_ROOTS = {
    "proxy.wsgi",
    "proxy.agent",
    "proxy.forwarding_canary",
    "tools.adblock_compile",
    "tools.adblock_icap_server",
    "tools.clamav_respmod_icap_server",
    "tools.safe_browsing_acl",
    "tools.sslfilter_apply",
    "tools.webcat_acl",
    "tools.webfilter_apply",
}


def _proxy_packaged_local_modules() -> set[str]:
    copied_services = _proxy_image_payload(r"web/services/[\w_]+\.py")
    copied_tools = _proxy_image_payload(r"web/tools/[\w_]+\.py")
    return {
        "proxy",
        *(f"proxy.{path.stem}" for path in (REPO_ROOT / "proxy").glob("*.py")),
        "services",
        *(f"services.{name[:-3]}" for name in copied_services if name != "__init__.py"),
        *(f"tools.{name[:-3]}" for name in copied_tools if name != "__init__.py"),
    }


def test_proxy_dockerfile_contains_transitive_local_import_closure() -> None:
    supervisord = _read("docker/supervisord.proxy.conf")
    entrypoint = _read("docker/entrypoint.sh")
    for marker in ("proxy.wsgi:app", "proxy.agent", "proxy.forwarding_canary"):
        assert marker in supervisord
    for tool in sorted(
        name.removeprefix("tools.")
        for name in PROXY_PYTHON_RUNTIME_ROOTS
        if name.startswith("tools.")
    ):
        assert (
            f"/app/tools/{tool}.py" in entrypoint
            or f"/app/tools/{tool}.py" in _read("web/services/webfilter_core.py")
        )

    missing, reachable = _missing_local_import_closure(
        PROXY_PYTHON_RUNTIME_ROOTS, _proxy_packaged_local_modules()
    )

    assert sorted(missing) == []
    assert "services.bounded_delete" in reachable


def test_proxy_local_import_closure_detects_removed_transitive_module() -> None:
    packaged = _proxy_packaged_local_modules()
    missing, reachable = _missing_local_import_closure(
        PROXY_PYTHON_RUNTIME_ROOTS, packaged - {"services.bounded_delete"}
    )

    assert "services.bounded_delete" in reachable
    assert missing == {"services.bounded_delete"}


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
    assert "bounded_delete.py" in copied_services
    assert "webcat_hygiene.py" in copied_services


def test_proxy_schema_startup_does_not_import_admin_only_modules() -> None:
    schema = _read("web/services/schema_lifecycle.py")
    proxy = _read("docker/Dockerfile.proxy")
    admin_only_modules = {
        "auth_store",
        "audit_store",
        "directory_auth",
        "saml_auth",
        "observability_maintenance",
        "observability_queries",
        "webfilter_store",
        "control_plane_maintenance",
    }

    for module_name in sorted(admin_only_modules):
        assert f'import_module("services.{module_name}")' not in schema
        assert f"import_module('services.{module_name}')" not in schema
        assert f"web/services/{module_name}.py" not in proxy

    for expected_table in (
        "users",
        "audit_events",
        "webfilter_settings",
        "webfilter_blocked_log",
        "observability_settings",
        "observability_report_schedules",
        "directory_auth_profiles",
        "saml_auth_profiles",
    ):
        assert expected_table in schema


def test_admin_image_contains_documented_mysql_state_validation_cli() -> None:
    admin = _read("docker/Dockerfile.admin")
    docs = _read("docs/mysql-backup-restore-validation.md")

    assert "Run from the admin-ui environment" in docs
    assert "python -m services.mysql_state_validation --phase pre-backup" in docs
    assert "python -m services.mysql_state_validation --phase post-restore" in docs
    assert "web/services/mysql_state_validation.py" in admin
    assert "web/services/mysql_state_validation.py" not in _read(
        "docker/Dockerfile.proxy"
    )


def test_local_deterministic_test_command_matches_ci_mysql_exclusion() -> None:
    expected_marker = '-m "not live and not mysql"'

    assert expected_marker in _read(".github/workflows/publish-ghcr.yml")
    assert expected_marker in _read("README.md")


def test_publish_workflow_enforces_static_and_local_image_security_gates() -> None:
    workflow = _read(".github/workflows/publish-ghcr.yml")
    static_job = _workflow_job_body(workflow, "static-analysis")
    ruff_job = _workflow_job_body(workflow, "ruff-check")
    build_job = _workflow_job_body(workflow, "build-test-images")

    for marker in (
        "actionlint -color=false",
        "zizmor --offline --format github",
        "shellcheck",
        "hadolint",
        "docker compose -f docker-compose.yml config --quiet",
        "docker compose -f docker-compose.ghcr.yml config --quiet",
        "docker compose -f docker-compose.server002.yml config --quiet",
        "gitleaks dir --no-banner --redact",
    ):
        assert marker in static_job

    assert "needs: static-analysis" in ruff_job
    assert "load: true" in build_job
    assert "aquasecurity/trivy-action@" in build_job
    assert "image-ref: docker-proxy-${{ matrix.image }}:ci" in build_job
    assert "scanners: vuln" in build_job
    assert "vuln-type: os,library" in build_job
    assert "severity: HIGH,CRITICAL" in build_job
    assert "ignore-unfixed: true" in build_job
    assert 'exit-code: "1"' in build_job


def test_ghcr_publish_passes_runtime_version_build_args() -> None:
    workflow = _read(".github/workflows/publish-ghcr.yml")
    proxy = _read("docker/Dockerfile.proxy")
    admin = _read("docker/Dockerfile.admin")
    build_arg_blocks = _workflow_build_arg_blocks(workflow)
    build_date_step = (
        "      - name: Compute OCI build date\n"
        "        id: build-date\n"
        "        shell: bash\n"
        "        run: echo \"value=$(date -u +'%Y-%m-%dT%H:%M:%SZ')\" "
        '>> "$GITHUB_OUTPUT"\n'
    )

    assert len(build_arg_blocks) == 2

    job_image_names = {
        "build-test-images": "docker-proxy-${{ matrix.image }}:ci",
        "publish-images": "${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}-${{ matrix.image }}",
    }
    for job_name, expected_image_name in job_image_names.items():
        job = _workflow_job_body(workflow, job_name)
        job_build_arg_blocks = _workflow_build_arg_blocks(job)
        assert len(job_build_arg_blocks) == 1
        job_build_args = job_build_arg_blocks[0]

        assert job.count("- name: Compute OCI build date") == 1
        assert build_date_step in job
        assert "date -u +'%Y-%m-%dT%H:%M:%SZ'" in job
        assert '>> "$GITHUB_OUTPUT"' in job
        assert job.index("id: build-date") < job.index(
            "uses: docker/build-push-action@"
        )
        assert "${{ github.event.head_commit.timestamp || github.run_id }}" not in job
        assert job.count("BUILD_DATE=${{ steps.build-date.outputs.value }}") == 1

        assert job_build_args["APP_VERSION"] == "${{ github.ref_name }}"
        assert job_build_args["GIT_COMMIT"] == "${{ github.sha }}"
        assert job_build_args["GIT_REF_NAME"] == "${{ github.ref_name }}"
        assert job_build_args["BUILD_DATE"] == "${{ steps.build-date.outputs.value }}"
        assert job_build_args["IMAGE_NAME"] == expected_image_name
    assert "ARG IMAGE_NAME=proxy" in proxy
    assert "ARG IMAGE_NAME=admin-ui" in admin
    assert "IMAGE_NAME=${IMAGE_NAME}" in proxy
    assert "IMAGE_NAME=${IMAGE_NAME}" in admin


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
    primary_proxy_block = live_compose.split("\n  proxy:\n", 1)[1].split(
        "\n  proxy-edge-2:\n",
        1,
    )[0]
    assert "        aliases:" in primary_proxy_block
    assert "          - proxy" in primary_proxy_block
    assert "          - ${LIVE_TEST_PROXY_ID:-live}" in primary_proxy_block
    assert (
        "PROXY_MANAGEMENT_URL: ${LIVE_TEST_PROXY_MANAGEMENT_URL:-http://proxy:5000}"
        in primary_proxy_block
    )
    assert (
        "PROXY_PUBLIC_HOST: ${LIVE_TEST_PROXY_PUBLIC_HOST:-proxy}"
        in primary_proxy_block
    )
    assert (
        "PROXY_PUBLIC_PAC_URL: ${LIVE_TEST_PROXY_PUBLIC_PAC_URL:-http://proxy/proxy.pac}"
        in primary_proxy_block
    )
    remote_proxy_block = live_compose.split("\n  proxy-edge-2:\n", 1)[1].split(
        "\n  live-tests:\n",
        1,
    )[0]
    assert (
        "PROXY_PUBLIC_HOST: ${LIVE_TEST_REMOTE_PROXY_PUBLIC_HOST:-proxy-edge-2}"
        in remote_proxy_block
    )
    assert (
        "PROXY_PUBLIC_PAC_URL: ${LIVE_TEST_REMOTE_PAC_URL:-http://proxy-edge-2/proxy.pac}"
        in remote_proxy_block
    )
    live_test_runner_block = live_compose.split("\n  live-tests:\n", 1)[1]
    assert "DEFAULT_PROXY_ID: ${LIVE_TEST_PROXY_ID:-live}" in live_test_runner_block
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
    assert (
        'rm -f "${av_pid}"; exec /usr/local/bin/cicap_av_runner.py "${av_conf}"'
        in entrypoint
    )
    dockerfile = _read("docker/Dockerfile.proxy")
    assert "web/tools/clamav_respmod_icap_server.py" in dockerfile
    assert (
        "COPY --chmod=755 docker/cicap_av_runner.py /usr/local/bin/cicap_av_runner.py"
        in dockerfile
    )

    env_example = _read("config/app.env.example")
    assert "# CICAP_AV_RESP_PORT=" in env_example
    assert "# ADBLOCK_CACHE_TTL=3600" in env_example
    assert "ADBLOCK_ARTIFACT_EXTRACT_MAX_BYTES=1073741824" in env_example
    assert "ADBLOCK_ARTIFACT_EXTRACT_MAX_MEMBERS=256" in env_example
    assert "# ADBLOCK_RULE_CACHE_MAX=50000" in env_example
    assert "# ADBLOCK_ICAP_MAX_BODY_DRAIN_BYTES=8388608" in env_example
    assert "MYSQL_MAX_ALLOWED_PACKET=256M" in env_example


def test_common_compose_env_surface_is_documented_in_env_example() -> None:
    compose = _read("docker-compose.common.yml")
    env_example = _read("config/app.env.example")
    compose_env_names = sorted(
        set(re.findall(r"\$\{([A-Z0-9_]+)(?::[-?][^}]*)?\}", compose)),
    )

    assert [name for name in compose_env_names if name not in env_example] == []


def test_adblock_artifact_budget_is_shared_across_builder_and_proxy() -> None:
    compose = _read("docker-compose.common.yml")
    readme = _read("README.md")

    assert compose.count("<<: *shared-app-env") == 2
    for variable, default in (
        ("ADBLOCK_ARTIFACT_EXTRACT_MAX_BYTES", "1073741824"),
        ("ADBLOCK_ARTIFACT_EXTRACT_MAX_MEMBERS", "256"),
    ):
        marker = f"{variable}: ${{{variable}:-{default}}}"
        assert marker in compose
        assert variable in readme


def test_management_token_packaging_fails_closed_without_public_default() -> None:
    compose = _read("docker-compose.common.yml")
    validator = _read("docker/validate-management-token.sh")

    assert "PROXY_MANAGEMENT_TOKEN: ${PROXY_MANAGEMENT_TOKEN:-}" in compose
    assert "PROXY_MANAGEMENT_TOKEN:***" not in compose
    public_placeholders = {
        "change-me",
        "replace-with-a-long-random-token",
        "replace_with_a_long_random_shared_token",
    }
    for placeholder in public_placeholders:
        assert placeholder in validator

    for path in ("README.md", "config/app.env.example"):
        match = re.search(
            r"^\s*PROXY_MANAGEMENT_TOKEN=(\S+)$", _read(path), re.MULTILINE
        )
        assert match is not None
        assert match.group(1) in public_placeholders
        assert match.group(1) in validator
    for entrypoint_name in ("docker/entrypoint.admin.sh", "docker/entrypoint.sh"):
        assert "/usr/local/bin/validate-management-token.sh" in _read(entrypoint_name)
    for dockerfile_name in ("docker/Dockerfile.admin", "docker/Dockerfile.proxy"):
        assert "docker/validate-management-token.sh" in _read(dockerfile_name)


def test_docs_config_track_schema_lifecycle_and_health_knobs() -> None:
    compose = _read("docker-compose.common.yml")
    env_example = _read("config/app.env.example")
    readme = _read("README.md")
    backup_docs = _read("docs/mysql-backup-restore-validation.md")
    recovery_docs = _read("docs/proxy-recovery.md")
    schema_docs = _read("docs/mysql-schema-lifecycle.md")
    schema = _read("web/services/schema_lifecycle.py")
    app = _read("web/app.py")

    schema_versions = [int(match) for match in re.findall(r"version=(\d+),", schema)]
    assert schema_versions
    latest_version = str(max(schema_versions))

    assert f"through version {latest_version}" in schema_docs
    assert "application_ledger_evidence_indexes" in schema_docs
    assert "timeseries_metric_count_columns" in schema_docs
    assert "application_ledger_evidence_indexes" in schema
    assert "timeseries_metric_count_columns" in schema
    assert "proxy_config_applications.config_sha256" in backup_docs
    assert "Timeseries metric count columns" in backup_docs

    for name in ("SESSION_TIMEOUT_HOURS", "DISABLE_CSRF"):
        assert name in app
        assert name in env_example
        assert name in readme
    assert "# SESSION_TIMEOUT_HOURS=8" in env_example

    assert "PROXY_HEALTH_UI_STALE_IF_ERROR_SECONDS" in app
    assert "PROXY_HEALTH_UI_STALE_IF_ERROR_SECONDS" in env_example
    assert "PROXY_HEALTH_UI_STALE_IF_ERROR_SECONDS" in readme
    assert "# PROXY_HEALTH_UI_TIMEOUT_SECONDS=1.5" in env_example
    assert "1.5 second navigation-health timeout" in readme

    recovery_default = "134217728"
    expected_compose_recovery_default = (
        "PROXY_RECOVERY_MAX_BUNDLE_BYTES: "
        f"${{PROXY_RECOVERY_MAX_BUNDLE_BYTES:-{recovery_default}}}"
    )
    assert expected_compose_recovery_default in compose
    assert f"# PROXY_RECOVERY_MAX_BUNDLE_BYTES={recovery_default}" in env_example
    assert recovery_default in readme
    assert recovery_default in recovery_docs


def test_proxy_cicap_sources_are_pinned_and_verified_before_compilation() -> None:
    proxy = _read("docker/Dockerfile.proxy")

    expected_sources = {
        "CICAP": (
            "C_ICAP_0.6.5",
            "b34baf32b764a2d79db34c61041cd9f92c39a535",
            "c_icap_src",
        ),
        "CICAP_MODULES": (
            "C_ICAP_MODULES_0.5.7",
            "e1f6af0e06be1ae1e8b8f822ae74bc0d352b788f",
            "c_icap_modules_src",
        ),
    }
    for prefix, (git_ref, git_commit, checkout) in expected_sources.items():
        assert f"ARG {prefix}_GIT_REF={git_ref}" in proxy
        assert f"ARG {prefix}_GIT_COMMIT={git_commit}" in proxy
        build_step = proxy.split(f"cd {checkout};", 1)[1].split("make install", 1)[0]
        assert 'actual_commit="$(git rev-parse HEAD)"' in build_step
        assert f'"${{{prefix}_GIT_COMMIT}}"' in build_step
        assert "source verification failed" in build_step
        assert build_step.index("git rev-parse HEAD") < build_step.index("./configure")


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


def test_build_and_git_ignores_exclude_local_operator_artifacts() -> None:
    dockerignore = _read(".dockerignore")
    gitignore = _read(".gitignore")

    for pattern in (".openclaw-artifacts/", "Deployment.zip"):
        assert pattern in dockerignore
        assert pattern in gitignore


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
    assert '"WEB_THREADS": "2"' in launcher
    assert "# WEB_THREADS=2" in env_example
    assert "--print-effective-gunicorn-env" in entrypoint
    assert 'web_threads="$WEB_THREADS"' in entrypoint
    assert "web_workers" not in entrypoint
    assert "derived_pool=$((web_threads + 12))" in entrypoint
    assert 'if [ "$derived_pool" -lt 16 ]; then' in entrypoint
    assert 'if [ "$derived_pool" -gt 32 ]; then' in entrypoint


@pytest.mark.parametrize(
    ("name", "default"),
    [
        ("WEB_WORKERS", "1"),
        ("WEB_THREADS", "2"),
        ("WEB_TIMEOUT", "120"),
        ("WEB_GRACEFUL_TIMEOUT", "30"),
    ],
)
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("7", "7"),
        ("0007", "7"),
        ("", None),
        ("oops", None),
        ("0", None),
        ("-1", None),
    ],
)
def test_admin_ui_gunicorn_positive_numeric_controls(
    name: str,
    default: str,
    value: str,
    expected: str | None,
) -> None:
    module = _load_start_admin_ui_module()

    effective = module.effective_gunicorn_numeric_env({name: value})

    assert effective[name] == (default if expected is None else expected)


@pytest.mark.parametrize(
    ("value", "expected"), [("9", "9"), ("000", "0"), ("-1", "5"), (" ", "5")]
)
def test_admin_ui_gunicorn_keepalive_is_nonnegative(value: str, expected: str) -> None:
    module = _load_start_admin_ui_module()

    effective = module.effective_gunicorn_numeric_env({"WEB_KEEPALIVE": value})

    assert effective["WEB_KEEPALIVE"] == expected


def test_admin_ui_numeric_env_executable_boundary_handles_oversized_digits() -> None:
    env = {
        **os.environ,
        "WEB_WORKERS": "3",
        "WEB_THREADS": " malformed ",
        "WEB_TIMEOUT": "0",
        "WEB_GRACEFUL_TIMEOUT": "9" * 5000,
        "WEB_KEEPALIVE": "0",
    }
    result = run_test_process(
        [
            sys.executable,
            "web/tools/start_admin_ui.py",
            "--print-effective-gunicorn-env",
        ],
        cwd=REPO_ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "3 2 120 30 0"


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
        "FORWARDING_CANARY_HOST",
        "FORWARDING_CANARY_PATH",
        "FORWARDING_CANARY_PORT",
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
    assert "python3 -m proxy.forwarding_canary" in supervisord
    assert "command=/usr/local/bin/squid_ready_start.sh" in supervisord
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
    assert (
        "ADMIN_UI_SSL_CERTFILE and ADMIN_UI_SSL_KEYFILE are internal bootstrap"
        in env_example
    )
    assert "prefer a server certificate whose subject/SAN matches" not in readme
    assert "dedicated Admin UI server leaf certificate" in readme
    assert "Admin UI container read-only" not in readme
    assert "mount is writable" in readme
    assert "saved DB setting is the source of truth" in readme
    assert (
        "standalone admin-UI deployments must keep that same mount available" in readme
    )


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
    result = run_test_process(
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


@pytest.mark.parametrize(
    ("environ", "gunicorn_bind", "health_host", "port"),
    [
        ({}, "0.0.0.0:5000", "127.0.0.1", 5000),
        ({"ADMIN_UI_PORT": "8443"}, "0.0.0.0:8443", "127.0.0.1", 8443),
        ({"ADMIN_UI_BIND": "9443"}, "0.0.0.0:9443", "127.0.0.1", 9443),
        ({"ADMIN_UI_BIND": ":7443"}, "0.0.0.0:7443", "127.0.0.1", 7443),
        ({"ADMIN_UI_BIND": "*:6443"}, "0.0.0.0:6443", "127.0.0.1", 6443),
        ({"ADMIN_UI_BIND": "10.0.0.8:5443"}, "10.0.0.8:5443", "10.0.0.8", 5443),
        ({"ADMIN_UI_BIND": "localhost:4443"}, "localhost:4443", "localhost", 4443),
        ({"ADMIN_UI_BIND": "[::]:3443"}, "[::]:3443", "::1", 3443),
        ({"ADMIN_UI_BIND": "[::1]:2443"}, "[::1]:2443", "::1", 2443),
    ],
)
def test_admin_ui_bind_contract(environ, gunicorn_bind, health_host, port) -> None:
    module = _load_start_admin_ui_module()

    bind = module.resolve_admin_ui_bind(environ)

    assert (bind.gunicorn_bind, bind.health_host, bind.port) == (
        gunicorn_bind,
        health_host,
        port,
    )


@pytest.mark.parametrize(
    "environ",
    [
        {"ADMIN_UI_PORT": "not-a-port"},
        {"ADMIN_UI_BIND": "host"},
        {"ADMIN_UI_BIND": "host:not-a-port"},
        {"ADMIN_UI_BIND": "::1:5000"},
        {"ADMIN_UI_BIND": "[::1]"},
        {"ADMIN_UI_BIND": "host:0"},
        {"ADMIN_UI_BIND": "host:65536"},
    ],
)
def test_admin_ui_bind_contract_rejects_unsupported_forms(environ) -> None:
    module = _load_start_admin_ui_module()

    with pytest.raises(ValueError):
        module.resolve_admin_ui_bind(environ)


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


def test_admin_ui_startup_malformed_saved_row_does_not_reenable_env_https() -> None:
    module = _load_start_admin_ui_module()
    from services.certificate_bundles import InvalidAdminUiHttpsSettingsError

    config = module.resolve_admin_ui_https_config(
        {"ADMIN_UI_HTTPS_ENABLED": "1"},
        settings_loader=lambda: (_ for _ in ()).throw(
            InvalidAdminUiHttpsSettingsError(
                "certfile contains unsupported control characters"
            )
        ),
    )

    assert config.source == "db-invalid"
    assert config.enabled is False
    assert config.certfile == ""
    assert config.keyfile == ""
    assert "malformed" in config.error


@pytest.mark.parametrize(
    "settings",
    [
        SimpleNamespace(enabled="0", updated_ts=7),
        SimpleNamespace(enabled=False, updated_ts="7"),
        SimpleNamespace(enabled=False, updated_ts=-1),
    ],
)
def test_admin_ui_startup_rejects_invalid_loader_contract(settings) -> None:
    module = _load_start_admin_ui_module()

    config = module.resolve_admin_ui_https_config(
        {"ADMIN_UI_HTTPS_ENABLED": "1"},
        settings_loader=lambda: settings,
    )

    assert config.source == "db-invalid"
    assert config.enabled is False
    assert config.error


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
    assert saved["san_tokens"] == (
        "proxyadmin.example.com\n192.0.2.10\nadmin-public.example.test"
    )


def test_admin_ui_startup_recovery_reuses_saved_request_derived_host(
    monkeypatch,
) -> None:
    module = _load_start_admin_ui_module()
    settings = SimpleNamespace(
        enabled=True,
        certfile="/etc/squid/ssl/certs/admin-ui.crt",
        keyfile="/etc/squid/ssl/certs/admin-ui.key",
        san_tokens="Admin.Example.TEST:8443\nadmin.example.test",
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

    def _materialize(_ca_dir, _bundle, *, san_tokens):
        assert san_tokens == ("Admin.Example.TEST:8443", "admin.example.test")
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

    recovered = module._try_materialize_saved_admin_ui_leaf({})

    assert recovered is not None
    assert recovered.enabled is True
    assert saved["san_tokens"] == "admin.example.test"


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
    assert (
        "not valid TLS material" in module.os.environ["ADMIN_UI_EFFECTIVE_HTTPS_ERROR"]
    )


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
    assert (
        "not valid TLS material" in module.os.environ["ADMIN_UI_EFFECTIVE_HTTPS_ERROR"]
    )


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


def test_admin_ui_startup_falls_back_to_env_before_saved_setting_or_db_failure() -> (
    None
):
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
    assert "from tools.start_admin_ui import resolve_admin_ui_bind" in healthcheck
    assert "(bind.health_host, bind.port)" in healthcheck
    assert '("127.0.0.1", 5000)' not in healthcheck
    assert "whether gunicorn is currently speaking HTTP or HTTPS" in healthcheck


def test_admin_healthcheck_resolves_runtime_address_from_launcher_env() -> None:
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
        ({}, "127.0.0.1", 5000),
        ({"ADMIN_UI_PORT": "8443"}, "127.0.0.1", 8443),
        ({"ADMIN_UI_BIND": "0.0.0.0:9443"}, "127.0.0.1", 9443),
        ({"ADMIN_UI_BIND": "10.0.0.8:7443"}, "10.0.0.8", 7443),
        ({"ADMIN_UI_BIND": "[::]:6443"}, "::1", 6443),
        ({"ADMIN_UI_BIND": "[::1]:5443"}, "::1", 5443),
    ]

    for env_overrides, expected_host, expected_port in cases:
        env = {
            key: value
            for key, value in os.environ.items()
            if key not in {"ADMIN_UI_BIND", "ADMIN_UI_PORT"}
        }
        env.update(env_overrides)
        result = run_test_process(
            [
                sys.executable,
                "-c",
                f"{harness}\n{script}\nprint(json.dumps(captures[-1]))",
            ],
            check=True,
            cwd=REPO_ROOT / "web",
            env=env,
            capture_output=True,
            text=True,
        )
        assert result.stdout.strip() == f'["{expected_host}", {expected_port}, 2]'


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

    result = run_test_process(
        [sys.executable, "-c", script],
        check=False,
        cwd=REPO_ROOT / "web",
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
        "acl icap_adblockable method GET HEAD POST OPTIONS PUT PATCH DELETE"
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
        "docker/icap_readiness.py",
        "docker/squid_ready_start.sh",
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


def test_proxy_entrypoint_perf_tuning_synthesizes_sslcrtd_child_options(
    tmp_path,
) -> None:
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
    run_test_process(
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
    run_test_process(
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
    run_test_process(
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
    run_test_process(
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
    run_test_process(
        [sys.executable, "-c", _entrypoint_listener_normalizer_script()],
        check=True,
        env=env,
        timeout=5,
    )

    rendered = config.read_text(encoding="utf-8")
    assert "http_port 0.0.0.0:3130 ssl-bump" in rendered
    assert "http_port 0.0.0.0:3131 intercept" in rendered
    assert "https_port 0.0.0.0:3132 intercept ssl-bump" in rendered
