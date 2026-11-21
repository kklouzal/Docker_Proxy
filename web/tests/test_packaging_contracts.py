from __future__ import annotations

import ast
import importlib.util
import os
import re
import subprocess
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

entrypoint = importlib.import_module({entrypoint_module!r})
application_module = importlib.import_module({application_module!r})
assert callable(entrypoint.app)
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


def _run_host_override_helper(config_path, environ: dict[str, str]):
    """Run the entrypoint's capture + apply helper steps on ``config_path``."""
    env = {
        key: value for key, value in os.environ.items() if not key.startswith("SQUID_")
    }
    env.update(environ)
    helper = str(REPO_ROOT / "web/services/squid_host_overrides.py")
    captured = run_test_process(
        [sys.executable, helper, "capture"],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    env["SQUID_HOST_CONFIG_OVERRIDES"] = captured.stdout.strip()
    applied = run_test_process(
        [sys.executable, helper, "apply", str(config_path)],
        check=False,
        capture_output=True,
        text=True,
        env=env,
        timeout=5,
    )
    return captured, applied


def _entrypoint_shell_block(start_marker: str, end_marker: str) -> str:
    text = _read("docker/entrypoint.sh")
    start = text.index(start_marker)
    end = text.index(end_marker, start)
    return text[start:end]


def _host_overrides_helper_command() -> str:
    return f"{sys.executable} {REPO_ROOT / 'web/services/squid_host_overrides.py'}"


def _entrypoint_perf_tuning_script() -> str:
    return "\n".join(
        [
            _entrypoint_shell_block(
                "config_has_directive() {",
                '\nif [ -z "${DB_POOL_MAX_IDLE_SECONDS:-}" ]; then',
            ),
            _entrypoint_shell_block(
                "replace_or_append_config_line() {",
                "\napply_squid_perf_tuning() {",
            ),
            _entrypoint_shell_block(
                "apply_squid_perf_tuning() {",
                "\n# The adblock compile and policy include helpers below read MySQL.",
            ),
        ],
    ).replace(
        "python3 /app/services/squid_host_overrides.py",
        _host_overrides_helper_command(),
    )


def _entrypoint_numeric_env_script() -> str:
    return "\n".join(
        [
            "set -eu",
            _entrypoint_shell_block(
                "sanitize_bounded_int() {",
                "\nsanitize_bind_host() {",
            ),
            "sanitize_bind_host() { printf '%s' \"$1\"; }",
            "sanitize_forwarding_canary_path() { printf '%s' \"$1\"; }",
            _entrypoint_shell_block(
                'PAC_HTTP_PORT="$(sanitize_port',
                '\nif [ "$TEST_MODE_ENABLED" = "1" ]; then',
            ),
            "printf '%s\\n' \"$PAC_HTTP_PORT|$FORWARDING_CANARY_PORT|$WEB_WORKERS|$WEB_THREADS|$WEB_TIMEOUT|$WEB_GRACEFUL_TIMEOUT|$WEB_KEEPALIVE\"",
        ]
    )


def _run_entrypoint_perf_tuning(config_path, *, overrides: str) -> None:
    script = (
        "set -eu\n"
        f"{_entrypoint_perf_tuning_script()}\n"
        "SQUID_WORKERS=4\n"
        "SQUID_CACHE_MEM_MB=256\n"
        "SQUID_SSLCRTD_CHILDREN=2\n"
        "SQUID_MAX_FILEDESCRIPTORS=65536\n"
        'apply_squid_perf_tuning "$1"\n'
    )
    env = {**os.environ, "SQUID_HOST_CONFIG_OVERRIDES": overrides}
    run_test_process(
        ["/bin/sh", "-c", script, "entrypoint-perf-tuning-test", str(config_path)],
        check=True,
        env=env,
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


def test_runtime_python_dependencies_use_abi_independent_import_path() -> None:
    dependency_path = "/opt/docker-proxy/python-deps"

    for dockerfile in ("docker/Dockerfile.admin", "docker/Dockerfile.proxy"):
        text = _read(dockerfile)
        assert f"PYTHONPATH={dependency_path}" in text
        assert f"COPY --from=python_deps /python-deps/ {dependency_path}/" in text
        assert "PYTHON_SITE_PACKAGES" not in text
        assert not re.search(r"/usr/lib/python\d+\.\d+/site-packages", text)


def test_packaged_cicap_runner_imports_shared_service_from_app(tmp_path) -> None:
    app = tmp_path / "app"
    services = app / "services"
    bin_dir = tmp_path / "usr" / "local" / "bin"
    services.mkdir(parents=True)
    bin_dir.mkdir(parents=True)
    (services / "__init__.py").write_text("", encoding="utf-8")
    for module in ("clamd_protocol.py", "icap_protocol.py"):
        (services / module).write_bytes(
            (REPO_ROOT / "web" / "services" / module).read_bytes()
        )
    runner_source = _read("docker/cicap_av_runner.py").replace(
        '_PACKAGED_APP_ROOT = Path("/app")',
        f"_PACKAGED_APP_ROOT = Path({str(app)!r})",
    )
    runner = bin_dir / "cicap_av_runner.py"
    runner.write_text(runner_source, encoding="utf-8")
    env = {**os.environ}
    env.pop("PYTHONPATH", None)

    result = run_test_process(
        [sys.executable, str(runner)],
        cwd=tmp_path,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 64
    assert result.stderr == "usage: cicap_av_runner.py <c-icap-av.conf>\n"


def test_application_owned_dependency_path_is_visible_to_python(tmp_path) -> None:
    dependency_path = tmp_path / "python-deps"
    package = dependency_path / "packaging_contract_probe"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("PROBE = 'visible'\n", encoding="utf-8")

    result = run_test_process(
        [
            sys.executable,
            "-c",
            "import packaging_contract_probe; assert packaging_contract_probe.PROBE == 'visible'",
        ],
        env={**os.environ, "PYTHONPATH": str(dependency_path)},
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


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
    assert "web/services/runtime_helpers.py" in proxy
    assert "web/services/download_safety.py" in proxy
    assert "web/services/domain_normalization.py" in proxy
    assert "web/services/version_status.py" in proxy
    assert "web/services/proxy_logs.py" in proxy
    assert "web/services/observability_queries.py" not in proxy
    assert "web/services/report_schedule_recipients.py" not in proxy
    assert "web/services/report_schedule_recipients.py" not in admin
    assert "web/services/helper_runtime.py" in admin
    assert "web/services/runtime_helpers.py" in admin
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


def test_proxy_management_server_imports_packaged_proxy_application(tmp_path) -> None:
    dockerfile = _read("docker/Dockerfile.proxy")
    supervisord = _read("docker/supervisord.proxy.conf")
    package = tmp_path / "proxy"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "app.py").write_text(
        "def app(environ, start_response):\n    return []\n",
        encoding="utf-8",
    )
    (package / "management_server.py").write_text(
        _read("proxy/management_server.py"), encoding="utf-8"
    )

    assert "WORKDIR /app" in dockerfile
    assert "COPY proxy /app/proxy" in dockerfile
    assert "directory=/app" in supervisord
    assert "command=python3 -m proxy.management_server\n" in supervisord
    # The packaged entry point serves the packaged management application.
    script = """
import inspect
import proxy.app
import proxy.management_server as server

assert "from proxy.app import app" in inspect.getsource(server.main)
assert callable(proxy.app.app)
"""
    result = run_test_process(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_admin_wsgi_imports_flat_packaged_application(tmp_path) -> None:
    dockerfile = _read("docker/Dockerfile.admin")
    supervisord = _read("docker/supervisord.admin.conf")
    launcher = _load_start_admin_ui_module()
    (tmp_path / "app.py").write_text(
        'from flask import Flask\napp = Flask("packaged-admin-app")\n'
        "def install_admin_default_proxy_resolver():\n    pass\n",
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
    "proxy.management_server",
    "proxy.public_app",
    "proxy.agent",
    "proxy.forwarding_canary",
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
    for marker in (
        "proxy.management_server",
        "proxy.public_app:app",
        "proxy.agent",
        "proxy.forwarding_canary",
    ):
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


def test_mysql_backed_ci_job_runs_the_whole_non_live_suite() -> None:
    # Most MySQL-backed tests are unmarked and skip without a database, so a
    # mysql-marker or file-list selection would leave them unexercised.
    mysql_job = _workflow_job_body(
        _read(".github/workflows/publish-ghcr.yml"),
        "mysql-integration-tests",
    )

    assert 'python -m pytest -m "not live" -p no:cacheprovider' in mysql_job
    assert "MYSQL_TEST_HOST: 127.0.0.1" in mysql_job
    assert '-m "not live" -p no:cacheprovider --durations=10 -ra web\\tests' in (
        _read("README.md")
    )


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


def test_live_test_workflow_preserves_result_and_collects_pre_timeout_diagnostics() -> (
    None
):
    workflow = _read(".github/workflows/publish-ghcr.yml")
    job = _workflow_job_body(workflow, "live-tests")

    assert "timeout-minutes: 35" in job
    assert (
        "timeout --foreground --signal=TERM --kill-after=30s 25m\n"
        "          docker compose"
    ) in job
    run_step = job.split("      - name: Run live tests\n", 1)[1].split(
        "\n      - name:", 1
    )[0]
    assert "--exit-code-from live-tests live-tests" in run_step
    assert "continue-on-error" not in run_step
    assert "|| true" not in run_step

    diagnostics_step = job.split(
        "      - name: Capture bounded live-test diagnostics\n", 1
    )[1].split("\n      - name:", 1)[0]
    assert "if: failure()" in diagnostics_step
    assert "services=(proxy proxy-edge-2 admin-ui live-tests)" in diagnostics_step
    assert 'ps --all "${services[@]}"' in diagnostics_step
    assert 'ps --all --format json "${services[@]}"' in diagnostics_step
    assert '--tail 200 "$service"' in diagnostics_step
    assert diagnostics_step.count("timeout --foreground --kill-after=5s 30s") == 3
    assert "logs --no-color --timestamps" in diagnostics_step
    assert "docker compose logs --no-color\n" not in job

    artifact_step = job.split("      - name: Retain live-test diagnostics\n", 1)[
        1
    ].split("\n      - name:", 1)[0]
    assert "if: failure()" in artifact_step
    assert re.search(r"uses: actions/upload-artifact@[0-9a-f]{40}", artifact_step)
    assert "path: live-test-diagnostics/" in artifact_step
    assert "if-no-files-found: error" in artifact_step

    teardown_step = job.split("      - name: Tear down live-test stack\n", 1)[1]
    assert "if: always()" in teardown_step
    assert "down -v --remove-orphans" in teardown_step
    assert (
        job.index("Capture bounded live-test diagnostics")
        < job.index("Retain live-test diagnostics")
        < job.index("Tear down live-test stack")
    )


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
    assert "\ndisable_log_bin\n" in mysql_conf
    mysql_settings = [
        line.strip()
        for line in mysql_conf.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert not any(
        line.startswith(("log_bin", "log-bin", "binlog_expire"))
        for line in mysql_settings
    )

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
    assert 'av_pid="/var/run/c-icap/c-icap-av.pid"' in entrypoint
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
    assert "web/services/clamd_protocol.py" in dockerfile
    assert "c-icap-modules-clamd-timeout.patch" in dockerfile
    assert "patch --batch --forward -p1" in dockerfile
    clamd_timeout_patch = _read("docker/patches/c-icap-modules-clamd-timeout.patch")
    assert (
        '{"ClamdTimeout", &CLAMD_TIMEOUT, ci_cfg_set_int, NULL}' in clamd_timeout_patch
    )
    assert "SO_RCVTIMEO" in clamd_timeout_patch
    assert "SO_SNDTIMEO" in clamd_timeout_patch
    assert "poll(&waiter, 1, timeout_seconds * 1000)" in clamd_timeout_patch
    assert "connect_result < 0" in clamd_timeout_patch
    assert "waiter.revents & (POLLERR | POLLHUP | POLLNVAL)" in clamd_timeout_patch
    assert "fcntl(sockd, F_SETFL, flags)" in clamd_timeout_patch
    assert "clamd_mod.ClamdTimeout ${CLAMD_TIMEOUT:-5}" in entrypoint

    admin_dockerfile = _read("docker/Dockerfile.admin")
    assert "web/services/clamd_protocol.py" in admin_dockerfile

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
            "a2ed1d4d1ad7226e638fcf6878ef29e241690ca4",
            "c-icap-server",
            "c_icap_src",
            "c_icap_commit",
        ),
        "CICAP_MODULES": (
            "e1f6af0e06be1ae1e8b8f822ae74bc0d352b788f",
            "c-icap-modules",
            "c_icap_modules_src",
            "c_icap_modules_commit",
        ),
    }
    assert "_GIT_REF" not in proxy
    for prefix, (
        git_commit,
        repository,
        checkout,
        info_key,
    ) in expected_sources.items():
        assert f"ARG {prefix}_GIT_COMMIT={git_commit}" in proxy
        build_step = proxy.split(f"cd {checkout};", 1)[1].split("make install", 1)[0]
        assert (
            f"git fetch --quiet --depth 1 https://github.com/c-icap/{repository}.git "
            f'"${{{prefix}_GIT_COMMIT}}"'
        ) in build_step
        assert 'actual_commit="$(git rev-parse HEAD)"' in build_step
        assert f'"${{{prefix}_GIT_COMMIT}}"' in build_step
        assert "source verification failed" in build_step
        assert build_step.index("git rev-parse HEAD") < build_step.index("./configure")
        assert f'"{info_key}=${{{prefix}_GIT_COMMIT}}"' in proxy


def test_images_record_resolved_package_snapshot() -> None:
    helper = _read("docker/record-build-info.sh")
    assert "/etc/alpine-release" in helper
    assert 'apk info -e -v "$1"' in helper

    for dockerfile, packages in (
        ("docker/Dockerfile.admin", ("python3", "openssl", "xmlsec")),
        ("docker/Dockerfile.proxy", ("squid", "python3", "openssl")),
    ):
        text = _read(dockerfile)
        runtime_stage = _dockerfile_stages(dockerfile)[-1]
        assert (
            'LABEL org.opencontainers.image.base.name="docker.io/library/alpine:'
            '${ALPINE_VERSION}"'
        ) in runtime_stage
        record = runtime_stage.split(
            'RUN record-build-info "alpine:${ALPINE_VERSION}"'
        )[1]
        assert runtime_stage.index("RUN apk-install") < runtime_stage.index(
            "RUN record-build-info"
        )
        for package in packages:
            assert f" {package}" in record.split("\n\n", 1)[0]
        for stage in _dockerfile_stages(dockerfile):
            if "RUN apk-install" in stage:
                assert stage.index("ARG PACKAGE_REFRESH=") < stage.index(
                    "RUN apk-install"
                )
        assert "ARG ALPINE_VERSION=edge" in text


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


@pytest.mark.parametrize(
    ("name", "default"),
    [("PAC_HTTP_PORT", "80"), ("FORWARDING_CANARY_PORT", "18080")],
)
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("1", "1"),
        ("65535", "65535"),
        ("00080", "80"),
        ("", None),
        ("malformed", None),
        ("0", None),
        ("-1", None),
        ("65536", None),
        ("9" * 5000, None),
    ],
)
def test_proxy_listener_ports_use_one_bounded_startup_contract(
    name: str, default: str, value: str, expected: str | None
) -> None:
    env = {**os.environ, name: value}
    result = run_test_process(
        ["/bin/sh", "-c", _entrypoint_numeric_env_script()],
        cwd=REPO_ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    fields = dict(
        zip(
            (
                "PAC_HTTP_PORT",
                "FORWARDING_CANARY_PORT",
                "WEB_WORKERS",
                "WEB_THREADS",
                "WEB_TIMEOUT",
                "WEB_GRACEFUL_TIMEOUT",
                "WEB_KEEPALIVE",
            ),
            result.stdout.strip().split("|"),
            strict=True,
        )
    )
    assert fields[name] == (default if expected is None else expected)


@pytest.mark.parametrize(
    ("name", "default"),
    [
        ("WEB_WORKERS", "1"),
        ("WEB_THREADS", "2"),
        ("WEB_TIMEOUT", "120"),
        ("WEB_GRACEFUL_TIMEOUT", "30"),
        ("WEB_KEEPALIVE", "5"),
    ],
)
@pytest.mark.parametrize("value", ["malformed", "-1", "2147483648", "9" * 5000])
def test_proxy_gunicorn_numeric_controls_reject_unsafe_values(
    name: str, default: str, value: str
) -> None:
    env = {**os.environ, name: value}
    result = run_test_process(
        ["/bin/sh", "-c", _entrypoint_numeric_env_script()],
        cwd=REPO_ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    fields = result.stdout.strip().split("|")
    index = [
        "PAC_HTTP_PORT",
        "FORWARDING_CANARY_PORT",
        "WEB_WORKERS",
        "WEB_THREADS",
        "WEB_TIMEOUT",
        "WEB_GRACEFUL_TIMEOUT",
        "WEB_KEEPALIVE",
    ].index(name)
    assert fields[index] == default


@pytest.mark.parametrize(
    ("name", "default"),
    [
        ("WEB_WORKERS", "1"),
        ("WEB_THREADS", "2"),
        ("WEB_TIMEOUT", "120"),
        ("WEB_GRACEFUL_TIMEOUT", "30"),
    ],
)
def test_proxy_gunicorn_positive_controls_reject_zero(name: str, default: str) -> None:
    env = {**os.environ, name: "0"}
    result = run_test_process(
        ["/bin/sh", "-c", _entrypoint_numeric_env_script()],
        cwd=REPO_ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    fields = result.stdout.strip().split("|")
    index = [
        "PAC_HTTP_PORT",
        "FORWARDING_CANARY_PORT",
        "WEB_WORKERS",
        "WEB_THREADS",
        "WEB_TIMEOUT",
        "WEB_GRACEFUL_TIMEOUT",
    ].index(name)
    assert fields[index] == default


def test_proxy_gunicorn_numeric_controls_preserve_boundaries() -> None:
    env = {
        **os.environ,
        "WEB_WORKERS": "0001",
        "WEB_THREADS": "2147483647",
        "WEB_TIMEOUT": "1",
        "WEB_GRACEFUL_TIMEOUT": "30",
        "WEB_KEEPALIVE": "0",
    }
    result = run_test_process(
        ["/bin/sh", "-c", _entrypoint_numeric_env_script()],
        cwd=REPO_ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().endswith("|1|2147483647|1|30|0")


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
    assert 'Path("/proc").glob("[0-9]*")' in healthcheck
    assert 'b"gunicorn" not in cmdline or b"wsgi:app" not in cmdline' in healthcheck
    assert "parent_pid in processes" in healthcheck
    assert "socket.create_connection" in healthcheck
    assert "from tools.start_admin_ui import resolve_admin_ui_bind" in healthcheck
    assert "(bind.health_host, bind.port)" in healthcheck
    assert '("127.0.0.1", 5000)' not in healthcheck
    assert "Do not issue an HTTP request" in healthcheck


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
    ).replace(
        "    processes = gunicorn_app_processes()\n",
        "    processes = {100: 1, 101: 100}\n",
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
    ).replace(
        "    processes = gunicorn_app_processes()\n",
        "    processes = {100: 1, 101: 100}\n",
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


def test_admin_healthcheck_rejects_master_without_booted_wsgi_worker() -> None:
    healthcheck = _read("docker/healthcheck.admin.sh")
    script = healthcheck.split("python3 - <<'PY'\n", 1)[1].split("\nPY", 1)[0]
    script = script.replace(
        "    processes = gunicorn_app_processes()\n",
        "    processes = {100: 1}\n",
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
    from services.clamav_config_forms import (
        EVENT_STREAM_ACCEPT_REGEX,
        STREAMING_RESPONSE_MIME_REGEX,
    )

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
    assert (
        "acl file_security_streaming_response rep_mime_type -i "
        f"{STREAMING_RESPONSE_MIME_REGEX}'" in entrypoint
    )
    assert (
        "acl file_security_event_stream_request req_header Accept -i "
        f'{EVENT_STREAM_ACCEPT_REGEX}"' in entrypoint
    )
    assert (
        "adaptation_access av_resp_set deny file_security_event_stream_request "
        "file_security_streaming_response" in entrypoint
    )


def test_proxy_entrypoint_only_reads_persisted_config_before_startup_complete() -> None:
    entrypoint = _read("docker/entrypoint.sh")
    pre_complete = entrypoint.split(
        "python3 /app/services/squid_transaction.py startup-complete", 1
    )[0]
    persisted_references = [
        line.strip()
        for line in pre_complete.splitlines()
        if "PERSISTED_SQUID_CONF_PATH" in line
    ]

    assert "ensure_auth_cookie_cache_deny /etc/squid/squid.conf" in entrypoint
    assert persisted_references == [
        'PERSISTED_SQUID_CONF_PATH="${PERSISTED_SQUID_CONF_PATH:-/var/lib/squid-flask-proxy/squid.conf}"',
        "export PERSISTED_SQUID_CONF_PATH",
        '--persisted "$PERSISTED_SQUID_CONF_PATH" \\',
        'if [ -f "$PERSISTED_SQUID_CONF_PATH" ]; then',
        'cp "$PERSISTED_SQUID_CONF_PATH" /etc/squid/squid.conf',
        'if [ -n "$TEMPLATE" ] && [ ! -f "$PERSISTED_SQUID_CONF_PATH" ]; then',
        'PERSISTED_SQUID_WORKERS="$(extract_squid_workers_from_file "$PERSISTED_SQUID_CONF_PATH")"',
        '--persisted "$PERSISTED_SQUID_CONF_PATH" \\',
    ]


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

    _run_entrypoint_perf_tuning(config, overrides="SQUID_SSLCRTD_CHILDREN=2")

    rendered = config.read_text(encoding="utf-8")
    assert "sslcrtd_children 2 startup=2 idle=2 queue-size=96" in rendered
    assert "sslcrtd_children 2\n" not in rendered


def test_proxy_entrypoint_perf_tuning_caps_sslcrtd_subordinate_counts(
    tmp_path,
) -> None:
    config = tmp_path / "squid.conf"
    config.write_text(
        "workers 1\n"
        "cache_mem 256 MB\n"
        "sslcrtd_children 4 startup=3 idle=2 queue-size=96\n"
        "max_filedescriptors 65536\n",
        encoding="utf-8",
    )

    _run_entrypoint_perf_tuning(config, overrides="SQUID_SSLCRTD_CHILDREN=1")

    rendered = config.read_text(encoding="utf-8")
    assert "sslcrtd_children 1 startup=1 idle=1 queue-size=96" in rendered


def test_proxy_entrypoint_perf_tuning_synthesizes_sslcrtd_child_options(
    tmp_path,
) -> None:
    config = tmp_path / "squid.conf"
    config.write_text("workers 4\ncache_mem 256 MB\n", encoding="utf-8")

    _run_entrypoint_perf_tuning(config, overrides="SQUID_SSLCRTD_CHILDREN=2")

    rendered = config.read_text(encoding="utf-8")
    assert "sslcrtd_children 2 startup=2 idle=1 queue-size=32" in rendered


_ENTRYPOINT_SIZING_NAMES = (
    "SQUID_HOST_CONFIG_OVERRIDES",
    "SQUID_WORKERS",
    "SQUID_CACHE_MEM_MB",
    "SQUID_SSLCRTD_CHILDREN",
    "SQUID_DYNAMIC_CERT_MEM_CACHE_MB",
    "SQUID_MAX_FILEDESCRIPTORS",
)


def _run_entrypoint_sizing_resolution(tmp_path, **env_values: str) -> dict[str, str]:
    persisted = tmp_path / "persisted.conf"
    persisted.write_text("workers 3\n", encoding="utf-8")
    script = "\n".join(
        [
            "set -eu",
            _entrypoint_shell_block("clamp_int() {", "\nsanitize_bounded_int() {"),
            _entrypoint_shell_block(
                "# Host configuration overrides: validate the operator's sizing and listener",
                '\nif [ -z "${ULIMIT_NOFILE:-}" ]; then',
            )
            .replace(
                "python3 /app/services/squid_host_overrides.py",
                _host_overrides_helper_command(),
            )
            .replace("/etc/squid/squid.conf", str(tmp_path / "missing.conf")),
            "printf '%s\\n' "
            + " ".join(f'"{name}=${name}"' for name in _ENTRYPOINT_SIZING_NAMES),
        ],
    )
    env = {
        key: value for key, value in os.environ.items() if not key.startswith("SQUID_")
    }
    env.update(env_values)
    env["PERSISTED_SQUID_CONF_PATH"] = str(persisted)
    result = run_test_process(
        ["/bin/sh", "-c", script],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    values = dict(line.split("=", 1) for line in result.stdout.splitlines())
    values["stderr"] = result.stderr
    return values


def test_proxy_entrypoint_exports_validated_host_sizing_overrides(tmp_path) -> None:
    values = _run_entrypoint_sizing_resolution(
        tmp_path,
        SQUID_WORKERS="9",
        SQUID_CACHE_MEM_MB="32",
        SQUID_SSLCRTD_CHILDREN="1",
    )

    assert values["SQUID_HOST_CONFIG_OVERRIDES"] == (
        "SQUID_CACHE_MEM_MB=32 SQUID_SSLCRTD_CHILDREN=1"
    )
    assert "SQUID_WORKERS=9 is outside 1..4" in values["stderr"]
    # An ignored worker override falls back to the persisted config.
    assert values["SQUID_WORKERS"] == "3"
    assert values["SQUID_CACHE_MEM_MB"] == "32"
    assert values["SQUID_SSLCRTD_CHILDREN"] == "1"
    assert values["SQUID_DYNAMIC_CERT_MEM_CACHE_MB"] == "384"
    assert values["SQUID_MAX_FILEDESCRIPTORS"] == "98304"


def test_proxy_entrypoint_without_sizing_env_exports_no_overrides(tmp_path) -> None:
    values = _run_entrypoint_sizing_resolution(tmp_path, SQUID_CACHE_MEM_MB="lots")

    assert values["SQUID_HOST_CONFIG_OVERRIDES"] == ""
    assert values["SQUID_CACHE_MEM_MB"] == "256"
    assert "SQUID_CACHE_MEM_MB='lots'" in values["stderr"]


def test_proxy_entrypoint_perf_tuning_pins_host_overrides(tmp_path) -> None:
    config = tmp_path / "squid.conf"
    config.write_text(
        "workers 4\n"
        "cache_mem 256 MB\n"
        "cache_dir rock /var/spool/squid 10000 slot-size=32768\n"
        "http_port 3128 ssl-bump generate-host-certificates=on dynamic_cert_mem_cache_size=128MB\n",
        encoding="utf-8",
    )

    _run_entrypoint_perf_tuning(
        config,
        overrides="SQUID_WORKERS=1 SQUID_CACHE_MEM_MB=32 SQUID_CACHE_DIR_MB=1024 "
        "SQUID_DYNAMIC_CERT_MEM_CACHE_MB=16",
    )

    rendered = config.read_text(encoding="utf-8")
    assert "workers 1\n" in rendered
    assert "cache_mem 32 MB\n" in rendered
    assert "cache_dir rock /var/spool/squid 1024 slot-size=32768\n" in rendered
    assert "dynamic_cert_mem_cache_size=16MB" in rendered


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

    _captured, applied = _run_host_override_helper(
        config,
        {
            "SQUID_HTTPS_INTERCEPT_ENABLED": "1",
            "SQUID_HTTPS_INTERCEPT_PORT": "3130",
        },
    )

    assert applied.returncode == 0, applied.stderr
    rendered = config.read_text(encoding="utf-8")
    assert "# BEGIN SQUID-UI HTTPS INTERCEPT LISTENER" in rendered
    assert "https_port 0.0.0.0:3130 intercept ssl-bump" in rendered
    assert "name=https_intercept" in rendered
    assert "\tdynamic_cert_mem_cache_size=256MB\n# END SQUID-UI HTTPS" in rendered


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
    env = {
        "SQUID_HTTPS_INTERCEPT_ENABLED": "1",
        "SQUID_HTTPS_INTERCEPT_PORT": "3130",
        "SQUID_HTTPS_INTERCEPT_SPLICE_ONLY": "1",
    }

    _captured, applied = _run_host_override_helper(config, env)

    assert applied.returncode == 0, applied.stderr
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

    _captured, applied = _run_host_override_helper(
        config,
        {**env, "SQUID_HTTPS_INTERCEPT_SPLICE_ONLY": "0"},
    )

    assert applied.returncode == 0, applied.stderr
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

    _captured, applied = _run_host_override_helper(
        config,
        {"SQUID_HTTPS_INTERCEPT_ENABLED": "0"},
    )

    assert applied.returncode == 0, applied.stderr
    assert config.read_text(encoding="utf-8") == (
        "http_port 0.0.0.0:3128 ssl-bump\nssl_bump peek step1\n"
    )


def test_proxy_entrypoint_env_rejects_duplicate_pinned_ports_and_shifts_defaults(
    tmp_path,
) -> None:
    config = tmp_path / "squid.conf"
    config.write_text("http_port 0.0.0.0:3130 ssl-bump\n", encoding="utf-8")

    captured, applied = _run_host_override_helper(
        config,
        {
            "SQUID_INTERCEPT_ENABLED": "1",
            "SQUID_INTERCEPT_PORT": "3131",
            "SQUID_HTTPS_INTERCEPT_ENABLED": "1",
            "SQUID_HTTPS_INTERCEPT_PORT": "3131",
        },
    )

    # A port pinned twice cannot be honoured for both listeners: the later
    # variable is ignored, and the unpinned listener's default port moves off
    # the ports already in use.
    assert "SQUID_HTTPS_INTERCEPT_PORT=3131 is already pinned" in captured.stderr
    assert applied.returncode == 0, applied.stderr
    rendered = config.read_text(encoding="utf-8")
    assert "http_port 0.0.0.0:3130 ssl-bump" in rendered
    assert "http_port 0.0.0.0:3131 intercept" in rendered
    assert "https_port 0.0.0.0:3132 intercept ssl-bump" in rendered


def test_proxy_entrypoint_stops_on_pinned_port_used_by_another_listener(
    tmp_path,
) -> None:
    original = "http_port 0.0.0.0:3128 ssl-bump\nhttp_port 3129 tproxy\n"
    config = tmp_path / "squid.conf"
    config.write_text(original, encoding="utf-8")

    _captured, applied = _run_host_override_helper(
        config,
        {"SQUID_INTERCEPT_PORT": "3129"},
    )

    assert applied.returncode == 1
    assert "ERROR: Host-pinned listener port(s) SQUID_INTERCEPT_PORT=3129" in (
        applied.stderr
    )
    assert config.read_text(encoding="utf-8") == original


def test_public_pac_listener_runs_apart_from_management_and_loads_no_database() -> None:
    import configparser

    parser = configparser.RawConfigParser(inline_comment_prefixes=(";",))
    parser.read(REPO_ROOT / "docker" / "supervisord.proxy.conf", encoding="utf-8")
    api = parser.get("program:proxy_api", "command")
    public = parser.get("program:proxy_public", "command")
    # PAC/WPAD must never wait behind management or control-plane DB work.
    assert "PAC_HTTP_PORT" not in api
    assert "PAC_HTTP_PORT" in public
    assert "proxy.public_app:app" in public
    assert "PAC_WEB_THREADS" in public
    # Nothing uses a gunicorn control socket; it would cost the arbiter a thread.
    assert "--no-control-socket" in public

    probe = (
        "import sys; import proxy.public_app; "
        "print(sorted(m for m in sys.modules if m in "
        "{'pymysql', 'services.db', 'proxy.runtime', 'proxy.agent'}))"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe],
        check=True,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env={**os.environ, "PYTHONPATH": f"{REPO_ROOT}:{REPO_ROOT / 'web'}"},
    )
    assert result.stdout.strip() == "[]"


def test_images_ship_build_time_bytecode() -> None:
    """Fresh containers must not compile dependencies or /app at first import."""
    for dockerfile in ("docker/Dockerfile.proxy", "docker/Dockerfile.admin"):
        text = _read(dockerfile)
        assert "--no-compile" not in text, dockerfile
        assert "RUN python3 -m compileall -q /app" in text, dockerfile
