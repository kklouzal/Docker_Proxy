from __future__ import annotations

import os
import random
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

HERE = Path(__file__).resolve().parent
APP_ROOT = HERE.parent
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

DEFAULT_CERTFILE = "/etc/squid/ssl/certs/admin-ui.crt"
DEFAULT_KEYFILE = "/etc/squid/ssl/certs/admin-ui.key"
GUNICORN_NUMERIC_DEFAULTS = {
    "WEB_WORKERS": "1",
    "WEB_THREADS": "2",
    "WEB_TIMEOUT": "120",
    "WEB_GRACEFUL_TIMEOUT": "30",
    "WEB_KEEPALIVE": "5",
}
BIND_ALL_IPV4 = "0.0.0.0"  # ruff: ignore[hardcoded-bind-all-interfaces] - intentional container listener wildcard
DATABASE_ENV_NAMES = ("DATABASE_URL", "MYSQL_HOST", "MYSQL_DATABASE", "MYSQL_USER")
# Startup waits only on MySQL failures that a starting, restarting, or not yet
# routable server produces. Anything else (credentials, privileges, schema
# history drift) is a configuration defect and fails startup loudly.
MYSQL_STARTUP_TRANSIENT_CODES = frozenset({1040, 1053, 2002, 2003, 2005, 2006, 2013})
MYSQL_WAIT_INITIAL_DELAY_SECONDS = 0.5
MYSQL_WAIT_MAX_DELAY_SECONDS = 5.0
MYSQL_WAIT_LOG_INTERVAL_SECONDS = 60.0


@dataclass(frozen=True)
class AdminUiHttpsRuntimeConfig:
    enabled: bool
    certfile: str
    keyfile: str
    source: str
    error: str = ""


@dataclass(frozen=True)
class AdminUiBindConfig:
    gunicorn_bind: str
    health_host: str
    port: int


def _parse_port(value: str, *, source: str) -> int:
    if not re.fullmatch(r"[0-9]+", value):
        message = f"{source} port must be a decimal integer"
        raise ValueError(message)
    port = int(value)
    if not 1 <= port <= 65535:
        message = f"{source} port must be between 1 and 65535"
        raise ValueError(message)
    return port


def resolve_admin_ui_bind(environ: Mapping[str, str]) -> AdminUiBindConfig:
    """Return one strict Gunicorn/healthcheck bind contract."""
    raw_bind = (environ.get("ADMIN_UI_BIND") or "").strip()
    if not raw_bind:
        raw_port = (environ.get("ADMIN_UI_PORT") or "5000").strip()
        port = _parse_port(raw_port, source="ADMIN_UI_PORT")
        return AdminUiBindConfig(f"{BIND_ALL_IPV4}:{port}", "127.0.0.1", port)

    if raw_bind.isdigit():
        port = _parse_port(raw_bind, source="ADMIN_UI_BIND")
        return AdminUiBindConfig(f"{BIND_ALL_IPV4}:{port}", "127.0.0.1", port)

    if raw_bind.startswith("["):
        match = re.fullmatch(r"\[([^]]+)]:(\d+)", raw_bind)
        if match is None:
            message = "ADMIN_UI_BIND bracketed IPv6 form must be [address]:port"
            raise ValueError(message)
        host, raw_port = match.groups()
        port = _parse_port(raw_port, source="ADMIN_UI_BIND")
        health_host = "::1" if host == "::" else host
        return AdminUiBindConfig(f"[{host}]:{port}", health_host, port)

    if raw_bind.count(":") != 1:
        message = (
            "ADMIN_UI_BIND must be port, host:port, or bracketed IPv6 [address]:port"
        )
        raise ValueError(message)
    host, raw_port = raw_bind.rsplit(":", 1)
    port = _parse_port(raw_port, source="ADMIN_UI_BIND")
    if any(character.isspace() for character in host):
        message = "ADMIN_UI_BIND host must not contain whitespace"
        raise ValueError(message)
    health_host = "127.0.0.1" if host in {"", BIND_ALL_IPV4, "*"} else host
    gunicorn_host = BIND_ALL_IPV4 if host in {"", "*"} else host
    return AdminUiBindConfig(f"{gunicorn_host}:{port}", health_host, port)


def _truthy(value: object | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on", "enabled"}


def _log(message: str) -> None:
    sys.stderr.write(f"{message}\n")
    sys.stderr.flush()


def effective_gunicorn_numeric_env(environ: Mapping[str, str]) -> dict[str, str]:
    """Return bounded canonical decimals for Gunicorn and shell arithmetic."""
    effective: dict[str, str] = {}
    maximum = "2147483647"
    for name, default in GUNICORN_NUMERIC_DEFAULTS.items():
        raw = environ.get(name, "")
        if not re.fullmatch(r"[0-9]+", raw or ""):
            effective[name] = default
            continue

        canonical = raw.lstrip("0") or "0"
        oversized = len(canonical) > len(maximum) or (
            len(canonical) == len(maximum) and canonical > maximum
        )
        positive_required = name != "WEB_KEEPALIVE" and canonical == "0"
        effective[name] = default if oversized or positive_required else canonical
    return effective


def database_configured(environ: Mapping[str, str]) -> bool:
    return any((environ.get(name) or "").strip() for name in DATABASE_ENV_NAMES)


def is_transient_mysql_startup_error(exc: BaseException) -> bool:
    try:
        import pymysql
    except ImportError:
        return False
    if not isinstance(exc, pymysql.MySQLError):
        return False
    args = getattr(exc, "args", ())
    code = args[0] if args and isinstance(args[0], int) else None
    if isinstance(exc, pymysql.InterfaceError) and code in {None, 0}:
        return True
    return code in MYSQL_STARTUP_TRANSIENT_CODES


def _probe_mysql_server() -> None:
    """Open and close one unretried server connection.

    The probe deliberately bypasses the pooled, internally retried connect path
    so an unreachable server costs one quiet attempt per wait iteration instead
    of a burst of per-attempt retry warnings. It does not select the database,
    which the migration step may still need to create.
    """
    from services.db import pymysql_connect, resolve_database_config

    cfg = resolve_database_config()
    pymysql_connect(
        host=cfg.host,
        port=int(cfg.port),
        user=cfg.user,
        password=cfg.password,
        charset=cfg.charset,
        connect_timeout=int(cfg.connect_timeout),
        read_timeout=int(cfg.read_timeout),
        write_timeout=int(cfg.write_timeout),
    ).close()


def run_when_mysql_ready[T](
    operation: Callable[[], T],
    *,
    probe: Callable[[], None] = _probe_mysql_server,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    uniform: Callable[[float, float], float] = random.uniform,  # ruff: ignore[suspicious-non-cryptographic-random-usage] - retry jitter
) -> T:
    """Run ``operation`` once MySQL is reachable, waiting without a deadline.

    Transient connectivity failures from the probe or the operation restart the
    wait with capped exponential backoff and jitter. The Admin UI cannot serve
    its DB-authoritative configuration without MySQL, so it waits instead of
    starting degraded; no listener exists meanwhile, so the container
    healthcheck truthfully reports not-ready. Logs are emitted on the first
    failure, when the MySQL error code changes, and at most once per
    ``MYSQL_WAIT_LOG_INTERVAL_SECONDS`` otherwise. Non-transient failures
    propagate unchanged.
    """
    started = monotonic()
    failures = 0
    last_logged_at: float | None = None
    last_code: object = None
    unreachable = False
    while True:
        try:
            probe()
            if unreachable:
                _log(
                    f"MySQL became reachable after {monotonic() - started:.1f}s "
                    f"({failures} failed attempts); continuing Admin UI startup.",
                )
                unreachable = False
            return operation()
        except Exception as exc:
            if not is_transient_mysql_startup_error(exc):
                raise
            failures += 1
            unreachable = True
            now = monotonic()
            cap = min(
                MYSQL_WAIT_MAX_DELAY_SECONDS,
                MYSQL_WAIT_INITIAL_DELAY_SECONDS * (2 ** min(failures - 1, 16)),
            )
            delay = uniform(cap / 2, cap)
            code = exc.args[0] if exc.args else None
            if (
                last_logged_at is None
                or code != last_code
                or now - last_logged_at >= MYSQL_WAIT_LOG_INTERVAL_SECONDS
            ):
                _log(
                    "Waiting for MySQL before starting the Admin UI "
                    f"(elapsed {now - started:.1f}s, failed attempts {failures}, "
                    f"next attempt in {delay:.1f}s): {type(exc).__name__}: {exc}",
                )
                last_logged_at = now
                last_code = code
            sleep(delay)


def _env_https_config(
    environ: Mapping[str, str],
) -> AdminUiHttpsRuntimeConfig:
    enabled = _truthy(environ.get("ADMIN_UI_HTTPS_ENABLED"))
    certfile = (environ.get("ADMIN_UI_SSL_CERTFILE") or "").strip()
    keyfile = (environ.get("ADMIN_UI_SSL_KEYFILE") or "").strip()
    if enabled:
        certfile = certfile or DEFAULT_CERTFILE
        keyfile = keyfile or DEFAULT_KEYFILE
    else:
        certfile = ""
        keyfile = ""
    return AdminUiHttpsRuntimeConfig(
        enabled=enabled,
        certfile=certfile,
        keyfile=keyfile,
        source="env",
    )


def _invalid_saved_https_config(detail: str) -> AdminUiHttpsRuntimeConfig:
    message = (
        "Saved Admin UI HTTPS settings are malformed; starting HTTP so the "
        "Certificates page can recover the setting."
    )
    _log(f"ERROR: {message} {detail}")
    return AdminUiHttpsRuntimeConfig(
        enabled=False,
        certfile="",
        keyfile="",
        source="db-invalid",
        error=message,
    )


def _is_invalid_saved_settings_error(exc: BaseException) -> bool:
    try:
        from services.certificate_bundles import InvalidAdminUiHttpsSettingsError
    except Exception:
        return False
    return isinstance(exc, InvalidAdminUiHttpsSettingsError)


def resolve_admin_ui_https_config(
    environ: Mapping[str, str],
    *,
    settings_loader: Callable[[], object | None] | None = None,
) -> AdminUiHttpsRuntimeConfig:
    """Resolve Admin UI HTTPS mode.

    Persisted UI settings become authoritative after the first explicit save.
    Environment variables remain the bootstrap fallback when no database is
    configured, the settings cannot be read for a non-transient reason, or the
    settings row has not been changed from its seeded default. Transient MySQL
    connectivity errors propagate so startup can wait for the authoritative row.
    """
    fallback = _env_https_config(environ)
    if settings_loader is None:
        try:
            from services.certificate_bundles import get_certificate_bundles

            settings_loader = get_certificate_bundles().get_admin_ui_https_settings
        except Exception as exc:
            _log(
                f"WARNING: failed to prepare Admin UI HTTPS settings loader; using environment fallback: {exc}",
            )
            return fallback
    try:
        settings = settings_loader()
    except Exception as exc:
        if _is_invalid_saved_settings_error(exc):
            return _invalid_saved_https_config(str(exc))
        if is_transient_mysql_startup_error(exc):
            # MySQL is temporarily unreachable: the caller waits and retries
            # rather than pinning this process to the bootstrap fallback.
            raise
        _log(
            f"WARNING: failed to load Admin UI HTTPS settings; using environment fallback: {exc}",
        )
        return fallback

    if settings is None:
        return fallback
    updated_ts = getattr(settings, "updated_ts", 0)
    if isinstance(updated_ts, bool) or not isinstance(updated_ts, int):
        return _invalid_saved_https_config("updated_ts must be a non-negative integer")
    if updated_ts < 0:
        return _invalid_saved_https_config("updated_ts must be a non-negative integer")
    if updated_ts == 0:
        return fallback

    enabled = getattr(settings, "enabled", False)
    if not isinstance(enabled, bool):
        return _invalid_saved_https_config("enabled must be boolean")
    if enabled:
        certfile = DEFAULT_CERTFILE
        keyfile = DEFAULT_KEYFILE
    else:
        certfile = ""
        keyfile = ""
    return AdminUiHttpsRuntimeConfig(
        enabled=enabled,
        certfile=certfile,
        keyfile=keyfile,
        source="db",
    )


def _env_san_tokens(environ: Mapping[str, str]) -> tuple[str, ...]:
    tokens = []
    for name in ("ADMIN_UI_PUBLIC_HOST", "PROXY_PUBLIC_HOST"):
        value = (environ.get(name) or "").strip()
        if value:
            tokens.append(value)
    return tuple(tokens)


def _settings_san_tokens(settings: object | None) -> tuple[str, ...]:
    raw = str(getattr(settings, "san_tokens", "") or "")
    return tuple(token.strip() for token in re.split(r"[\n,]+", raw) if token.strip())


def _persistent_san_tokens(
    saved_tokens: tuple[str, ...],
    env_tokens: tuple[str, ...],
) -> tuple[str, ...]:
    from services.certificate_core import (
        normalize_admin_ui_certificate_san_token,
        normalize_admin_ui_certificate_sans,
    )

    saved: list[str] = []
    seen: set[str] = set()
    implicit = {token.lower() for token in normalize_admin_ui_certificate_sans(())}

    def add(token: str, *, skip_implicit: bool = False) -> None:
        normalized = normalize_admin_ui_certificate_san_token(token)
        if not normalized:
            return
        if skip_implicit and normalized.lower() in implicit:
            return
        key = normalized.lower()
        if key not in seen:
            seen.add(key)
            saved.append(normalized)

    for token in saved_tokens:
        add(token)
    for token in env_tokens:
        add(token, skip_implicit=True)
    return tuple(saved)


def _try_materialize_saved_admin_ui_leaf(
    environ: Mapping[str, str],
) -> AdminUiHttpsRuntimeConfig | None:
    try:
        from services.certificate_bundles import get_certificate_bundles
        from services.certificate_core import materialize_admin_ui_server_certificate

        store = get_certificate_bundles()
        settings = store.get_admin_ui_https_settings()
        bundle = store.get_active_bundle()
        if bundle is None:
            return None
        saved_san_tokens = _settings_san_tokens(settings)
        env_san_tokens = _env_san_tokens(environ)
        san_tokens = (*saved_san_tokens, *env_san_tokens)
        material = materialize_admin_ui_server_certificate(
            str(Path(DEFAULT_CERTFILE).parent),
            bundle,
            san_tokens=san_tokens,
        )
        store.set_admin_ui_https_settings(
            enabled=True,
            certfile=material.certfile,
            keyfile=material.keyfile,
            san_tokens="\n".join(
                _persistent_san_tokens(saved_san_tokens, env_san_tokens),
            ),
            updated_by=getattr(settings, "updated_by", ""),
        )
        return AdminUiHttpsRuntimeConfig(
            enabled=True,
            certfile=material.certfile,
            keyfile=material.keyfile,
            source="db",
        )
    except Exception as exc:
        if is_transient_mysql_startup_error(exc):
            raise
        _log(
            "WARNING: failed to materialize saved Admin UI HTTPS leaf certificate; "
            f"starting HTTP so the Certificates page can recover the setting: {exc}",
        )
        return None


def build_gunicorn_argv(
    environ: Mapping[str, str],
    config: AdminUiHttpsRuntimeConfig,
) -> list[str]:
    bind = resolve_admin_ui_bind(environ).gunicorn_bind
    numeric = effective_gunicorn_numeric_env(environ)
    argv = [
        "python3",
        "-m",
        "gunicorn",
        "-b",
        bind,
        "wsgi:app",
        "--workers",
        numeric["WEB_WORKERS"],
        "--threads",
        numeric["WEB_THREADS"],
        "--timeout",
        numeric["WEB_TIMEOUT"],
        "--graceful-timeout",
        numeric["WEB_GRACEFUL_TIMEOUT"],
        "--keep-alive",
        numeric["WEB_KEEPALIVE"],
        "--worker-tmp-dir",
        "/dev/shm",  # ruff: ignore[hardcoded-temp-file]
        "--error-logfile",
        "-",
    ]
    if config.enabled:
        argv.extend(["--certfile", config.certfile, "--keyfile", config.keyfile])
    return argv


def select_admin_ui_https_config(
    environ: Mapping[str, str],
) -> AdminUiHttpsRuntimeConfig:
    """Resolve the HTTPS mode, recovering a saved-enabled DB leaf if needed."""
    from services.certificate_core import validate_tls_material_paths

    config = resolve_admin_ui_https_config(environ)
    if not (config.enabled and config.source == "db"):
        return config
    if validate_tls_material_paths(config.certfile, config.keyfile).ready:
        return config
    recovered = _try_materialize_saved_admin_ui_leaf(environ)
    if (
        recovered is not None
        and validate_tls_material_paths(recovered.certfile, recovered.keyfile).ready
    ):
        return recovered
    _log(
        "WARNING: saved Admin UI HTTPS setting is enabled but the active "
        "Admin UI leaf certificate is not valid TLS material; starting HTTP so the "
        "Certificates page can recover the setting.",
    )
    return AdminUiHttpsRuntimeConfig(
        enabled=False,
        certfile="",
        keyfile="",
        source="db-missing-material",
        error=(
            "Saved Admin UI HTTPS is enabled, but the Admin UI leaf "
            "certificate is not valid TLS material inside the admin-ui "
            "container."
        ),
    )


def prepare_database_startup(
    environ: Mapping[str, str],
) -> AdminUiHttpsRuntimeConfig:
    """Apply schema migrations once, then select DB-authoritative HTTPS mode.

    The launcher owns this step before Gunicorn starts, so workers boot against
    a migrated schema and the listener is chosen from the saved settings row
    instead of the environment fallback. The step is idempotent and is replayed
    whole by ``run_when_mysql_ready`` after a transient MySQL failure.
    """
    from services.schema_lifecycle import ensure_startup_schema_if_configured

    ensure_startup_schema_if_configured()
    return select_admin_ui_https_config(environ)


def main() -> int:
    if sys.argv[1:] == ["--print-effective-gunicorn-env"]:
        effective = effective_gunicorn_numeric_env(os.environ)
        sys.stdout.write(
            " ".join(effective[name] for name in GUNICORN_NUMERIC_DEFAULTS) + "\n"
        )
        return 0

    from services.certificate_core import validate_tls_material_paths

    if database_configured(os.environ):
        config = run_when_mysql_ready(lambda: prepare_database_startup(os.environ))
    else:
        config = select_admin_ui_https_config(os.environ)
    if config.enabled and config.source != "db":
        material = validate_tls_material_paths(config.certfile, config.keyfile)
        if not material.ready:
            _log(
                "ERROR: Admin UI HTTPS is enabled by "
                f"{config.source} but TLS material is not valid: {material.detail}",
            )
            return 1
    os.environ["ADMIN_UI_EFFECTIVE_HTTPS_ENABLED"] = "1" if config.enabled else "0"
    os.environ["ADMIN_UI_EFFECTIVE_SSL_CERTFILE"] = config.certfile
    os.environ["ADMIN_UI_EFFECTIVE_SSL_KEYFILE"] = config.keyfile
    os.environ["ADMIN_UI_EFFECTIVE_HTTPS_SOURCE"] = config.source
    if config.error:
        os.environ["ADMIN_UI_EFFECTIVE_HTTPS_ERROR"] = config.error
    else:
        os.environ.pop("ADMIN_UI_EFFECTIVE_HTTPS_ERROR", None)
    os.execvp("python3", build_gunicorn_argv(os.environ, config))  # ruff: ignore[start-process-with-no-shell]
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
