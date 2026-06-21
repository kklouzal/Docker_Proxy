from __future__ import annotations

import os
import re
import sys
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


@dataclass(frozen=True)
class AdminUiHttpsRuntimeConfig:
    enabled: bool
    certfile: str
    keyfile: str
    source: str


def _truthy(value: object | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on", "enabled"}


def _log(message: str) -> None:
    sys.stderr.write(f"{message}\n")
    sys.stderr.flush()


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


def resolve_admin_ui_https_config(
    environ: Mapping[str, str],
    *,
    settings_loader: Callable[[], object | None] | None = None,
) -> AdminUiHttpsRuntimeConfig:
    """Resolve Admin UI HTTPS mode.

    Persisted UI settings become authoritative after the first explicit save.
    Environment variables remain the bootstrap fallback when the DB is unavailable
    or the settings row has not been changed from its seeded default.
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
        _log(
            f"WARNING: failed to load Admin UI HTTPS settings; using environment fallback: {exc}",
        )
        return fallback

    if settings is None or int(getattr(settings, "updated_ts", 0) or 0) <= 0:
        return fallback

    enabled = bool(getattr(settings, "enabled", False))
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
        material = materialize_admin_ui_server_certificate(
            str(Path(DEFAULT_CERTFILE).parent),
            bundle,
            san_tokens=(*_settings_san_tokens(settings), *_env_san_tokens(environ)),
        )
        store.set_admin_ui_https_settings(
            enabled=True,
            certfile=material.certfile,
            keyfile=material.keyfile,
            san_tokens=getattr(settings, "san_tokens", ""),
            updated_by=getattr(settings, "updated_by", ""),
        )
        return AdminUiHttpsRuntimeConfig(
            enabled=True,
            certfile=material.certfile,
            keyfile=material.keyfile,
            source="db",
        )
    except Exception as exc:
        _log(
            "WARNING: failed to materialize saved Admin UI HTTPS leaf certificate; "
            f"starting HTTP so the Certificates page can recover the setting: {exc}",
        )
        return None


def build_gunicorn_argv(
    environ: Mapping[str, str],
    config: AdminUiHttpsRuntimeConfig,
) -> list[str]:
    bind = environ.get("ADMIN_UI_BIND") or f"0.0.0.0:{environ.get('ADMIN_UI_PORT') or '5000'}"
    argv = [
        "python3",
        "-m",
        "gunicorn",
        "-b",
        bind,
        "wsgi:app",
        "--workers",
        environ.get("WEB_WORKERS") or "1",
        "--threads",
        environ.get("WEB_THREADS") or "2",
        "--timeout",
        environ.get("WEB_TIMEOUT") or "120",
        "--graceful-timeout",
        environ.get("WEB_GRACEFUL_TIMEOUT") or "30",
        "--keep-alive",
        environ.get("WEB_KEEPALIVE") or "5",
        "--worker-tmp-dir",
        "/dev/shm",  # noqa: S108
        "--error-logfile",
        "-",
    ]
    if config.enabled:
        argv.extend(["--certfile", config.certfile, "--keyfile", config.keyfile])
    return argv


def main() -> int:
    from services.certificate_core import validate_tls_material_paths

    config = resolve_admin_ui_https_config(os.environ)
    if config.enabled:
        material = validate_tls_material_paths(config.certfile, config.keyfile)
        if config.source == "db" and not material.ready:
            recovered = _try_materialize_saved_admin_ui_leaf(os.environ)
            if recovered is not None:
                material = validate_tls_material_paths(
                    recovered.certfile,
                    recovered.keyfile,
                )
            if recovered is not None and material.ready:
                config = recovered
            else:
                _log(
                    "WARNING: saved Admin UI HTTPS setting is enabled but the active "
                    "Admin UI leaf certificate is not valid TLS material; starting HTTP so the "
                    "Certificates page can recover the setting.",
                )
                config = AdminUiHttpsRuntimeConfig(
                    enabled=False,
                    certfile="",
                    keyfile="",
                    source="db-missing-material",
                )
        elif not material.ready:
            _log(
                "ERROR: Admin UI HTTPS is enabled by "
                f"{config.source} but TLS material is not valid: {material.detail}",
            )
            return 1
    os.environ["ADMIN_UI_EFFECTIVE_HTTPS_ENABLED"] = "1" if config.enabled else "0"
    os.environ["ADMIN_UI_EFFECTIVE_SSL_CERTFILE"] = config.certfile
    os.environ["ADMIN_UI_EFFECTIVE_SSL_KEYFILE"] = config.keyfile
    os.environ["ADMIN_UI_EFFECTIVE_HTTPS_SOURCE"] = config.source
    if config.source == "db-missing-material":
        os.environ["ADMIN_UI_EFFECTIVE_HTTPS_ERROR"] = (
            "Saved Admin UI HTTPS is enabled, but the Admin UI leaf certificate "
            "is not valid TLS material inside the admin-ui container."
        )
    else:
        os.environ.pop("ADMIN_UI_EFFECTIVE_HTTPS_ERROR", None)
    os.execvp("python3", build_gunicorn_argv(os.environ, config))  # noqa: S606
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
