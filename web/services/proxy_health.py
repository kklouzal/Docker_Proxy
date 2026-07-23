from __future__ import annotations

import ipaddress
import os
from typing import Any

from services.health_checks import (
    ErrorFormatter,
    annotate_service_target,
    build_clamav_health,
    check_clamd,
    check_http_proxy_forwarding,
    check_icap_service,
    resolve_host_port,
    resolve_tcp_port,
    send_sample_respmod_to,
    test_clamd_eicar,
)
from services.squid_core import (
    _clamav_respmod_stream_port_base,
    _clamd_host_is_remote,
    _clamp_icap_workers,
    _icap_port_bases,
)


def _resolve_host_port_override(
    *,
    host: str | None,
    port: int | None,
    host_env: str,
    port_env: str,
    default_host: str = "127.0.0.1",
    default_port: int,
) -> tuple[str, int]:
    if host is None and port is None:
        return resolve_host_port(
            host_env=host_env,
            port_env=port_env,
            default_host=default_host,
            default_port=default_port,
        )

    resolved_host = (
        host or os.environ.get(host_env) or default_host
    ).strip() or default_host
    resolved_port = resolve_tcp_port(
        port if port is not None else (os.environ.get(port_env) or default_port),
        default_port,
    )
    return resolved_host, resolved_port


def _env_bool(name: str, default: bool = False) -> bool:
    value = (os.environ.get(name) or "").strip().lower()
    if not value:
        return default
    return value in {"1", "true", "yes", "on", "enabled", "required", "strict"}


def _proxy_http_port() -> int:
    try:
        port = int((os.environ.get("SQUID_HTTP_PORT") or "3128").strip())
    except Exception:
        port = 3128
    return port if 1 <= port <= 65535 else 3128


def _forwarding_canary_target_url() -> str:
    host = (
        os.environ.get("FORWARDING_CANARY_HOST") or "127.0.0.1"
    ).strip() or "127.0.0.1"
    normalized_host = host.strip("[]")
    if normalized_host.lower() == "localhost":
        host = "localhost"
    else:
        try:
            address = ipaddress.ip_address(normalized_host)
        except ValueError:
            address = None
        if not (address is not None and address.version == 4 and address.is_loopback):
            # Normalize wildcard, IPv6, and DNS-name inputs to the local IPv4
            # canary target. The canary listener intentionally only accepts
            # IPv4 loopback bind addresses.
            host = "127.0.0.1"
        else:
            host = normalized_host
    display_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    try:
        port = int((os.environ.get("FORWARDING_CANARY_PORT") or "18080").strip())
    except Exception:
        port = 18080
    port = port if 1 <= port <= 65535 else 18080
    path = (
        os.environ.get("FORWARDING_CANARY_PATH") or "/__docker_proxy_forwarding_canary"
    ).strip()
    if (
        not path.startswith("/")
        or "?" in path
        or "#" in path
        or "\\" in path
        or "//" in path
    ):
        path = "/__docker_proxy_forwarding_canary"
    return f"http://{display_host}:{port}{path}"


def unavailable_service(
    detail: str,
    *,
    target: str = "unavailable",
    service: str = "",
) -> dict[str, Any]:
    status: dict[str, Any] = {
        "ok": False,
        "detail": str(detail or "unavailable"),
        "host": "",
        "port": 0,
        "target": target,
    }
    if service:
        status["service"] = service
    return status


def forwarding_mode_detail(
    *,
    forwarding_ok: bool,
    clamav_required: bool,
    av_icap_ok: bool,
) -> str:
    if forwarding_ok:
        if av_icap_ok:
            return "Squid explicit forwarding path returned a local health response."
        if clamav_required:
            return (
                "Squid explicit forwarding path returned a local health response, "
                "but ClamAV is fail-closed and AV ICAP is not healthy."
            )
        return (
            "Squid explicit forwarding path returned a local health response; "
            "ClamAV/adblock ICAP are configured fail-open unless required."
        )
    if clamav_required:
        return (
            "Squid explicit forwarding path is degraded while ClamAV is fail-closed; "
            "AV ICAP/clamd must be healthy before forwarding can be trusted."
        )
    return (
        "Squid explicit forwarding path is degraded. ClamAV/adblock ICAP are "
        "configured fail-open unless required, but forwarding still must return a "
        "local health response before operator health is green."
    )


def check_forwarding_path_health(
    *,
    proxy_host: str = "127.0.0.1",
    proxy_port: int | None = None,
    target_url: str | None = None,
    timeout: float = 1.0,
    av_icap_health: dict[str, Any] | None = None,
    error_formatter: ErrorFormatter | None = None,
) -> dict[str, Any]:
    resolved_proxy_port = int(
        proxy_port if proxy_port is not None else _proxy_http_port()
    )
    resolved_target_url = target_url or _forwarding_canary_target_url()
    result = check_http_proxy_forwarding(
        proxy_host=proxy_host,
        proxy_port=resolved_proxy_port,
        target_url=resolved_target_url,
        timeout=timeout,
        error_formatter=error_formatter,
    )
    clamav_required = _env_bool("CLAMAV_REQUIRED") or _env_bool(
        "FILE_SECURITY_AV_REQUIRED",
    )
    av_icap_ok = bool((av_icap_health or {}).get("ok"))
    status = annotate_service_target(
        result,
        host=proxy_host,
        port=resolved_proxy_port,
        service="explicit-forwarding",
    )
    status["probe_url"] = resolved_target_url
    status["traffic_scope"] = "local-only"
    status["clamav_required"] = clamav_required
    status["fail_mode"] = "closed" if clamav_required else "open"
    status["fail_open"] = not clamav_required
    status["av_icap_ok"] = av_icap_ok
    status["contract"] = forwarding_mode_detail(
        forwarding_ok=bool(status["ok"]),
        clamav_required=clamav_required,
        av_icap_ok=av_icap_ok,
    )
    if not status["ok"]:
        status["detail"] = f"{status['detail']} | {status['contract']}"
    return status


def normalize_service_health(
    result: Any,
    *,
    default_target: str = "unavailable",
    service: str = "",
) -> dict[str, Any]:
    if not isinstance(result, dict):
        return unavailable_service(
            "unavailable",
            target=default_target,
            service=service,
        )
    detail = str(result.get("detail") or "unavailable")
    host = str(result.get("host") or "")
    try:
        port = int(result.get("port") or 0)
    except Exception:
        port = 0
    target = str(
        result.get("target") or (f"{host}:{port}" if host and port else default_target),
    )
    normalized = {
        "ok": bool(result.get("ok")),
        "detail": detail,
        "host": host,
        "port": port,
        "target": target,
    }
    effective_service = str(result.get("service") or service)
    if effective_service:
        normalized["service"] = effective_service
    return normalized


def _remote_health_source(health_payload: dict[str, Any]) -> str:
    source = str(
        health_payload.get("proxy_status") or health_payload.get("detail") or "",
    )
    if health_payload.get("_stale"):
        stale_detail = str(
            health_payload.get("health_cache_detail")
            or health_payload.get("detail")
            or "using recent cached health after refresh failure",
        )
        return f"{source} ({stale_detail})" if source else stale_detail
    if health_payload.get("_unavailable_cached"):
        unavailable_detail = str(
            health_payload.get("detail") or "proxy health unavailable",
        )
        return f"{source} ({unavailable_detail})" if source else unavailable_detail
    return source


def build_unavailable_runtime_health(
    detail: str,
    *,
    proxy_status: str = "offline",
) -> dict[str, Any]:
    icap = unavailable_service(detail)
    av_icap = unavailable_service(detail, service="/avrespmod")
    clamd = unavailable_service(detail)
    return {
        "ok": False,
        "status": proxy_status,
        "proxy_status": str(detail or "unavailable"),
        "stats": {},
        "services": {
            "icap": icap,
            "av_icap": av_icap,
            "clamd": clamd,
            "clamav": {
                "ok": False,
                "detail": str(detail or "unavailable"),
                "components": {
                    "av_icap": av_icap,
                    "clamd": clamd,
                },
            },
        },
    }


def _check_resolved_icap_target(
    icap_service: str,
    *,
    host: str | None,
    port: int | None,
    port_env: str,
    default_port: int,
    timeout: float,
    error_formatter: ErrorFormatter | None,
    user_agent: str = "squid-flask-proxy-ui",
    success_detail: str | None = None,
) -> dict[str, Any]:
    resolved_host, resolved_port = _resolve_host_port_override(
        host=host,
        port=port,
        host_env="CICAP_HOST",
        port_env=port_env,
        default_port=default_port,
    )
    result = check_icap_service(
        host=resolved_host,
        port=resolved_port,
        service=icap_service,
        timeout=timeout,
        user_agent=user_agent,
        success_detail=success_detail,
        error_formatter=error_formatter,
    )
    return annotate_service_target(
        result,
        host=resolved_host,
        port=resolved_port,
        service=icap_service,
    )


def _call_resolved_clamd_target(
    probe: Any,
    *,
    host: str | None,
    port: int | None,
    timeout: float,
    error_formatter: ErrorFormatter | None,
    annotate: bool = False,
) -> dict[str, Any]:
    resolved_host, resolved_port = _resolve_host_port_override(
        host=host,
        port=port,
        host_env="CLAMD_HOST",
        port_env="CLAMD_PORT",
        default_port=3310,
    )
    result = probe(
        host=resolved_host,
        port=resolved_port,
        timeout=timeout,
        error_formatter=error_formatter,
    )
    if annotate:
        return annotate_service_target(
            result,
            host=resolved_host,
            port=resolved_port,
        )
    return result


def check_adblock_icap_health(
    *,
    host: str | None = None,
    port: int | None = None,
    timeout: float = 0.8,
    error_formatter: ErrorFormatter | None = None,
) -> dict[str, Any]:
    return _check_resolved_icap_target(
        "/adblockreq",
        host=host,
        port=port,
        port_env="CICAP_PORT",
        default_port=14000,
        timeout=timeout,
        error_formatter=error_formatter,
    )


def _check_av_icap_endpoint(
    *,
    host: str,
    port: int,
    timeout: float,
    error_formatter: ErrorFormatter | None,
) -> dict[str, Any]:
    result = check_icap_service(
        host=host,
        port=port,
        service="/avrespmod",
        timeout=timeout,
        user_agent="squid-flask-proxy-ui",
        error_formatter=error_formatter,
    )
    return annotate_service_target(
        result,
        host=host,
        port=port,
        service="/avrespmod",
    )


def check_av_icap_health(
    *,
    host: str | None = None,
    port: int | None = None,
    timeout: float = 0.8,
    error_formatter: ErrorFormatter | None = None,
) -> dict[str, Any]:
    if port is not None or not _clamd_host_is_remote(os.environ.get("CLAMD_HOST")):
        resolved_host, resolved_port = _resolve_host_port_override(
            host=host,
            port=port,
            host_env="CICAP_HOST",
            port_env="CICAP_AV_PORT",
            default_port=14001,
        )
        return _check_av_icap_endpoint(
            host=resolved_host,
            port=resolved_port,
            timeout=timeout,
            error_formatter=error_formatter,
        )

    resolved_host = (
        host or os.environ.get("CICAP_HOST") or "127.0.0.1"
    ).strip() or "127.0.0.1"
    workers = _clamp_icap_workers(
        os.environ.get("SQUID_WORKERS") or os.environ.get("WORKERS") or "1"
    )
    _adblock_base, upload_port = _icap_port_bases(workers)
    download_port = _clamav_respmod_stream_port_base(workers)
    upload = _check_av_icap_endpoint(
        host=resolved_host,
        port=upload_port,
        timeout=timeout,
        error_formatter=error_formatter,
    )
    download = _check_av_icap_endpoint(
        host=resolved_host,
        port=download_port,
        timeout=timeout,
        error_formatter=error_formatter,
    )
    status = dict(download)
    status["ok"] = bool(upload.get("ok")) and bool(download.get("ok"))
    status["detail"] = (
        f"upload={upload.get('detail')} | download={download.get('detail')}"
    )
    status["components"] = {
        "upload_av_icap": upload,
        "download_av_icap": download,
    }
    return status


def check_clamd_health(
    *,
    host: str | None = None,
    port: int | None = None,
    timeout: float = 0.8,
    error_formatter: ErrorFormatter | None = None,
) -> dict[str, Any]:
    return _call_resolved_clamd_target(
        check_clamd,
        host=host,
        port=port,
        timeout=timeout,
        error_formatter=error_formatter,
        annotate=True,
    )


def send_sample_av_icap(
    *,
    host: str | None = None,
    port: int | None = None,
    timeout: float = 1.2,
    error_formatter: ErrorFormatter | None = None,
) -> dict[str, Any]:
    if port is not None or not _clamd_host_is_remote(os.environ.get("CLAMD_HOST")):
        resolved_host, resolved_port = _resolve_host_port_override(
            host=host,
            port=port,
            host_env="CICAP_HOST",
            port_env="CICAP_AV_PORT",
            default_port=14001,
        )
    else:
        resolved_host = (
            host or os.environ.get("CICAP_HOST") or "127.0.0.1"
        ).strip() or "127.0.0.1"
        workers = _clamp_icap_workers(
            os.environ.get("SQUID_WORKERS") or os.environ.get("WORKERS") or "1"
        )
        resolved_port = _clamav_respmod_stream_port_base(workers)
    result = send_sample_respmod_to(
        host=resolved_host,
        port=resolved_port,
        service="/avrespmod",
        timeout=timeout,
        error_formatter=error_formatter,
    )
    if str(result.get("detail") or "").startswith(
        "ICAP/1.0 500 Service Unavailable",
    ):
        result = {
            **result,
            "detail": "Connection refused by ClamAV backend: "
            f"{result.get('detail')}",
        }
    return annotate_service_target(
        result,
        host=resolved_host,
        port=resolved_port,
        service="/avrespmod",
    )


def test_eicar(
    *,
    host: str | None = None,
    port: int | None = None,
    timeout: float = 2.0,
    error_formatter: ErrorFormatter | None = None,
) -> dict[str, Any]:
    return _call_resolved_clamd_target(
        test_clamd_eicar,
        host=host,
        port=port,
        timeout=timeout,
        error_formatter=error_formatter,
        annotate=True,
    )


def build_local_clamav_view(
    *,
    error_formatter: ErrorFormatter | None = None,
    icap_timeout: float = 0.8,
    clamd_timeout: float = 0.8,
) -> dict[str, dict[str, Any]]:
    clamd_health = check_clamd_health(
        timeout=clamd_timeout,
        error_formatter=error_formatter,
    )
    av_icap_health = check_av_icap_health(
        timeout=icap_timeout,
        error_formatter=error_formatter,
    )
    return {
        "health": build_clamav_health(clamd_health, av_icap_health),
        "clamd_health": clamd_health,
        "av_icap_health": av_icap_health,
    }


def _normalize_av_icap_health(result: Any) -> dict[str, Any]:
    normalized = normalize_service_health(result, service="/avrespmod")
    components = result.get("components") if isinstance(result, dict) else None
    if isinstance(components, dict):
        normalized_components = {
            key: normalize_service_health(value, service="/avrespmod")
            for key, value in components.items()
            if isinstance(value, dict)
        }
        if normalized_components:
            normalized["components"] = normalized_components
    return normalized


def build_remote_clamav_view(health_payload: dict[str, Any]) -> dict[str, Any]:
    services = health_payload.get("services") or {}
    aggregate = (
        services.get("clamav") if isinstance(services.get("clamav"), dict) else {}
    )
    components = aggregate.get("components") if isinstance(aggregate, dict) else {}
    clamd_health = normalize_service_health(
        services.get("clamd")
        or (components.get("clamd") if isinstance(components, dict) else None)
        or aggregate,
    )
    av_icap_health = _normalize_av_icap_health(
        services.get("av_icap")
        or (components.get("av_icap") if isinstance(components, dict) else None),
    )
    health = dict(aggregate) if isinstance(aggregate, dict) else {}
    if not health:
        health = build_clamav_health(clamd_health, av_icap_health)
    else:
        health["ok"] = bool(health.get("ok"))
        health["detail"] = str(
            health.get("detail")
            or build_clamav_health(clamd_health, av_icap_health).get("detail"),
        )
        health["components"] = {
            "clamd": clamd_health,
            "av_icap": av_icap_health,
        }
    return {
        "health": health,
        "clamd_health": clamd_health,
        "av_icap_health": av_icap_health,
        "health_source": _remote_health_source(health_payload),
    }


def build_local_runtime_services(
    *,
    error_formatter: ErrorFormatter | None = None,
    icap_timeout: float = 0.8,
    tcp_timeout: float = 0.75,
) -> dict[str, dict[str, Any]]:
    clamav_view = build_local_clamav_view(
        error_formatter=error_formatter,
        icap_timeout=icap_timeout,
        clamd_timeout=tcp_timeout,
    )
    forwarding = check_forwarding_path_health(
        timeout=tcp_timeout,
        av_icap_health=clamav_view["av_icap_health"],
        error_formatter=error_formatter,
    )
    return {
        "icap": check_adblock_icap_health(
            timeout=icap_timeout,
            error_formatter=error_formatter,
        ),
        "av_icap": clamav_view["av_icap_health"],
        "clamd": clamav_view["clamd_health"],
        "clamav": clamav_view["health"],
        "forwarding": forwarding,
    }
