from __future__ import annotations

import os
from typing import Any

from services.health_checks import ErrorFormatter, annotate_service_target, build_clamav_health, check_clamd, check_icap_service, check_local_listener, check_tcp, is_local_host, resolve_host_port, send_sample_respmod_to, test_clamd_eicar


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
        return resolve_host_port(host_env=host_env, port_env=port_env, default_host=default_host, default_port=default_port)

    resolved_host = (host or os.environ.get(host_env) or default_host).strip() or default_host
    try:
        resolved_port = int(port if port is not None else (os.environ.get(port_env) or default_port))
    except Exception:
        resolved_port = int(default_port)
    return resolved_host, resolved_port


def unavailable_service(detail: str, *, target: str = "unavailable", service: str = "") -> dict[str, Any]:
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


def normalize_service_health(result: Any, *, default_target: str = "unavailable", service: str = "") -> dict[str, Any]:
    if not isinstance(result, dict):
        return unavailable_service("unavailable", target=default_target, service=service)
    detail = str(result.get("detail") or "unavailable")
    host = str(result.get("host") or "")
    try:
        port = int(result.get("port") or 0)
    except Exception:
        port = 0
    target = str(result.get("target") or (f"{host}:{port}" if host and port else default_target))
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


def build_unavailable_runtime_health(detail: str, *, proxy_status: str = "offline") -> dict[str, Any]:
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


def _check_icap_target(
    service_name: str,
    icap_service: str,
    *,
    host: str,
    port: int,
    timeout: float,
    error_formatter: ErrorFormatter | None,
    user_agent: str = "squid-flask-proxy-ui",
    success_detail: str | None = None,
) -> dict[str, Any]:
    result = (
        check_local_listener(service_name, host, port)
        if is_local_host(host)
        else check_icap_service(
            host=host,
            port=port,
            service=icap_service,
            timeout=timeout,
            user_agent=user_agent,
            success_detail=success_detail,
            error_formatter=error_formatter,
        )
    )
    return annotate_service_target(result, host=host, port=port, service=icap_service)


def check_adblock_icap_health(
    *,
    host: str | None = None,
    port: int | None = None,
    timeout: float = 0.8,
    error_formatter: ErrorFormatter | None = None,
) -> dict[str, Any]:
    resolved_host, resolved_port = _resolve_host_port_override(
        host=host,
        port=port,
        host_env="CICAP_HOST",
        port_env="CICAP_PORT",
        default_port=14000,
    )
    return _check_icap_target(
        "c-icap",
        "/adblockreq",
        host=resolved_host,
        port=resolved_port,
        timeout=timeout,
        error_formatter=error_formatter,
    )


def check_av_icap_health(
    *,
    host: str | None = None,
    port: int | None = None,
    timeout: float = 0.8,
    error_formatter: ErrorFormatter | None = None,
) -> dict[str, Any]:
    resolved_host, resolved_port = _resolve_host_port_override(
        host=host,
        port=port,
        host_env="CICAP_HOST",
        port_env="CICAP_AV_PORT",
        default_port=14001,
    )
    return _check_icap_target(
        "c-icap av",
        "/avrespmod",
        host=resolved_host,
        port=resolved_port,
        timeout=timeout,
        error_formatter=error_formatter,
    )


def check_clamd_health(
    *,
    host: str | None = None,
    port: int | None = None,
    timeout: float = 0.8,
    error_formatter: ErrorFormatter | None = None,
) -> dict[str, Any]:
    resolved_host, resolved_port = _resolve_host_port_override(
        host=host,
        port=port,
        host_env="CLAMD_HOST",
        port_env="CLAMD_PORT",
        default_port=3310,
    )
    result = check_clamd(host=resolved_host, port=resolved_port, timeout=timeout, error_formatter=error_formatter)
    return annotate_service_target(result, host=resolved_host, port=resolved_port)


def send_sample_av_icap(
    *,
    host: str | None = None,
    port: int | None = None,
    timeout: float = 1.2,
    error_formatter: ErrorFormatter | None = None,
) -> dict[str, Any]:
    resolved_host, resolved_port = _resolve_host_port_override(
        host=host,
        port=port,
        host_env="CICAP_HOST",
        port_env="CICAP_AV_PORT",
        default_port=14001,
    )
    return send_sample_respmod_to(
        host=resolved_host,
        port=resolved_port,
        service="/avrespmod",
        timeout=timeout,
        error_formatter=error_formatter,
    )


def test_eicar(
    *,
    host: str | None = None,
    port: int | None = None,
    timeout: float = 2.0,
    error_formatter: ErrorFormatter | None = None,
) -> dict[str, Any]:
    resolved_host, resolved_port = _resolve_host_port_override(
        host=host,
        port=port,
        host_env="CLAMD_HOST",
        port_env="CLAMD_PORT",
        default_port=3310,
    )
    return test_clamd_eicar(
        host=resolved_host,
        port=resolved_port,
        timeout=timeout,
        error_formatter=error_formatter,
    )


def build_local_clamav_view(
    *,
    error_formatter: ErrorFormatter | None = None,
    icap_timeout: float = 0.8,
    clamd_timeout: float = 0.8,
) -> dict[str, dict[str, Any]]:
    clamd_health = check_clamd_health(timeout=clamd_timeout, error_formatter=error_formatter)
    av_icap_health = check_av_icap_health(timeout=icap_timeout, error_formatter=error_formatter)
    return {
        "health": build_clamav_health(clamd_health, av_icap_health),
        "clamd_health": clamd_health,
        "av_icap_health": av_icap_health,
    }


def build_remote_clamav_view(health_payload: dict[str, Any]) -> dict[str, Any]:
    services = health_payload.get("services") or {}
    aggregate = services.get("clamav") if isinstance(services.get("clamav"), dict) else {}
    components = aggregate.get("components") if isinstance(aggregate, dict) else {}
    clamd_health = normalize_service_health(
        services.get("clamd") or (components.get("clamd") if isinstance(components, dict) else None) or aggregate,
    )
    av_icap_health = normalize_service_health(
        services.get("av_icap") or (components.get("av_icap") if isinstance(components, dict) else None),
        service="/avrespmod",
    )
    health = dict(aggregate) if isinstance(aggregate, dict) else {}
    if not health:
        health = build_clamav_health(clamd_health, av_icap_health)
    else:
        health["ok"] = bool(health.get("ok"))
        health["detail"] = str(health.get("detail") or build_clamav_health(clamd_health, av_icap_health).get("detail"))
        health["components"] = {
            "clamd": clamd_health,
            "av_icap": av_icap_health,
        }
    return {
        "health": health,
        "clamd_health": clamd_health,
        "av_icap_health": av_icap_health,
        "health_source": str(health_payload.get("proxy_status") or health_payload.get("detail") or ""),
    }


def build_local_runtime_services(
    *,
    error_formatter: ErrorFormatter | None = None,
    icap_timeout: float = 0.8,
    tcp_timeout: float = 0.75,
) -> dict[str, dict[str, Any]]:
    clamav_view = build_local_clamav_view(error_formatter=error_formatter, icap_timeout=icap_timeout, clamd_timeout=icap_timeout)
    return {
        "icap": check_adblock_icap_health(timeout=icap_timeout, error_formatter=error_formatter),
        "av_icap": clamav_view["av_icap_health"],
        "clamd": clamav_view["clamd_health"],
        "clamav": clamav_view["health"],
    }
