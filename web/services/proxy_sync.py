from __future__ import annotations

from services.proxy_registry import get_proxy_registry

try:
    from services.proxy_client import ProxyClientError, get_proxy_client
except Exception:
    class ProxyClientError(RuntimeError):
        """Fallback error used when the admin-only proxy client is unavailable."""

    def get_proxy_client():
        raise RuntimeError("Proxy client is unavailable in this runtime image")


def nudge_registered_proxies(*, force: bool = False) -> tuple[int, int]:
    proxies = get_proxy_registry().list_proxies()
    if not proxies:
        return 0, 0

    try:
        client = get_proxy_client()
    except Exception:
        return len(proxies), 0

    ok_count = 0
    for proxy in proxies:
        try:
            result = client.sync_proxy(proxy.proxy_id, force=force)
        except ProxyClientError:
            continue
        if bool(result.get("ok", False)):
            ok_count += 1
    return len(proxies), ok_count