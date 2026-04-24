"""Compatibility shim for proxy/runtime imports.

The canonical proxy-safe web filter store lives in `services.webfilter_core`.
Keep this module as a thin re-export layer for callers that still import the
older proxy-specific module path.
"""

from services.webfilter_core import ProxyWebFilterStore, WebFilterMaterializedState, WebFilterSettings, get_proxy_webfilter_store

__all__ = [
    "ProxyWebFilterStore",
    "WebFilterMaterializedState",
    "WebFilterSettings",
    "get_proxy_webfilter_store",
]
