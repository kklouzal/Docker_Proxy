from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

from .mysql_test_utils import WEB_ROOT, configure_test_mysql_env


def ensure_web_import_path() -> None:
    web_dir = str(WEB_ROOT)
    if web_dir not in sys.path:
        sys.path.insert(0, web_dir)


def import_remote_app_module(
    *,
    secret_prefix: str = "sfp_secret_remote_",
    mysql_prefix: str = "sfp_mysql_remote_",
):
    ensure_web_import_path()

    os.environ["PROXY_CONTROL_MODE"] = "remote"
    os.environ["DISABLE_BACKGROUND"] = "1"
    os.environ["PROXY_MANAGEMENT_TOKEN"] = "test-token"
    os.environ["DEFAULT_PROXY_ID"] = "edge-1"

    secret_path = Path(tempfile.mkdtemp(prefix=secret_prefix)) / "flask_secret.key"
    configure_test_mysql_env(tempfile.mkdtemp(prefix=mysql_prefix), secret_path=secret_path)

    import app as app_module  # type: ignore

    app_module.app.testing = True
    return app_module


class FakeProxyClient:
    def __init__(
        self,
        *,
        proxy_status: str = "healthy",
        sync_detail: str = "sync requested",
        clear_detail: str = "cache clear requested",
        eicar_detail: str = "Eicar FOUND",
        icap_detail: str = "ICAP/1.0 200 OK",
    ):
        self.health_calls: list[str] = []
        self.sync_calls: list[tuple[str, bool]] = []
        self.clear_calls: list[str] = []
        self.eicar_calls: list[str] = []
        self.icap_calls: list[str] = []
        self.proxy_status = proxy_status
        self.sync_detail = sync_detail
        self.clear_detail = clear_detail
        self.eicar_detail = eicar_detail
        self.icap_detail = icap_detail

    def get_health(self, proxy_id, *, timeout_seconds=2.0):
        self.health_calls.append(str(proxy_id))
        return {
            "ok": True,
            "proxy_id": str(proxy_id),
            "proxy_status": self.proxy_status,
            "stats": {},
            "services": {
                "icap": {"ok": True, "detail": "ok", "host": "127.0.0.1", "port": 14000, "target": "127.0.0.1:14000", "service": "/adblockreq"},
                "av_icap": {"ok": True, "detail": "av ok", "host": "clamav.internal", "port": 14001, "target": "clamav.internal:14001", "service": "/avrespmod"},
                "clamd": {"ok": True, "detail": "PONG (clamav.internal:3310)", "host": "clamav.internal", "port": 3310, "target": "clamav.internal:3310"},
                "clamav": {"ok": True, "detail": "AV c-icap=av ok | clamd=PONG (clamav.internal:3310)", "components": {"av_icap": {"ok": True, "detail": "av ok", "host": "clamav.internal", "port": 14001, "target": "clamav.internal:14001", "service": "/avrespmod"}, "clamd": {"ok": True, "detail": "PONG (clamav.internal:3310)", "host": "clamav.internal", "port": 3310, "target": "clamav.internal:3310"}}},
                "dante": {"ok": True, "detail": "ok"},
            },
        }

    def sync_proxy(self, proxy_id, *, force=False, timeout_seconds=15.0):
        self.sync_calls.append((str(proxy_id), bool(force)))
        return {"ok": True, "detail": self.sync_detail}

    def clear_proxy_cache(self, proxy_id, *, timeout_seconds=60.0):
        self.clear_calls.append(str(proxy_id))
        return {"ok": True, "detail": self.clear_detail}

    def test_clamav_eicar(self, proxy_id, *, timeout_seconds=10.0):
        self.eicar_calls.append(str(proxy_id))
        return {"ok": True, "detail": self.eicar_detail}

    def test_clamav_icap(self, proxy_id, *, timeout_seconds=10.0):
        self.icap_calls.append(str(proxy_id))
        return {"ok": True, "detail": self.icap_detail}