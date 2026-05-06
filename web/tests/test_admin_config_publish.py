from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import SimpleNamespace


def _add_web_path() -> None:
    web_root = Path(__file__).resolve().parents[1]
    if str(web_root) not in sys.path:
        sys.path.insert(0, str(web_root))


def _load_admin_app(monkeypatch, tmp_path):
    _add_web_path()
    monkeypatch.setenv("DISABLE_BACKGROUND", "1")
    monkeypatch.setenv("FLASK_SECRET_PATH", str(tmp_path / "flask_secret.key"))
    sys.modules.pop("app", None)
    import app as admin_app  # type: ignore

    return importlib.reload(admin_app)


class _Controller:
    def __init__(self):
        self.applied: list[str] = []

    def normalize_config_text(self, text: str) -> str:
        return text.rstrip() + "\n"

    def apply_config_text(self, text: str):
        self.applied.append(text)
        return True, "applied locally"


class _Revisions:
    def __init__(self):
        self.created: list[dict[str, object]] = []
        self.applied: list[dict[str, object]] = []

    def create_revision(self, proxy_id, config_text, *, created_by, source_kind, activate):
        self.created.append(
            {
                "proxy_id": proxy_id,
                "config_text": config_text,
                "created_by": created_by,
                "source_kind": source_kind,
                "activate": activate,
            }
        )
        return SimpleNamespace(revision_id=17)

    def record_apply_result(self, proxy_id, revision_id, *, ok, detail, applied_by):
        self.applied.append(
            {
                "proxy_id": proxy_id,
                "revision_id": revision_id,
                "ok": ok,
                "detail": detail,
                "applied_by": applied_by,
            }
        )


def test_publish_config_does_not_create_revision_when_proxy_validation_fails(monkeypatch, tmp_path) -> None:
    admin_app = _load_admin_app(monkeypatch, tmp_path)
    controller = _Controller()
    revisions = _Revisions()

    monkeypatch.setattr(admin_app, "squid_controller", controller)
    monkeypatch.setattr(admin_app, "get_proxy_id", lambda: "edge-a")
    monkeypatch.setattr(admin_app, "get_config_revisions", lambda: revisions)
    monkeypatch.setattr(admin_app, "_validate_config_for_current_mode", lambda _text: (False, "proxy parser rejected it"))

    with admin_app.app.test_request_context("/"):
        admin_app.session["user"] = "admin"
        ok, detail = admin_app._publish_config_for_current_mode("workers 1", source_kind="manual")

    assert ok is False
    assert "revision was not activated" in detail
    assert "proxy parser rejected it" in detail
    assert revisions.created == []
    assert controller.applied == []


def test_publish_config_saves_revision_but_reports_remote_sync_failure(monkeypatch, tmp_path) -> None:
    admin_app = _load_admin_app(monkeypatch, tmp_path)
    controller = _Controller()
    revisions = _Revisions()

    class Client:
        def sync_proxy(self, proxy_id, *, force=False):
            assert proxy_id == "edge-a"
            assert force is True
            raise admin_app.ProxyClientError("proxy unavailable")

    monkeypatch.setattr(admin_app, "squid_controller", controller)
    monkeypatch.setattr(admin_app, "get_proxy_id", lambda: "edge-a")
    monkeypatch.setattr(admin_app, "get_config_revisions", lambda: revisions)
    monkeypatch.setattr(admin_app, "_validate_config_for_current_mode", lambda _text: (True, "ok"))
    monkeypatch.setattr(admin_app, "_uses_remote_proxy_runtime", lambda: True)
    monkeypatch.setattr(admin_app, "get_proxy_client", lambda: Client())

    with admin_app.app.test_request_context("/"):
        admin_app.session["user"] = "operator"
        ok, detail = admin_app._publish_config_for_current_mode("workers 1", source_kind="manual")

    assert ok is False
    assert "Revision 17 saved" in detail
    assert "proxy unavailable" in detail
    assert revisions.created == [
        {
            "proxy_id": "edge-a",
            "config_text": "workers 1\n",
            "created_by": "operator",
            "source_kind": "manual",
            "activate": True,
        }
    ]
    assert controller.applied == []


def test_validate_config_requires_proxy_or_local_squid_runtime(monkeypatch, tmp_path) -> None:
    admin_app = _load_admin_app(monkeypatch, tmp_path)

    monkeypatch.setattr(admin_app, "get_proxy_id", lambda: "edge-a")
    monkeypatch.setattr(admin_app, "_active_proxy_management_url", lambda: "")
    monkeypatch.setattr(admin_app.shutil, "which", lambda _name: None)

    ok, detail = admin_app._validate_config_for_current_mode("workers 1\n")

    assert ok is False
    assert "not registered with a management URL" in detail
    assert "does not include a local Squid runtime" in detail


def test_validate_config_uses_selected_proxy_management_api(monkeypatch, tmp_path) -> None:
    admin_app = _load_admin_app(monkeypatch, tmp_path)
    captured: dict[str, str] = {}

    class Client:
        def validate_config(self, proxy_id, config_text):
            captured["proxy_id"] = proxy_id
            captured["config_text"] = config_text
            return {"ok": True, "detail": "valid on proxy"}

    monkeypatch.setattr(admin_app, "get_proxy_id", lambda: "edge-a")
    monkeypatch.setattr(admin_app, "_active_proxy_management_url", lambda: "http://proxy:5000")
    monkeypatch.setattr(admin_app, "get_proxy_client", lambda: Client())

    ok, detail = admin_app._validate_config_for_current_mode("workers 1\n")

    assert ok is True
    assert detail == "valid on proxy"
    assert captured == {"proxy_id": "edge-a", "config_text": "workers 1\n"}
