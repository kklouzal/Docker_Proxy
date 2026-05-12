from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit


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

    class Op:
        operation_id = 42

    def fake_request_proxy_reconcile(proxy_id, **kwargs):
        assert proxy_id == "edge-a"
        assert kwargs["operation_type"] == "config_apply"
        assert kwargs["target_kind"] == "config_revision"
        assert kwargs["target_ref"] == 17
        return Op()

    monkeypatch.setattr(admin_app, "squid_controller", controller)
    monkeypatch.setattr(admin_app, "get_proxy_id", lambda: "edge-a")
    monkeypatch.setattr(admin_app, "get_config_revisions", lambda: revisions)
    monkeypatch.setattr(admin_app, "_validate_config_for_current_mode", lambda _text: (True, "ok"))
    monkeypatch.setattr(admin_app, "_uses_remote_proxy_runtime", lambda: True)
    monkeypatch.setattr(admin_app, "request_proxy_reconcile", fake_request_proxy_reconcile)

    with admin_app.app.test_request_context("/"):
        admin_app.session["user"] = "operator"
        ok, detail = admin_app._publish_config_for_current_mode("workers 1", source_kind="manual")

    assert ok is True
    assert "Revision 17 saved" in detail
    assert "operation #42" in detail
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


class _AdminStore:
    def __init__(self, users):
        self.users = list(users)
        self.deleted: list[str] = []

    def list_users(self):
        return list(self.users)

    def add_user(self, username, password):
        raise AssertionError("add_user should not be called")

    def set_password(self, username, new_password):
        raise AssertionError("set_password should not be called")

    def delete_user(self, username):
        self.deleted.append(username)


def _message_from_redirect(location: str) -> str:
    return (parse_qs(urlsplit(location).query).get("msg") or [""])[0]


def test_administration_handler_rejects_current_user_and_last_user_deletion(monkeypatch, tmp_path) -> None:
    admin_app = _load_admin_app(monkeypatch, tmp_path)

    with admin_app.app.test_request_context("/administration", method="POST", data={"action": "delete_user", "username": "Admin"}):
        response = admin_app._handle_administration_post(_AdminStore(["Admin", "other"]), "admin")
        assert _message_from_redirect(response.location) == "Cannot remove the currently signed-in user."

    one_user_store = _AdminStore(["admin"])
    with admin_app.app.test_request_context("/administration", method="POST", data={"action": "delete_user", "username": "other"}):
        response = admin_app._handle_administration_post(one_user_store, "admin")
        assert _message_from_redirect(response.location) == "Cannot remove the last user."
        assert one_user_store.deleted == []


def test_administration_handler_allows_other_user_deletion_and_rejects_unknown_action(monkeypatch, tmp_path) -> None:
    admin_app = _load_admin_app(monkeypatch, tmp_path)
    store = _AdminStore(["admin", "operator"])

    with admin_app.app.test_request_context("/administration", method="POST", data={"action": "delete_user", "username": "operator"}):
        response = admin_app._handle_administration_post(store, "admin")
        assert _message_from_redirect(response.location) == "User removed."
        assert store.deleted == ["operator"]

    with admin_app.app.test_request_context("/administration", method="POST", data={"action": "definitely_unknown"}):
        response = admin_app._handle_administration_post(store, "admin")
        assert _message_from_redirect(response.location) == "Unknown action."



def test_operations_api_returns_ledger_entries(monkeypatch, tmp_path) -> None:
    admin_app = _load_admin_app(monkeypatch, tmp_path)

    class Op:
        operation_id = 7
        status = "pending"
        updated_ts = 123

        def to_dict(self):
            return {"operation_id": self.operation_id, "status": self.status, "updated_ts": self.updated_ts}

    class Ledger:
        def list_operations(self, proxy_id, *, limit):
            assert proxy_id == "edge-a"
            assert limit == 100
            return [Op()]

        def counts_by_status(self, proxy_id):
            assert proxy_id == "edge-a"
            return {"pending": 1, "applying": 0, "applied": 0, "failed": 0}

    monkeypatch.setattr(admin_app, "get_proxy_id", lambda: "edge-a")
    monkeypatch.setattr(admin_app, "get_operation_ledger", lambda: Ledger())

    with admin_app.app.test_request_context("/api/operations"):
        response, status = admin_app.api_operations()

    assert status == 200
    data = response.get_json()
    assert data["ok"] is True
    assert data["proxy_id"] == "edge-a"
    assert data["operations"] == [{"operation_id": 7, "status": "pending", "updated_ts": 123}]
    assert data["counts"]["pending"] == 1


def test_revert_operation_queues_revision_revert(monkeypatch, tmp_path) -> None:
    admin_app = _load_admin_app(monkeypatch, tmp_path)
    queued: list[dict[str, object]] = []

    class Op:
        operation_id = 9
        proxy_id = "edge-a"
        can_revert = True
        rollback_kind = "config_revision"
        rollback_ref = "3"
        operation_type = "config_apply"
        target_ref = "4"

    class Ledger:
        def get_operation(self, operation_id):
            assert operation_id == 9
            return Op()

    class Revisions:
        def get_revision(self, revision_id, *, proxy_id=None):
            assert revision_id == "3"
            assert proxy_id == "edge-a"
            return SimpleNamespace(revision_id=3, config_text="workers 1\n")

        def create_revision(self, proxy_id, config_text, *, created_by, source_kind, activate):
            assert proxy_id == "edge-a"
            assert config_text == "workers 1\n"
            assert created_by == "operator"
            assert source_kind == "revert-config_apply"
            assert activate is True
            return SimpleNamespace(revision_id=12, config_sha256="abc")

    def fake_request_proxy_reconcile(proxy_id, **kwargs):
        queued.append({"proxy_id": proxy_id, **kwargs})
        return SimpleNamespace(operation_id=10)

    monkeypatch.setattr(admin_app, "get_proxy_id", lambda: "edge-a")
    monkeypatch.setattr(admin_app, "get_operation_ledger", lambda: Ledger())
    monkeypatch.setattr(admin_app, "get_config_revisions", lambda: Revisions())
    monkeypatch.setattr(admin_app, "request_proxy_reconcile", fake_request_proxy_reconcile)

    with admin_app.app.test_request_context("/operations/9/revert", method="POST"):
        admin_app.session["user"] = "operator"
        response = admin_app.revert_operation(9)

    assert response.status_code == 302
    assert "/operations" in response.location
    assert queued == [
        {
            "proxy_id": "edge-a",
            "operation_type": "revert",
            "subject": "Revert #9",
            "summary": "Restored config revision 3; applying asynchronously.",
            "target_kind": "config_revision",
            "target_ref": 12,
            "rollback_kind": "config_revision",
            "rollback_ref": "4",
            "request_hash": "abc",
            "detail": "Revert queued from failed operation #9.",
            "created_by": "operator",
            "force": False,
        }
    ]
