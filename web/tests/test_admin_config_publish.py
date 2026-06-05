from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import NoReturn
from urllib.parse import parse_qs, urlsplit

import pytest


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
    def __init__(self) -> None:
        self.applied: list[str] = []

    def normalize_config_text(self, text: str) -> str:
        return text.rstrip() + "\n"

    def apply_config_text(self, text: str):
        self.applied.append(text)
        return True, "applied locally"


class _Revisions:
    def __init__(self) -> None:
        self.created: list[dict[str, object]] = []
        self.applied: list[dict[str, object]] = []
        self.active_revision_id: int | None = None
        self.active_revision = None

    def get_active_revision(self, _proxy_id):
        return self.active_revision

    def create_revision(
        self, proxy_id, config_text, *, created_by, source_kind, activate
    ):
        revision_id = len(self.created) + 17
        self.created.append(
            {
                "proxy_id": proxy_id,
                "config_text": config_text,
                "created_by": created_by,
                "source_kind": source_kind,
                "activate": activate,
                "revision_id": revision_id,
            },
        )
        revision = SimpleNamespace(revision_id=revision_id, config_sha256="abc")
        if activate:
            self.active_revision_id = revision_id
            self.active_revision = revision
        return revision

    def activate_revision(self, proxy_id, revision_id):
        self.active_revision_id = int(revision_id)
        self.active_revision = SimpleNamespace(
            revision_id=int(revision_id),
            proxy_id=proxy_id,
            config_sha256="previous-sha",
        )
        return self.active_revision

    def deactivate_revision(self, _proxy_id, revision_id) -> None:
        if self.active_revision_id == int(revision_id):
            self.active_revision_id = None
            self.active_revision = None

    def record_apply_result(
        self, proxy_id, revision_id, *, ok, detail, applied_by
    ) -> None:
        self.applied.append(
            {
                "proxy_id": proxy_id,
                "revision_id": revision_id,
                "ok": ok,
                "detail": detail,
                "applied_by": applied_by,
            },
        )


def test_publish_config_does_not_create_revision_when_proxy_validation_fails(
    monkeypatch, tmp_path
) -> None:
    admin_app = _load_admin_app(monkeypatch, tmp_path)
    controller = _Controller()
    revisions = _Revisions()

    monkeypatch.setattr(admin_app, "squid_controller", controller)
    monkeypatch.setattr(admin_app, "get_proxy_id", lambda: "edge-a")
    monkeypatch.setattr(admin_app, "get_config_revisions", lambda: revisions)
    monkeypatch.setattr(
        admin_app,
        "_validate_config_for_current_mode",
        lambda _text: (False, "proxy parser rejected it"),
    )

    with admin_app.app.test_request_context("/"):
        admin_app.session["user"] = "admin"
        ok, detail = admin_app._publish_config_for_current_mode(
            "workers 1", source_kind="manual"
        )

    assert ok is False
    assert "revision was not activated" in detail
    assert "proxy parser rejected it" in detail
    assert revisions.created == []
    assert controller.applied == []


def test_publish_config_saves_revision_but_reports_remote_sync_failure(
    monkeypatch, tmp_path
) -> None:
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
    monkeypatch.setattr(
        admin_app, "_validate_config_for_current_mode", lambda _text: (True, "ok")
    )
    monkeypatch.setattr(admin_app, "_uses_remote_proxy_runtime", lambda: True)
    monkeypatch.setattr(
        admin_app, "request_proxy_reconcile", fake_request_proxy_reconcile
    )

    with admin_app.app.test_request_context("/"):
        admin_app.session["user"] = "operator"
        ok, detail = admin_app._publish_config_for_current_mode(
            "workers 1", source_kind="manual"
        )

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
            "revision_id": 17,
        },
    ]
    assert controller.applied == []


def test_publish_config_queues_operation_without_local_apply_fallback(
    monkeypatch, tmp_path
) -> None:
    admin_app = _load_admin_app(monkeypatch, tmp_path)
    controller = _Controller()
    revisions = _Revisions()
    queued: list[dict[str, object]] = []

    def fake_request_proxy_reconcile(proxy_id, **kwargs):
        queued.append({"proxy_id": proxy_id, **kwargs})
        return SimpleNamespace(operation_id=77)

    monkeypatch.setattr(admin_app, "squid_controller", controller)
    monkeypatch.setattr(admin_app, "get_proxy_id", lambda: "edge-local")
    monkeypatch.setattr(admin_app, "get_config_revisions", lambda: revisions)
    monkeypatch.setattr(
        admin_app, "_validate_config_for_current_mode", lambda _text: (True, "ok")
    )
    monkeypatch.setattr(admin_app, "_uses_remote_proxy_runtime", lambda: False)
    monkeypatch.setattr(admin_app.shutil, "which", lambda _name: "squid")
    monkeypatch.setattr(
        admin_app, "request_proxy_reconcile", fake_request_proxy_reconcile
    )

    with admin_app.app.test_request_context("/"):
        admin_app.session["user"] = "operator"
        ok, detail = admin_app._publish_config_for_current_mode(
            "workers 1", source_kind="manual"
        )

    assert ok is True
    assert "operation #77" in detail
    assert controller.applied == []
    assert revisions.applied == []
    assert queued[0]["operation_type"] == "config_apply"
    assert queued[0]["proxy_id"] == "edge-local"


def test_publish_config_restores_previous_revision_when_reconcile_not_queued(
    monkeypatch,
    tmp_path,
) -> None:
    admin_app = _load_admin_app(monkeypatch, tmp_path)
    controller = _Controller()
    revisions = _Revisions()
    revisions.active_revision = SimpleNamespace(revision_id=3, config_sha256="old-sha")
    revisions.active_revision_id = 3

    def fake_request_proxy_reconcile(_proxy_id, **_kwargs):
        return SimpleNamespace(
            operation_id=0,
            status="failed",
            detail="operation ledger unavailable",
        )

    monkeypatch.setattr(admin_app, "squid_controller", controller)
    monkeypatch.setattr(admin_app, "get_proxy_id", lambda: "edge-a")
    monkeypatch.setattr(admin_app, "get_config_revisions", lambda: revisions)
    monkeypatch.setattr(
        admin_app, "_validate_config_for_current_mode", lambda _text: (True, "ok")
    )
    monkeypatch.setattr(
        admin_app, "request_proxy_reconcile", fake_request_proxy_reconcile
    )

    with admin_app.app.test_request_context("/"):
        admin_app.session["user"] = "operator"
        ok, detail = admin_app._publish_config_for_current_mode(
            "workers 2", source_kind="manual"
        )

    assert ok is False
    assert "operation ledger unavailable" in detail
    assert "Previous active revision was restored" in detail
    assert revisions.created[-1]["activate"] is True
    assert revisions.created[-1]["revision_id"] == 17
    assert revisions.active_revision_id == 3
    assert controller.applied == []


def test_validate_config_requires_proxy_or_local_squid_runtime(
    monkeypatch, tmp_path
) -> None:
    admin_app = _load_admin_app(monkeypatch, tmp_path)

    monkeypatch.setattr(admin_app, "get_proxy_id", lambda: "edge-a")
    monkeypatch.setattr(admin_app, "_active_proxy_management_url", lambda: "")
    monkeypatch.setattr(admin_app.shutil, "which", lambda _name: None)

    ok, detail = admin_app._validate_config_for_current_mode("workers 1\n")

    assert ok is False
    assert "not registered with a management URL" in detail
    assert "does not include a local Squid runtime" in detail


def test_validate_config_uses_selected_proxy_management_api(
    monkeypatch, tmp_path
) -> None:
    admin_app = _load_admin_app(monkeypatch, tmp_path)
    captured: dict[str, str] = {}

    class Client:
        def validate_config(self, proxy_id, config_text):
            captured["proxy_id"] = proxy_id
            captured["config_text"] = config_text
            return {"ok": True, "detail": "valid on proxy"}

    monkeypatch.setattr(admin_app, "get_proxy_id", lambda: "edge-a")
    monkeypatch.setattr(
        admin_app, "_active_proxy_management_url", lambda: "http://proxy:5000"
    )
    monkeypatch.setattr(admin_app, "get_proxy_client", Client)

    ok, detail = admin_app._validate_config_for_current_mode("workers 1\n")

    assert ok is True
    assert detail == "valid on proxy"
    assert captured == {"proxy_id": "edge-a", "config_text": "workers 1\n"}


class _AdminStore:
    def __init__(self, users) -> None:
        self.users = list(users)
        self.deleted: list[str] = []

    def list_users(self):
        return list(self.users)

    def add_user(self, username, password) -> NoReturn:
        msg = "add_user should not be called"
        raise AssertionError(msg)

    def set_password(self, username, new_password) -> NoReturn:
        msg = "set_password should not be called"
        raise AssertionError(msg)

    def delete_user(self, username) -> None:
        self.deleted.append(username)


class _ValidationAdminStore(_AdminStore):
    def add_user(self, username, password) -> NoReturn:
        msg = "Password is required."
        raise ValueError(msg)


def _message_from_redirect(location: str) -> str:
    return (parse_qs(urlsplit(location).query).get("msg") or [""])[0]


def test_administration_handler_rejects_current_user_and_last_user_deletion(
    monkeypatch, tmp_path
) -> None:
    admin_app = _load_admin_app(monkeypatch, tmp_path)

    with admin_app.app.test_request_context(
        "/administration",
        method="POST",
        data={"action": "delete_user", "username": "Admin"},
    ):
        response = admin_app._handle_administration_post(
            _AdminStore(["Admin", "other"]), "admin"
        )
        assert (
            _message_from_redirect(response.location)
            == "Cannot remove the currently signed-in user."
        )

    one_user_store = _AdminStore(["admin"])
    with admin_app.app.test_request_context(
        "/administration",
        method="POST",
        data={"action": "delete_user", "username": "other"},
    ):
        response = admin_app._handle_administration_post(one_user_store, "admin")
        assert (
            _message_from_redirect(response.location) == "Cannot remove the last user."
        )
        assert one_user_store.deleted == []


def test_administration_handler_allows_other_user_deletion_and_rejects_unknown_action(
    monkeypatch, tmp_path
) -> None:
    admin_app = _load_admin_app(monkeypatch, tmp_path)
    store = _AdminStore(["admin", "operator"])

    with admin_app.app.test_request_context(
        "/administration",
        method="POST",
        data={"action": "delete_user", "username": "operator"},
    ):
        response = admin_app._handle_administration_post(store, "admin")
        assert _message_from_redirect(response.location) == "User removed."
        assert store.deleted == ["operator"]

    with admin_app.app.test_request_context(
        "/administration", method="POST", data={"action": "definitely_unknown"}
    ):
        response = admin_app._handle_administration_post(store, "admin")
        assert _message_from_redirect(response.location) == "Unknown action."


def test_administration_handler_validation_error_does_not_log_exception(
    monkeypatch, tmp_path, caplog
) -> None:
    admin_app = _load_admin_app(monkeypatch, tmp_path)

    with admin_app.app.test_request_context(
        "/administration",
        method="POST",
        data={"action": "add_user", "username": "operator", "password": ""},
    ):
        response = admin_app._handle_administration_post(
            _ValidationAdminStore(["admin"]), "admin"
        )

    assert _message_from_redirect(response.location) == "Password is required."
    assert "Administration action failed" not in caplog.text


def test_operations_api_returns_ledger_entries(monkeypatch, tmp_path) -> None:
    admin_app = _load_admin_app(monkeypatch, tmp_path)

    class Op:
        operation_id = 7
        status = "pending"
        updated_ts = 123

        def to_dict(self):
            return {
                "operation_id": self.operation_id,
                "status": self.status,
                "updated_ts": self.updated_ts,
            }

    class Ledger:
        def list_operations(self, proxy_id, *, limit):
            assert proxy_id == "edge-a"
            assert limit == 100
            return [Op()]

        def counts_by_status(self, proxy_id):
            assert proxy_id == "edge-a"
            return {"pending": 1, "applying": 0, "applied": 0, "failed": 0}

    monkeypatch.setattr(admin_app, "get_proxy_id", lambda: "edge-a")
    monkeypatch.setattr(admin_app, "get_operation_ledger", Ledger)

    with admin_app.app.test_request_context("/api/operations"):
        response, status = admin_app.api_operations()

    assert status == 200
    data = response.get_json()
    assert data["ok"] is True
    assert data["proxy_id"] == "edge-a"
    assert data["operations"] == [
        {"operation_id": 7, "status": "pending", "updated_ts": 123}
    ]
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

        def create_revision(
            self, proxy_id, config_text, *, created_by, source_kind, activate
        ):
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
    monkeypatch.setattr(admin_app, "get_operation_ledger", Ledger)
    monkeypatch.setattr(admin_app, "get_config_revisions", Revisions)
    monkeypatch.setattr(
        admin_app, "request_proxy_reconcile", fake_request_proxy_reconcile
    )

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
        },
    ]


@pytest.mark.parametrize("queue_failure", ["raises", "failed_operation"])
def test_revert_operation_restores_active_revision_when_queue_fails(
    monkeypatch, tmp_path, queue_failure
) -> None:
    admin_app = _load_admin_app(monkeypatch, tmp_path)

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
        def __init__(self) -> None:
            self.active_revision_id = 4
            self.created: list[int] = []

        def get_active_revision(self, _proxy_id):
            return SimpleNamespace(revision_id=self.active_revision_id)

        def get_revision(self, revision_id, *, proxy_id=None):
            assert revision_id == "3"
            assert proxy_id == "edge-a"
            return SimpleNamespace(revision_id=3, config_text="workers 1\n")

        def create_revision(
            self, _proxy_id, _config_text, *, created_by, source_kind, activate
        ):
            assert created_by == "operator"
            assert source_kind == "revert-config_apply"
            assert activate is True
            self.active_revision_id = 12
            self.created.append(12)
            return SimpleNamespace(revision_id=12, config_sha256="abc")

        def activate_revision(self, _proxy_id, revision_id):
            self.active_revision_id = int(revision_id)

        def deactivate_revision(self, _proxy_id, revision_id):
            if self.active_revision_id == int(revision_id):
                self.active_revision_id = None

    revisions = Revisions()

    def fail_reconcile(*_args, **_kwargs):
        if queue_failure == "raises":
            msg = "operation ledger unavailable"
            raise RuntimeError(msg)
        return SimpleNamespace(
            operation_id=0,
            status="failed",
            detail="operation ledger unavailable",
        )

    monkeypatch.setattr(admin_app, "get_proxy_id", lambda: "edge-a")
    monkeypatch.setattr(admin_app, "get_operation_ledger", Ledger)
    monkeypatch.setattr(admin_app, "get_config_revisions", lambda: revisions)
    monkeypatch.setattr(admin_app, "request_proxy_reconcile", fail_reconcile)

    with admin_app.app.test_request_context("/operations/9/revert", method="POST"):
        admin_app.session["user"] = "operator"
        response = admin_app.revert_operation(9)

    assert response.status_code == 302
    assert "error=revert_failed" in response.location
    assert revisions.created == [12]
    assert revisions.active_revision_id == 4
