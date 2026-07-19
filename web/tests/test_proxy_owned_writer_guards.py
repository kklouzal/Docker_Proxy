from __future__ import annotations

import contextlib
import importlib
import sys
from pathlib import Path
from types import SimpleNamespace


def _add_web_to_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


class _Result:
    lastrowid = 17
    rowcount = 1

    def __init__(self, row=None):
        self._row = row

    def fetchone(self):
        return self._row

    def fetchall(self):
        return []


class _Conn:
    def __init__(self):
        self.calls: list[tuple[str, tuple[object, ...]]] = []

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql, params=()):
        text = " ".join(str(sql).split())
        params_t = tuple(params or ())
        self.calls.append((text, params_t))
        if "INSERT INTO policy_requests" in text:
            return _Result()
        if "FROM policy_requests WHERE id=%s" in text:
            return _Result(
                {
                    "id": 17,
                    "proxy_id": "edge-new",
                    "status": "pending",
                    "block_type": "webfilter",
                    "client_ip": "192.0.2.10",
                    "request_url": "https://example.com/path",
                    "domain": "example.com",
                    "category": "",
                    "method": "GET",
                    "squid_error": "",
                    "user_note": "",
                    "admin_note": "",
                    "created_ts": 100,
                    "updated_ts": 100,
                    "reviewed_ts": 0,
                    "reviewer": "",
                    "exception_id": None,
                },
            )
        return _Result()


@contextlib.contextmanager
def _fake_guard(_conn, proxy_id, **_kwargs):
    yield SimpleNamespace(
        requested_proxy_id=str(proxy_id),
        proxy_id="edge-new",
        resolved_alias=str(proxy_id) != "edge-new",
    )


def test_policy_request_create_uses_guard_canonical_proxy(monkeypatch) -> None:
    _add_web_to_path()
    from services import policy_requests  # type: ignore

    module = importlib.reload(policy_requests)
    conn = _Conn()
    monkeypatch.setattr(module, "guarded_proxy_write", _fake_guard)

    store = module.PolicyRequestStore()
    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "_connect", lambda: conn)

    created = store.create_request(
        proxy_id="edge-old",
        client_ip="192.0.2.10",
        request_url="https://example.com/path",
        domain="example.com",
    )

    insert = next(call for call in conn.calls if "INSERT INTO policy_requests" in call[0])
    assert insert[1][0] == "edge-new"
    assert created.proxy_id == "edge-new"


def test_observability_schedule_uses_guard_canonical_proxy(monkeypatch) -> None:
    _add_web_to_path()
    from services import observability_queries  # type: ignore

    module = importlib.reload(observability_queries)
    conn = _Conn()
    monkeypatch.setattr(module, "guarded_proxy_write", _fake_guard)
    monkeypatch.setattr(module, "get_proxy_id", lambda: "edge-old")

    queries = module.ObservabilityQueries()
    monkeypatch.setattr(queries, "_connect", lambda: conn)
    monkeypatch.setattr(queries, "report_schedules", lambda limit=1: [SimpleNamespace(id=1)])

    monkeypatch.setattr(queries, "_ensure_report_schedule_db", lambda: None)
    queries.save_report_schedule(name="Daily", cadence="daily", recipients="ops@example.com")

    insert = next(call for call in conn.calls if "INSERT INTO observability_report_schedules" in call[0])
    assert insert[1][0] == "edge-new"


def test_webfilter_scoped_setting_uses_guard_but_global_setting_does_not(monkeypatch) -> None:
    _add_web_to_path()
    from services import webfilter_core  # type: ignore

    module = importlib.reload(webfilter_core)
    conn = _Conn()
    guarded: list[str] = []

    @contextlib.contextmanager
    def guard(conn_obj, proxy_id, **kwargs):
        guarded.append(str(proxy_id))
        yield SimpleNamespace(proxy_id="edge-new")

    monkeypatch.setattr(module, "guarded_proxy_write", guard)
    monkeypatch.setattr(module, "get_proxy_id", lambda: "edge-old")

    store = module.WebFilterStoreBase()
    store._set(conn, "enabled", "1")
    store._set(conn, "source_url", "https://example.test/list")

    assert guarded == ["edge-old"]
    scoped, global_call = conn.calls[-2:]
    assert scoped[1][0] == "edge-new"
    assert global_call[1][0] == module._GLOBAL_SCOPE
