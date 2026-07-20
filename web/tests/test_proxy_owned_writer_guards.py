from __future__ import annotations

import contextlib
import importlib
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


def _add_web_to_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


class _Result:
    lastrowid = 17

    def __init__(self, row=None, *, rowcount: int = 1):
        self._rows = row if isinstance(row, list) else ([] if row is None else [row])
        self.rowcount = rowcount

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)


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

    def executemany(self, sql, seq_of_params):
        text = " ".join(str(sql).split())
        for params in seq_of_params:
            self.calls.append((text, tuple(params or ())))
        return _Result()

    def commit(self):
        return None

    def rollback(self):
        return None


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

    insert = next(
        call for call in conn.calls if "INSERT INTO policy_requests" in call[0]
    )
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
    monkeypatch.setattr(
        queries, "report_schedules", lambda limit=1: [SimpleNamespace(id=1)]
    )

    monkeypatch.setattr(queries, "_ensure_report_schedule_db", lambda: None)
    queries.save_report_schedule(
        name="Daily", cadence="daily", recipients="ops@example.com"
    )

    insert = next(
        call
        for call in conn.calls
        if "INSERT INTO observability_report_schedules" in call[0]
    )
    assert insert[1][0] == "edge-new"


def test_policy_close_and_revoke_scoped_mutations_use_guard_canonical_proxy(
    monkeypatch,
) -> None:
    _add_web_to_path()
    from services import policy_requests  # type: ignore

    module = importlib.reload(policy_requests)
    conn = _Conn()
    monkeypatch.setattr(module, "guarded_proxy_write", _fake_guard)

    store = module.PolicyRequestStore()
    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "_connect", lambda: conn)

    store.close_request(17, reviewer="admin", proxy_id="edge-old")
    store.revoke_exception(23, revoked_by="admin", proxy_id="edge-old")

    scoped_updates = [call for call in conn.calls if " AND proxy_id=%s" in call[0]]
    assert len(scoped_updates) == 2
    assert all(call[1][-1] == "edge-new" for call in scoped_updates)


def test_policy_close_and_revoke_unscoped_mutations_do_not_guard(monkeypatch) -> None:
    _add_web_to_path()
    from services import policy_requests  # type: ignore

    module = importlib.reload(policy_requests)
    conn = _Conn()

    def fail_guard(*_args, **_kwargs):
        msg = "unscoped mutation should not use lifecycle guard"
        raise AssertionError(msg)

    monkeypatch.setattr(module, "guarded_proxy_write", fail_guard)

    store = module.PolicyRequestStore()
    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "_connect", lambda: conn)

    store.close_request(17, reviewer="admin")
    store.revoke_exception(23, revoked_by="admin")

    assert len(conn.calls) == 2
    assert all(" AND proxy_id=%s" not in call[0] for call in conn.calls)


def test_webfilter_scoped_setting_uses_guard_but_global_setting_does_not(
    monkeypatch,
) -> None:
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


def test_pac_backup_mutations_use_guard_canonical_proxy(monkeypatch) -> None:
    _add_web_to_path()
    from services import pac_profiles_store  # type: ignore

    module = importlib.reload(pac_profiles_store)
    conn = _Conn()
    monkeypatch.setattr(module, "guarded_proxy_write", _fake_guard)
    monkeypatch.setattr(module, "get_proxy_id", lambda: "edge-old")

    def fake_execute(sql, params=()):
        text = " ".join(str(sql).split())
        params_t = tuple(params or ())
        conn.calls.append((text, params_t))
        if "SELECT 1 FROM pac_backup_proxies" in text:
            return _Result({"1": 1})
        if "SELECT id FROM pac_backup_proxies" in text:
            return _Result([{"id": 21}, {"id": 22}])
        return _Result(rowcount=1)

    monkeypatch.setattr(conn, "execute", fake_execute)
    store = module.PacProfilesStore()
    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "_connect", lambda: conn)

    assert store.delete_backup_proxy(21) is True
    assert store.move_backup_proxy(22, "up") is True

    proxy_scoped_calls = [
        call
        for call in conn.calls
        if "pac_backup_proxies" in call[0] and "proxy_id=%s" in call[0]
    ]
    assert proxy_scoped_calls
    assert all(call[1][-1] == "edge-new" for call in proxy_scoped_calls)


def test_adblock_event_insert_and_batch_use_guard_canonical_proxy(monkeypatch) -> None:
    _add_web_to_path()
    from services import adblock_store  # type: ignore

    module = importlib.reload(adblock_store)
    conn = _Conn()
    monkeypatch.setattr(module, "guarded_proxy_write", _fake_guard)
    monkeypatch.setattr(module, "get_proxy_id", lambda: "edge-old")

    def fake_guarded_rows(_conn, proxy_id, rows, row_factory, **_kwargs):
        materialized = tuple(tuple(row_factory("edge-new", row)) for row in rows)
        return SimpleNamespace(
            requested_proxy_id=str(proxy_id),
            proxy_id="edge-new",
            rows=materialized,
        )

    monkeypatch.setattr(module, "guarded_proxy_rows", fake_guarded_rows)
    monkeypatch.setattr(module, "_now", lambda: 1234)
    store = module.AdblockStore(cicap_access_log_path="fake.log")
    parsed = {
        "ts": 111,
        "src_ip": "192.0.2.10",
        "method": "GET",
        "url": "https://ads.example/",
        "http_status": 403,
        "http_resp_line": "HTTP/1.1 403 Forbidden",
        "icap_status": 200,
        "raw": "raw-line",
    }

    store._insert_event(conn, parsed)
    assert conn.calls[-1][1][0] == "edge-new"

    conn.calls.clear()
    monkeypatch.setattr(store, "_get_proxy_meta", lambda *_args: "0")
    monkeypatch.setattr(store, "_set_proxy_meta_values", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(store, "_prune_events", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        module.os, "stat", lambda _path: SimpleNamespace(st_ino=7, st_size=128)
    )

    class FakePath:
        def __init__(self, _path):
            pass

        def open(self, *_args, **_kwargs):
            return self

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def seek(self, *_args):
            return None

        def read(self):
            return b"111\t192.0.2.10\t198.51.100.10\tREQMOD\t/adblockreq\t200\tGET / HTTP/1.1\thttps://ads.example/\tHTTP/1.1 403 Forbidden\n"

        def tell(self):
            return 128

    monkeypatch.setattr(module.pathlib, "Path", FakePath)

    store._ingest_new_cicap_lines(conn)

    batch_insert = next(
        call for call in conn.calls if "INSERT IGNORE INTO adblock_events" in call[0]
    )
    assert batch_insert[1][0] == "edge-new"


def test_guarded_service_writes_reject_tombstoned_proxy(monkeypatch) -> None:
    _add_web_to_path()
    from services import (  # type: ignore
        adblock_store,
        pac_profiles_store,
        policy_requests,
    )
    from services.proxy_write_guard import ProxyLifecycleWriteError

    adblock_module = importlib.reload(adblock_store)
    pac_module = importlib.reload(pac_profiles_store)
    policy_module = importlib.reload(policy_requests)

    @contextlib.contextmanager
    def reject_guard(_conn, proxy_id, **_kwargs):
        msg = f"Proxy {proxy_id!r} has been removed"
        raise ProxyLifecycleWriteError(msg)
        yield

    def reject_rows(_conn, proxy_id, *_args, **_kwargs):
        msg = f"Proxy {proxy_id!r} has been removed"
        raise ProxyLifecycleWriteError(msg)

    for module in (adblock_module, pac_module, policy_module):
        monkeypatch.setattr(module, "guarded_proxy_write", reject_guard)
    monkeypatch.setattr(adblock_module, "guarded_proxy_rows", reject_rows)
    monkeypatch.setattr(adblock_module, "get_proxy_id", lambda: "edge-removed")
    monkeypatch.setattr(pac_module, "get_proxy_id", lambda: "edge-removed")

    conn = _Conn()
    ad_store = adblock_module.AdblockStore(cicap_access_log_path="fake.log")
    pac_store = pac_module.PacProfilesStore()
    pol_store = policy_module.PolicyRequestStore()
    monkeypatch.setattr(pac_store, "init_db", lambda: None)
    monkeypatch.setattr(pac_store, "_connect", lambda: conn)
    monkeypatch.setattr(pol_store, "init_db", lambda: None)
    monkeypatch.setattr(pol_store, "_connect", lambda: conn)

    with pytest.raises(ProxyLifecycleWriteError):
        ad_store._insert_event(conn, {"url": "https://ads.example/"})

    monkeypatch.setattr(
        adblock_module.os,
        "stat",
        lambda _path: SimpleNamespace(st_ino=7, st_size=128),
    )

    class FakePath:
        def __init__(self, _path):
            pass

        def open(self, *_args, **_kwargs):
            return self

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def seek(self, *_args):
            return None

        def read(self):
            return b"111\t192.0.2.10\t198.51.100.10\tREQMOD\t/adblockreq\t200\tGET / HTTP/1.1\thttps://ads.example/\tHTTP/1.1 403 Forbidden\n"

        def tell(self):
            return 128

    monkeypatch.setattr(adblock_module.pathlib, "Path", FakePath)
    monkeypatch.setattr(ad_store, "_get_proxy_meta", lambda *_args: "0")

    with pytest.raises(ProxyLifecycleWriteError):
        ad_store._ingest_new_cicap_lines(conn)
    with pytest.raises(ProxyLifecycleWriteError):
        pac_store.delete_backup_proxy(21)
    with pytest.raises(ProxyLifecycleWriteError):
        pac_store.move_backup_proxy(21, "up")
    with pytest.raises(ProxyLifecycleWriteError):
        pol_store.close_request(17, proxy_id="edge-removed")
    with pytest.raises(ProxyLifecycleWriteError):
        pol_store.revoke_exception(23, proxy_id="edge-removed")
