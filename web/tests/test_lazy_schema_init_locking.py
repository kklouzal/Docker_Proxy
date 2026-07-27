from __future__ import annotations

import sys
import threading
from pathlib import Path
from types import SimpleNamespace


def _add_web_to_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


_add_web_to_path()
from services import (  # type: ignore  # noqa: E402
    adblock_artifacts,  # type: ignore
    certificate_bundles,  # type: ignore
    config_revisions,  # type: ignore
    schema_lifecycle,  # type: ignore
)


class _InitConn:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql, params=None):
        self.calls.append(str(sql))
        return SimpleNamespace(fetchone=lambda: None, fetchall=list, rowcount=0)


class _TrackingLock:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._attempts = 0
        self.second_acquire_attempted = threading.Event()

    def __enter__(self):
        self._attempts += 1
        if self._attempts == 2:
            self.second_acquire_attempted.set()
        self._lock.acquire()
        return self

    def __exit__(self, *_exc):
        self._lock.release()
        return False


def _assert_concurrent_init_is_serialized(monkeypatch, module, store) -> None:
    first_readiness_entered = threading.Event()
    release_first_readiness = threading.Event()
    second_readiness_entered = threading.Event()
    schema_lock = _TrackingLock()
    calls: list[str] = []
    errors: list[BaseException] = []
    readiness_calls = {"count": 0}

    def fake_connect():
        return _InitConn(calls)

    def fake_runtime_schema_ready(_conn) -> bool:
        readiness_calls["count"] += 1
        if readiness_calls["count"] == 1:
            first_readiness_entered.set()
            assert release_first_readiness.wait(timeout=2), "timed out releasing init"
        else:
            second_readiness_entered.set()
        return False

    def run_init() -> None:
        try:
            store.init_db()
        except BaseException as exc:  # pragma: no cover - assertion reports thread errors
            errors.append(exc)

    monkeypatch.setattr(store, "_connect", fake_connect)
    monkeypatch.setattr(store, "_schema_lock", schema_lock)
    monkeypatch.setattr(
        schema_lifecycle,
        "runtime_schema_ready_for_lazy_store",
        fake_runtime_schema_ready,
    )
    monkeypatch.setattr(module, "ensure_generated_column", lambda *args, **kwargs: None)
    monkeypatch.setattr(module, "ensure_index", lambda *args, **kwargs: None)
    monkeypatch.setattr(module, "repair_duplicate_active_rows", lambda *args, **kwargs: None)

    first = threading.Thread(target=run_init)
    first.start()
    assert first_readiness_entered.wait(timeout=2), "first init did not enter readiness"

    second = threading.Thread(target=run_init)
    second.start()

    assert schema_lock.second_acquire_attempted.wait(timeout=2)
    assert not second_readiness_entered.wait(timeout=0.1)
    assert readiness_calls["count"] == 1

    release_first_readiness.set()
    first.join(timeout=2)
    second.join(timeout=2)

    assert not first.is_alive()
    assert not second.is_alive()
    assert errors == []
    assert store._schema_ready is True
    assert readiness_calls["count"] == 1
    assert any("CREATE TABLE IF NOT EXISTS" in call for call in calls)


def test_config_revision_init_serializes_lazy_schema_work(monkeypatch) -> None:
    _assert_concurrent_init_is_serialized(
        monkeypatch,
        config_revisions,
        config_revisions.ConfigRevisionStore(),
    )


def test_certificate_bundle_init_serializes_lazy_schema_work(monkeypatch) -> None:
    _assert_concurrent_init_is_serialized(
        monkeypatch,
        certificate_bundles,
        certificate_bundles.CertificateBundleStore(),
    )


def test_adblock_artifact_init_serializes_lazy_schema_work(monkeypatch, tmp_path) -> None:
    _assert_concurrent_init_is_serialized(
        monkeypatch,
        adblock_artifacts,
        adblock_artifacts.AdblockArtifactStore(compiled_dir=str(tmp_path)),
    )
