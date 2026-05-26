from __future__ import annotations

import sys
from pathlib import Path

import pytest


def _add_repo_paths() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    web_root = repo_root / "web"
    for path in (repo_root, web_root):
        path_str = str(path)
        if path_str not in sys.path:
            sys.path.insert(0, path_str)


def _noop_init_schema(_conn) -> None:
    return None


def test_adblock_artifact_background_start_does_not_latch_on_init_failure(monkeypatch) -> None:
    _add_repo_paths()
    from services.adblock_artifacts import AdblockArtifactStore  # type: ignore

    store = AdblockArtifactStore()

    def fail_init() -> None:
        msg = "db unavailable"
        raise RuntimeError(msg)

    monkeypatch.setattr(store, "init_db", fail_init)

    with pytest.raises(RuntimeError, match="db unavailable"):
        store.start_background()

    assert store._started is False


def test_webfilter_background_start_does_not_latch_on_init_failure(monkeypatch) -> None:
    _add_repo_paths()
    from services.webfilter_store import WebFilterStore  # type: ignore

    store = WebFilterStore()

    def fail_init() -> None:
        msg = "db unavailable"
        raise RuntimeError(msg)

    monkeypatch.setattr(store, "init_db", fail_init)

    with pytest.raises(RuntimeError, match="db unavailable"):
        store.start_background()

    assert store._started is False


def test_safe_browsing_background_start_does_not_latch_on_init_failure(monkeypatch) -> None:
    _add_repo_paths()
    from services.safe_browsing_v5 import SafeBrowsingStore  # type: ignore

    store = SafeBrowsingStore()

    def fail_init() -> None:
        msg = "db unavailable"
        raise RuntimeError(msg)

    monkeypatch.setattr(store, "init_db", fail_init)

    with pytest.raises(RuntimeError, match="db unavailable"):
        store.start_background(lambda: None, lambda *_args: None)

    assert store._started is False


def test_safe_browsing_local_checker_close_releases_cached_connection(monkeypatch) -> None:
    _add_repo_paths()
    from services import safe_browsing_v5  # type: ignore

    closed: list[bool] = []

    class FakeConn:
        def close(self) -> None:
            closed.append(True)

    monkeypatch.setattr(safe_browsing_v5, "connect", FakeConn)
    monkeypatch.setattr(
        safe_browsing_v5.SafeBrowsingStore,
        "init_schema",
        staticmethod(_noop_init_schema),
    )

    checker = safe_browsing_v5.SafeBrowsingLocalChecker(api_key="test")
    conn = checker._connect()

    conn.close()
    checker.close()

    assert closed == [True]
    assert checker._conn is None


def test_safe_browsing_local_checker_context_manager_closes(monkeypatch) -> None:
    _add_repo_paths()
    from services import safe_browsing_v5  # type: ignore

    closed: list[bool] = []

    class FakeConn:
        def close(self) -> None:
            closed.append(True)

    monkeypatch.setattr(safe_browsing_v5, "connect", FakeConn)
    monkeypatch.setattr(
        safe_browsing_v5.SafeBrowsingStore,
        "init_schema",
        staticmethod(_noop_init_schema),
    )

    with safe_browsing_v5.SafeBrowsingLocalChecker(api_key="test") as checker:
        conn = checker._connect()
        conn.close()

    assert closed == [True]
    assert checker._conn is None


def test_safe_browsing_local_checker_discards_cached_connection_on_db_error(monkeypatch) -> None:
    _add_repo_paths()
    from services import safe_browsing_v5  # type: ignore

    closed: list[bool] = []

    class FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.close()
            return False

        def execute(self, *_args, **_kwargs):
            msg = "stale connection"
            raise RuntimeError(msg)

        def close(self) -> None:
            closed.append(True)

    monkeypatch.setattr(safe_browsing_v5, "connect", FakeConn)
    monkeypatch.setattr(
        safe_browsing_v5.SafeBrowsingStore,
        "init_schema",
        staticmethod(_noop_init_schema),
    )

    checker = safe_browsing_v5.SafeBrowsingLocalChecker(api_key="test")

    assert checker._local_lists_for_prefix(b"abcd") == ()
    assert closed == [True, True]
    assert checker._conn is None
