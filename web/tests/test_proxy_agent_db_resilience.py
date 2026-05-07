from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace


def _add_repo_paths() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    web_root = repo_root / "web"
    for path in (repo_root, web_root):
        path_str = str(path)
        if path_str not in sys.path:
            sys.path.insert(0, path_str)


def test_proxy_agent_startup_does_not_exit_when_initial_control_plane_db_calls_fail(monkeypatch) -> None:
    _add_repo_paths()
    import proxy.agent as agent  # type: ignore

    calls: list[str] = []
    threads: list[tuple[str, object]] = []

    class Runtime:
        def ensure_registered(self):
            calls.append("ensure_registered")
            raise RuntimeError("mysql unavailable")

        def bootstrap_revision_if_missing(self):
            calls.append("bootstrap")
            raise RuntimeError("mysql unavailable")

        def start_background_tasks(self):
            calls.append("background")
            raise RuntimeError("mysql unavailable")

        def sync_from_db(self, *, force=False):
            calls.append(f"sync:{force}")
            raise RuntimeError("mysql unavailable")

        def heartbeat(self):  # pragma: no cover - thread target is not run here
            raise AssertionError("thread target should not run synchronously")

    class FakeThread:
        def __init__(self, *, target, args=(), name, daemon):
            assert daemon is True
            threads.append((name, target))

        def start(self):
            return None

    monkeypatch.setattr(agent, "_started", False)
    monkeypatch.setattr(agent, "get_runtime", lambda: Runtime())
    monkeypatch.setattr(agent.threading, "Thread", FakeThread)
    monkeypatch.setattr(agent, "log_exception_throttled", lambda *args, **kwargs: None)
    monkeypatch.setattr(agent, "_env_float", lambda *_args, **_kwargs: 1.0)

    agent.start_agent()

    assert calls == ["ensure_registered", "bootstrap", "background", "sync:False"]
    assert [name for name, _target in threads] == ["proxy-heartbeat", "proxy-sync-loop"]


def test_proxy_agent_sync_loop_retries_background_tasks_before_sync() -> None:
    _add_repo_paths()
    import proxy.agent as agent  # type: ignore

    calls: list[str] = []

    class Runtime:
        def start_background_tasks(self):
            calls.append("background")

        def sync_from_db(self, *, force=False):
            calls.append(f"sync:{force}")
            return {"ok": True}

    result = agent._sync_loop(Runtime(), force=False)

    assert result == {"ok": True}
    assert calls == ["background", "sync:False"]


def test_proxy_agent_logs_database_outages_without_traceback(monkeypatch) -> None:
    _add_repo_paths()
    import pymysql  # type: ignore
    import proxy.agent as agent  # type: ignore

    warnings: list[tuple[str, tuple[object, ...]]] = []

    monkeypatch.setattr(agent, "should_log", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(agent.logger, "warning", lambda message, *args: warnings.append((message, args)))
    monkeypatch.setattr(
        agent,
        "log_exception_throttled",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("database outages should not log tracebacks")),
    )

    agent._log_recoverable_or_unexpected(
        "test.db",
        interval_seconds=1.0,
        recoverable_message="waiting for db",
        unexpected_message="unexpected",
        exc=pymysql.err.OperationalError(2003, "connect timed out"),
    )

    assert warnings
    assert warnings[0][0] == "%s: %s"
    assert warnings[0][1][0] == "waiting for db"


def test_proxy_agent_logs_unexpected_errors_with_traceback(monkeypatch) -> None:
    _add_repo_paths()
    import proxy.agent as agent  # type: ignore

    calls: list[tuple[object, ...]] = []
    monkeypatch.setattr(agent, "log_exception_throttled", lambda *args, **kwargs: calls.append(args))

    agent._log_recoverable_or_unexpected(
        "test.unexpected",
        interval_seconds=1.0,
        recoverable_message="waiting",
        unexpected_message="unexpected failure",
        exc=RuntimeError("bug"),
    )

    assert calls


def test_proxy_runtime_construction_does_not_initialize_database_backed_stores(monkeypatch) -> None:
    _add_repo_paths()
    import proxy.runtime as runtime_module  # type: ignore
    import services.adblock_artifacts as adblock_artifacts  # type: ignore
    import services.adblock_store as adblock_store  # type: ignore
    import services.certificate_bundles as certificate_bundles  # type: ignore
    import services.config_revisions as config_revisions  # type: ignore
    import services.diagnostic_store as diagnostic_store  # type: ignore
    import services.proxy_registry as proxy_registry  # type: ignore
    import services.ssl_errors_store as ssl_errors_store  # type: ignore

    for module in (
        adblock_artifacts,
        adblock_store,
        certificate_bundles,
        config_revisions,
        diagnostic_store,
        proxy_registry,
        ssl_errors_store,
    ):
        monkeypatch.setattr(module, "_store", None)

    def fail_init(self):  # pragma: no cover - should never run in this test
        raise AssertionError(f"{type(self).__name__}.init_db should not run during ProxyRuntime construction")

    monkeypatch.setattr(adblock_artifacts.AdblockArtifactStore, "init_db", fail_init)
    monkeypatch.setattr(adblock_store.AdblockStore, "init_db", fail_init)
    monkeypatch.setattr(certificate_bundles.CertificateBundleStore, "init_db", fail_init)
    monkeypatch.setattr(config_revisions.ConfigRevisionStore, "init_db", fail_init)
    monkeypatch.setattr(diagnostic_store.DiagnosticStore, "init_db", fail_init)
    monkeypatch.setattr(proxy_registry.ProxyRegistry, "init_db", fail_init)
    monkeypatch.setattr(ssl_errors_store.SslErrorsStore, "init_db", fail_init)

    runtime = runtime_module.ProxyRuntime()

    assert runtime.registry is not None
    assert runtime.revisions is not None
    assert runtime.certificate_bundles is not None
    assert runtime.adblock_artifacts is not None
    assert runtime.adblock_store is not None
    assert runtime.diagnostic_store is not None
    assert runtime.ssl_errors_store is not None


def test_proxy_runtime_background_task_startup_is_isolated_and_retryable(monkeypatch) -> None:
    _add_repo_paths()
    from proxy.runtime import ProxyRuntime  # type: ignore

    runtime = ProxyRuntime.__new__(ProxyRuntime)
    calls: list[str] = []

    def failing(name: str):
        def _inner(*_args, **_kwargs):
            calls.append(name)
            raise RuntimeError(f"{name} database unavailable")

        return _inner

    runtime.live_stats_store = SimpleNamespace(start_background=failing("live_stats"))
    runtime.diagnostic_store = SimpleNamespace(start_background=failing("diagnostic"))
    runtime.timeseries_store = SimpleNamespace(start_background=failing("timeseries"))
    runtime.ssl_errors_store = SimpleNamespace(start_background=failing("ssl_errors"))
    runtime.adblock_store = SimpleNamespace(start_blocklog_background=failing("adblock"))
    runtime.stats_provider = lambda: {}

    monkeypatch.delenv("DISABLE_BACKGROUND", raising=False)
    import proxy.runtime as runtime_module  # type: ignore

    monkeypatch.setattr(runtime_module, "log_exception_throttled", lambda *args, **kwargs: None)

    runtime.start_background_tasks()
    runtime.start_background_tasks()

    assert calls == [
        "live_stats",
        "diagnostic",
        "timeseries",
        "ssl_errors",
        "adblock",
        "live_stats",
        "diagnostic",
        "timeseries",
        "ssl_errors",
        "adblock",
    ]
