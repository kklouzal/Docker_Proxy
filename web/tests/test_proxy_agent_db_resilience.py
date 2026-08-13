from __future__ import annotations

from types import SimpleNamespace
from typing import NoReturn

import pytest


def test_proxy_agent_startup_does_not_exit_when_initial_control_plane_db_calls_fail(
    monkeypatch,
) -> None:
    from proxy import agent  # type: ignore

    calls: list[str] = []
    threads: list[tuple[str, object]] = []

    class Runtime:
        def ensure_registered(self) -> NoReturn:
            calls.append("ensure_registered")
            msg = "mysql unavailable"
            raise RuntimeError(msg)

        def bootstrap_revision_if_missing(self) -> NoReturn:
            calls.append("bootstrap")
            msg = "mysql unavailable"
            raise RuntimeError(msg)

        def start_background_tasks(self) -> NoReturn:
            calls.append("background")
            msg = "mysql unavailable"
            raise RuntimeError(msg)

        def sync_from_db(self, *, force=False) -> NoReturn:
            calls.append(f"sync:{force}")
            msg = "mysql unavailable"
            raise RuntimeError(msg)

        def heartbeat(
            self,
        ) -> NoReturn:  # pragma: no cover - thread target is not run here
            msg = "thread target should not run synchronously"
            raise AssertionError(msg)

    class FakeThread:
        def __init__(self, *, target, args=(), name, daemon) -> None:
            assert daemon is True
            threads.append((name, target))

        def start(self) -> None:
            return None

    monkeypatch.setattr(agent, "_started", False)
    monkeypatch.setattr(agent, "get_runtime", Runtime)
    monkeypatch.setattr(agent.threading, "Thread", FakeThread)
    monkeypatch.setattr(agent, "log_exception_throttled", lambda *args, **kwargs: None)
    monkeypatch.setattr(agent, "_env_float", lambda *_args, **_kwargs: 1.0)

    agent.start_agent()

    assert calls == ["ensure_registered", "bootstrap", "background", "sync:False"]
    assert [name for name, _target in threads] == ["proxy-heartbeat", "proxy-sync-loop"]


def test_proxy_agent_runtime_construction_failure_allows_one_successful_retry(
    monkeypatch,
) -> None:
    from proxy import agent  # type: ignore

    runtime_attempts = 0
    thread_starts: list[str] = []

    class Runtime:
        def ensure_registered(self) -> None:
            pass

        def bootstrap_revision_if_missing(self) -> None:
            pass

        def start_background_tasks(self) -> None:
            pass

        def sync_from_db(self, *, force=False):
            return {"ok": True}

        def heartbeat(self) -> None:
            pass

    def get_runtime():
        nonlocal runtime_attempts
        runtime_attempts += 1
        if runtime_attempts == 1:
            msg = "runtime construction failed"
            raise RuntimeError(msg)
        return Runtime()

    class FakeThread:
        def __init__(self, *, target, args=(), name, daemon) -> None:
            assert callable(target)
            assert daemon is True
            self.name = name

        def start(self) -> None:
            thread_starts.append(self.name)

    monkeypatch.setattr(agent, "_started", False)
    monkeypatch.setattr(agent, "get_runtime", get_runtime)
    monkeypatch.setattr(agent.threading, "Thread", FakeThread)
    monkeypatch.setattr(agent, "_env_float", lambda *_args, **_kwargs: 1.0)

    with pytest.raises(RuntimeError, match="runtime construction failed"):
        agent.start_agent()

    assert agent._started is False

    agent.start_agent()
    agent.start_agent()

    assert runtime_attempts == 2
    assert thread_starts == ["proxy-heartbeat", "proxy-sync-loop"]
    assert agent._started is True


@pytest.mark.parametrize(
    ("failed_start_name", "expected_start_attempts"),
    [
        (
            "proxy-heartbeat",
            ["proxy-heartbeat", "proxy-heartbeat", "proxy-sync-loop"],
        ),
        (
            "proxy-sync-loop",
            ["proxy-heartbeat", "proxy-sync-loop", "proxy-sync-loop"],
        ),
    ],
)
def test_proxy_agent_thread_start_failure_retries_only_missing_loops(
    monkeypatch,
    failed_start_name,
    expected_start_attempts,
) -> None:
    from proxy import agent  # type: ignore

    runtime_attempts = 0
    start_attempts: list[str] = []
    successful_starts: list[str] = []
    failure_raised = False

    class Runtime:
        def ensure_registered(self) -> None:
            pass

        def bootstrap_revision_if_missing(self) -> None:
            pass

        def start_background_tasks(self) -> None:
            pass

        def sync_from_db(self, *, force=False):
            return {"ok": True}

        def heartbeat(self) -> None:
            pass

    def get_runtime():
        nonlocal runtime_attempts
        runtime_attempts += 1
        return Runtime()

    class FakeThread:
        def __init__(self, *, target, args=(), name, daemon) -> None:
            assert callable(target)
            assert daemon is True
            self.name = name

        def start(self) -> None:
            nonlocal failure_raised
            start_attempts.append(self.name)
            if self.name == failed_start_name and not failure_raised:
                failure_raised = True
                msg = f"simulated {self.name} start failure"
                raise RuntimeError(msg)
            successful_starts.append(self.name)

    monkeypatch.setattr(agent, "_started", False)
    monkeypatch.setattr(agent, "_started_loop_names", set())
    monkeypatch.setattr(agent, "get_runtime", get_runtime)
    monkeypatch.setattr(agent.threading, "Thread", FakeThread)
    monkeypatch.setattr(agent, "_env_float", lambda *_args, **_kwargs: 1.0)

    with pytest.raises(RuntimeError, match=f"simulated {failed_start_name}"):
        agent.start_agent()

    assert agent._started is False

    agent.start_agent()
    agent.start_agent()

    assert runtime_attempts == 2
    assert start_attempts == expected_start_attempts
    assert successful_starts == ["proxy-heartbeat", "proxy-sync-loop"]
    assert agent._started is True


def test_proxy_agent_runs_schema_when_runtime_has_no_recovery_hook(monkeypatch) -> None:
    from proxy import agent  # type: ignore

    calls: list[str] = []

    class Runtime:
        def ensure_startup_schema(self) -> None:
            calls.append("schema")

        def ensure_registered(self) -> None:
            calls.append("ensure_registered")

        def bootstrap_revision_if_missing(self) -> None:
            calls.append("bootstrap")

        def start_background_tasks(self) -> None:
            calls.append("background")

        def sync_from_db(self, *, force=False):
            calls.append(f"sync:{force}")
            return {"ok": True, "changed": False}

        def heartbeat(self):  # pragma: no cover - thread target is not run here
            msg = "thread target should not run synchronously"
            raise AssertionError(msg)

    class FakeThread:
        def __init__(self, *, target, args=(), name, daemon) -> None:
            return None

        def start(self) -> None:
            return None

    monkeypatch.setattr(agent, "_started", False)
    monkeypatch.setattr(agent, "get_runtime", Runtime)
    monkeypatch.setattr(agent.threading, "Thread", FakeThread)
    monkeypatch.setattr(agent, "_env_float", lambda *_args, **_kwargs: 1.0)

    agent.start_agent()

    assert calls == [
        "schema",
        "ensure_registered",
        "bootstrap",
        "background",
        "sync:False",
    ]


def test_proxy_agent_skips_initial_db_mutation_when_missing_bundle_schema_deferred(
    monkeypatch,
) -> None:
    from proxy import agent  # type: ignore

    calls: list[str] = []
    threads: list[str] = []

    class Runtime:
        def run_startup_recovery(self):
            calls.append("recovery")
            return SimpleNamespace(proxy_id="edge-01", capture_required=True)

        def ensure_startup_schema(self) -> None:
            calls.append("schema")
            msg = "mysql unavailable"
            raise RuntimeError(msg)

        def ensure_registered(self) -> None:
            calls.append("ensure_registered")

        def bootstrap_revision_if_missing(self) -> None:
            calls.append("bootstrap")

        def start_background_tasks(self) -> None:
            calls.append("background")

        def sync_from_db(self, *, force=False):
            calls.append(f"sync:{force}")
            return {"ok": True}

        def heartbeat(self):  # pragma: no cover - thread target is not run here
            msg = "thread target should not run synchronously"
            raise AssertionError(msg)

    class FakeThread:
        def __init__(self, *, target, args=(), name, daemon) -> None:
            threads.append(name)

        def start(self) -> None:
            return None

    monkeypatch.setattr(agent, "_started", False)
    monkeypatch.setattr(agent, "get_runtime", Runtime)
    monkeypatch.setattr(agent.threading, "Thread", FakeThread)
    monkeypatch.setattr(agent, "log_exception_throttled", lambda *args, **kwargs: None)
    monkeypatch.setattr(agent, "_env_float", lambda *_args, **_kwargs: 1.0)

    agent.start_agent()

    assert calls == ["recovery", "schema"]
    assert threads == ["proxy-heartbeat", "proxy-sync-loop"]


def test_proxy_agent_runs_recovery_before_initial_registration_and_required_capture(
    monkeypatch,
) -> None:
    from proxy import agent  # type: ignore

    calls: list[str] = []

    class Runtime:
        def run_startup_recovery(self):
            calls.append("recovery")
            return SimpleNamespace(proxy_id="edge-01", capture_required=True)

        def ensure_startup_schema(self) -> None:
            calls.append("schema")

        def ensure_registered(self) -> None:
            calls.append("ensure_registered")

        def bootstrap_revision_if_missing(self) -> None:
            calls.append("bootstrap")

        def start_background_tasks(self) -> None:
            calls.append("background")

        def sync_from_db(self, *, force=False):
            calls.append(f"sync:{force}")
            return {"ok": True, "changed": True}

        def capture_recovery_bundle(self, *, reason, required=False, changed=False):
            calls.append(f"capture:{reason}:{required}:{changed}")
            return {"ok": True}

        def heartbeat(self):  # pragma: no cover - thread target is not run here
            msg = "thread target should not run synchronously"
            raise AssertionError(msg)

    class FakeThread:
        def __init__(self, *, target, args=(), name, daemon) -> None:
            return None

        def start(self) -> None:
            return None

    monkeypatch.setattr(agent, "_started", False)
    monkeypatch.setattr(agent, "get_runtime", Runtime)
    monkeypatch.setattr(agent.threading, "Thread", FakeThread)
    monkeypatch.setattr(agent, "_env_float", lambda *_args, **_kwargs: 1.0)

    agent.start_agent()

    assert calls == [
        "recovery",
        "schema",
        "ensure_registered",
        "bootstrap",
        "background",
        "sync:False",
        "capture:startup_initial:True:True",
    ]


def test_proxy_agent_defers_initial_capture_when_initial_sync_result_failed(
    monkeypatch,
) -> None:
    from proxy import agent  # type: ignore

    calls: list[str] = []

    class Runtime:
        def run_startup_recovery(self):
            calls.append("recovery")
            return SimpleNamespace(proxy_id="edge-01", capture_required=True)

        def ensure_startup_schema(self) -> None:
            calls.append("schema")

        def ensure_registered(self) -> None:
            calls.append("ensure_registered")

        def bootstrap_revision_if_missing(self) -> None:
            calls.append("bootstrap")

        def start_background_tasks(self) -> None:
            calls.append("background")

        def sync_from_db(self, *, force=False):
            calls.append(f"sync:{force}")
            return {"ok": False, "changed": True, "detail": "apply failed"}

        def capture_recovery_bundle(self, *, reason, required=False, changed=False):
            calls.append(f"capture:{reason}:{required}:{changed}")
            return {"ok": True}

        def heartbeat(self):  # pragma: no cover - thread target is not run here
            msg = "thread target should not run synchronously"
            raise AssertionError(msg)

    class FakeThread:
        def __init__(self, *, target, args=(), name, daemon) -> None:
            return None

        def start(self) -> None:
            return None

    monkeypatch.setattr(agent, "_started", False)
    monkeypatch.setattr(agent, "get_runtime", Runtime)
    monkeypatch.setattr(agent.threading, "Thread", FakeThread)
    monkeypatch.setattr(agent, "_env_float", lambda *_args, **_kwargs: 1.0)

    agent.start_agent()

    assert calls == [
        "recovery",
        "schema",
        "ensure_registered",
        "bootstrap",
        "background",
        "sync:False",
    ]


def test_proxy_agent_retries_deferred_required_initial_capture_in_sync_loop() -> None:
    from proxy import agent  # type: ignore

    calls: list[str] = []

    class Runtime:
        recovery_initial_capture_required = True

        def ensure_startup_schema(self) -> None:
            calls.append("schema")

        def start_background_tasks(self) -> None:
            calls.append("background")

        def sync_from_db(self, *, force=False):
            calls.append(f"sync:{force}")
            return {"ok": True, "changed": True}

        def capture_recovery_bundle(self, *, reason, required=False, changed=False):
            calls.append(f"capture:{reason}:{required}:{changed}")
            self.recovery_initial_capture_required = False
            return {"ok": True}

    result = agent._sync_loop(Runtime(), force=False)

    assert result == {"ok": True, "changed": True}
    assert calls == [
        "schema",
        "sync:False",
        "capture:startup_initial:True:True",
        "background",
    ]


def test_proxy_agent_required_capture_failure_stays_required_and_retryable() -> None:
    from services.proxy_recovery_startup import (  # type: ignore
        ProxyRecoveryCaptureError,
    )

    from proxy import agent  # type: ignore

    calls: list[str] = []

    class Runtime:
        recovery_initial_capture_required = True
        capture_attempts = 0

        def ensure_startup_schema(self) -> None:
            calls.append("schema")

        def start_background_tasks(self) -> None:
            calls.append("background")

        def sync_from_db(self, *, force=False):
            calls.append(f"sync:{force}")
            return {"ok": True, "changed": False}

        def capture_recovery_bundle(self, *, reason, required=False, changed=False):
            calls.append(f"capture:{reason}:{required}:{changed}")
            assert required is True
            self.capture_attempts += 1
            if self.capture_attempts == 1:
                message = "disk unavailable"
                raise ProxyRecoveryCaptureError(message)
            self.recovery_initial_capture_required = False
            return {"ok": True, "skipped": False}

    runtime = Runtime()
    with pytest.raises(ProxyRecoveryCaptureError, match="disk unavailable"):
        agent._sync_loop(runtime, force=False)

    assert runtime.recovery_initial_capture_required is True
    assert "background" not in calls

    result = agent._sync_loop(runtime, force=False)

    assert result == {"ok": True, "changed": False}
    assert runtime.recovery_initial_capture_required is False
    assert calls == [
        "schema",
        "sync:False",
        "capture:startup_initial:True:False",
        "schema",
        "sync:False",
        "capture:startup_initial:True:False",
        "background",
    ]


def test_proxy_agent_defers_required_capture_when_sync_result_failed() -> None:
    from proxy import agent  # type: ignore

    calls: list[str] = []

    class Runtime:
        recovery_initial_capture_required = True

        def ensure_startup_schema(self) -> None:
            calls.append("schema")

        def start_background_tasks(self) -> None:
            calls.append("background")

        def sync_from_db(self, *, force=False):
            calls.append(f"sync:{force}")
            return {"ok": False, "changed": True, "detail": "apply failed"}

        def capture_recovery_bundle(self, *, reason, required=False, changed=False):
            calls.append(f"capture:{reason}:{required}:{changed}")
            return {"ok": True}

    result = agent._sync_loop(Runtime(), force=False)

    assert result == {"ok": False, "changed": True, "detail": "apply failed"}
    assert calls == ["schema", "sync:False"]


def test_proxy_agent_sync_loop_retries_background_tasks_before_sync() -> None:
    from proxy import agent  # type: ignore

    calls: list[str] = []

    class Runtime:
        def start_background_tasks(self) -> None:
            calls.append("background")

        def sync_from_db(self, *, force=False):
            calls.append(f"sync:{force}")
            return {"ok": True}

    result = agent._sync_loop(Runtime(), force=False)

    assert result == {"ok": True}
    assert calls == ["background", "sync:False"]


def test_proxy_agent_sync_loop_does_not_restart_background_after_shutdown() -> None:
    from proxy import agent  # type: ignore

    calls: list[str] = []
    stop_event = agent.threading.Event()

    class Runtime:
        recovery_initial_capture_required = True

        def ensure_startup_schema(self) -> None:
            calls.append("schema")

        def sync_from_db(self, *, force=False):
            calls.append(f"sync:{force}")
            stop_event.set()
            self.recovery_initial_capture_required = False
            return {"ok": True, "changed": False}

        def start_background_tasks(self) -> None:
            calls.append("background")

    result = agent._sync_loop(Runtime(), stop_event=stop_event)

    assert result == {"ok": True, "changed": False}
    assert calls == ["schema", "sync:False"]


def test_proxy_agent_loop_shutdown_interrupts_wait_and_prevents_next_iteration() -> (
    None
):
    from proxy import agent  # type: ignore

    stop_event = agent.threading.Event()
    calls = 0

    def run_once() -> None:
        nonlocal calls
        calls += 1
        stop_event.set()

    agent._loop(3600.0, run_once, stop_event)

    assert calls == 1


def test_proxy_agent_logs_database_outages_without_traceback(monkeypatch) -> None:
    import pymysql  # type: ignore

    from proxy import agent  # type: ignore

    warnings: list[tuple[str, tuple[object, ...]]] = []

    monkeypatch.setattr(agent, "should_log", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        agent.logger, "warning", lambda message, *args: warnings.append((message, args))
    )
    monkeypatch.setattr(
        agent,
        "log_exception_throttled",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("database outages should not log tracebacks")
        ),
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
    from proxy import agent  # type: ignore

    calls: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        agent, "log_exception_throttled", lambda *args, **kwargs: calls.append(args)
    )

    agent._log_recoverable_or_unexpected(
        "test.unexpected",
        interval_seconds=1.0,
        recoverable_message="waiting",
        unexpected_message="unexpected failure",
        exc=RuntimeError("bug"),
    )

    assert calls


def test_proxy_runtime_construction_does_not_initialize_database_backed_stores(
    monkeypatch,
) -> None:
    from services import (
        adblock_artifacts,  # type: ignore
        adblock_store,  # type: ignore
        certificate_bundles,  # type: ignore
        config_revisions,  # type: ignore
        diagnostic_store,  # type: ignore
        proxy_registry,  # type: ignore
        ssl_errors_store,  # type: ignore
    )

    import proxy.runtime as runtime_module  # type: ignore

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

    def fail_init(self) -> NoReturn:  # pragma: no cover - should never run in this test
        msg = f"{type(self).__name__}.init_db should not run during ProxyRuntime construction"
        raise AssertionError(msg)

    monkeypatch.setattr(adblock_artifacts.AdblockArtifactStore, "init_db", fail_init)
    monkeypatch.setattr(adblock_store.AdblockStore, "init_db", fail_init)
    monkeypatch.setattr(
        certificate_bundles.CertificateBundleStore, "init_db", fail_init
    )
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


def test_proxy_runtime_singleton_is_thread_safe(monkeypatch) -> None:
    import threading
    import time

    import proxy.runtime as runtime_module  # type: ignore

    created: list[object] = []

    class Runtime:
        def __init__(self) -> None:
            time.sleep(0.01)
            created.append(self)

    monkeypatch.setattr(runtime_module, "_runtime", None)
    monkeypatch.setattr(runtime_module, "ProxyRuntime", Runtime)

    results: list[object] = []
    threads = [
        threading.Thread(target=lambda: results.append(runtime_module.get_runtime()))
        for _index in range(8)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=2)

    assert len(results) == 8
    assert len(created) == 1
    assert all(result is created[0] for result in results)


def test_proxy_runtime_singleton_lock_recovers_after_failed_initialization(
    monkeypatch,
) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    attempts = 0

    class Runtime:
        def __init__(self) -> None:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                msg = "first init failed"
                raise RuntimeError(msg)

    monkeypatch.setattr(runtime_module, "_runtime", None)
    monkeypatch.setattr(runtime_module, "ProxyRuntime", Runtime)

    with pytest.raises(RuntimeError, match="first init failed"):
        runtime_module.get_runtime()

    result = runtime_module.get_runtime()

    assert isinstance(result, Runtime)
    assert attempts == 2


def test_proxy_runtime_required_initial_capture_suppresses_optional_sync_capture(
    monkeypatch,
) -> None:
    from proxy.runtime import ProxyRuntime  # type: ignore

    runtime = ProxyRuntime.__new__(ProxyRuntime)
    runtime._recovery_initial_capture_required = True
    captures: list[str] = []

    monkeypatch.setattr(
        runtime,
        "capture_recovery_bundle",
        lambda **kwargs: captures.append(str(kwargs.get("reason"))) or {"ok": True},
    )

    runtime._capture_recovery_bundle_after_sync({"ok": True, "changed": True})

    assert captures == []


def test_proxy_runtime_successful_required_capture_clears_initial_guard(
    monkeypatch,
) -> None:
    import proxy.runtime as runtime_module  # type: ignore

    runtime = runtime_module.ProxyRuntime.__new__(runtime_module.ProxyRuntime)
    runtime._recovery_capture_lock = runtime_module.threading.Lock()
    runtime._last_recovery_capture_mono = 0.0
    runtime._recovery_initial_capture_required = True
    monkeypatch.setattr(
        runtime_module.ProxyRuntime,
        "proxy_id",
        property(lambda _self: "edge-01"),
    )

    def capture(**kwargs):
        return SimpleNamespace(
            ok=True,
            skipped=False,
            proxy_id=str(kwargs["proxy_id"]),
            path="",
            reason=str(kwargs["reason"]),
            required=bool(kwargs["required"]),
            detail="",
        )

    monkeypatch.setattr(
        runtime_module, "capture_recovery_bundle_after_authoritative_state", capture
    )

    result = runtime.capture_recovery_bundle(reason="startup_initial", required=True)

    assert result["ok"] is True
    assert runtime.recovery_initial_capture_required is False


def test_proxy_runtime_successful_rollback_captures_authoritative_state(
    monkeypatch,
) -> None:
    from proxy.runtime import ProxyRuntime  # type: ignore

    runtime = ProxyRuntime.__new__(ProxyRuntime)
    runtime.controller = SimpleNamespace(
        restore_last_known_good_config=lambda *, reason: (True, "rolled back"),
    )
    runtime.registry = SimpleNamespace(mark_apply_result=lambda *_args, **_kwargs: None)
    monkeypatch.setattr(ProxyRuntime, "proxy_id", property(lambda _self: "edge-01"))
    captures: list[dict[str, object]] = []

    monkeypatch.setattr(runtime, "_invalidate_health_cache", lambda: None)
    monkeypatch.setattr(runtime, "_current_config_sha", lambda: "abc123")
    monkeypatch.setattr(
        runtime,
        "_capture_recovery_bundle_after_sync",
        lambda result: captures.append(dict(result)),
    )

    result = runtime.rollback_last_known_good_config(reason="test")

    assert result["ok"] is True
    assert captures == [result]


def test_proxy_runtime_background_task_startup_is_isolated_and_retryable(
    monkeypatch,
) -> None:
    from proxy.runtime import ProxyRuntime  # type: ignore

    runtime = ProxyRuntime.__new__(ProxyRuntime)
    calls: list[str] = []

    def failing(name: str):
        def _inner(*_args, **_kwargs) -> NoReturn:
            calls.append(name)
            msg = f"{name} database unavailable"
            raise RuntimeError(msg)

        return _inner

    runtime.live_stats_store = SimpleNamespace(start_background=failing("live_stats"))
    runtime.diagnostic_store = SimpleNamespace(start_background=failing("diagnostic"))
    runtime.timeseries_store = SimpleNamespace(start_background=failing("timeseries"))
    runtime.ssl_errors_store = SimpleNamespace(start_background=failing("ssl_errors"))
    runtime.adblock_store = SimpleNamespace(
        start_blocklog_background=failing("adblock")
    )
    runtime.stats_provider = dict

    monkeypatch.delenv("DISABLE_BACKGROUND", raising=False)
    import proxy.runtime as runtime_module  # type: ignore

    monkeypatch.setattr(
        runtime_module, "log_exception_throttled", lambda *args, **kwargs: None
    )

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


def test_runtime_stop_background_tasks_uses_one_bounded_shared_deadline(monkeypatch):
    from proxy.runtime import ProxyRuntime

    calls = []

    class Store:
        def __init__(self, name):
            self.name = name

        def stop_background(self, *, timeout):
            calls.append((self.name, timeout))
            return True

    class Adblock:
        def stop_blocklog_background(self, *, timeout):
            calls.append(("adblock", timeout))
            return True

    runtime = ProxyRuntime.__new__(ProxyRuntime)
    runtime.live_stats_store = Store("live")
    runtime.diagnostic_store = Store("diagnostic")
    runtime.timeseries_store = Store("timeseries")
    runtime.ssl_errors_store = Store("ssl")
    runtime.adblock_store = Adblock()
    ticks = iter((100.0, 101.0, 102.0, 103.0, 104.0, 105.0))
    monkeypatch.setattr("proxy.runtime.time.monotonic", lambda: next(ticks))

    assert runtime.stop_background_tasks(timeout=10.0) is True
    assert calls == [
        ("live", 9.0),
        ("diagnostic", 8.0),
        ("timeseries", 7.0),
        ("ssl", 6.0),
        ("adblock", 5.0),
    ]


def test_runtime_stop_background_tasks_continues_after_failure():
    from proxy.runtime import ProxyRuntime

    calls = []

    class Store:
        def __init__(self, name, result=True):
            self.name = name
            self.result = result

        def stop_background(self, *, timeout):
            calls.append(self.name)
            if isinstance(self.result, Exception):
                raise self.result
            return self.result

    class Adblock:
        def stop_blocklog_background(self, *, timeout):
            calls.append("adblock")
            return True

    runtime = ProxyRuntime.__new__(ProxyRuntime)
    runtime.live_stats_store = Store("live", False)
    runtime.diagnostic_store = Store("diagnostic", RuntimeError("boom"))
    runtime.timeseries_store = Store("timeseries")
    runtime.ssl_errors_store = Store("ssl")
    runtime.adblock_store = Adblock()

    assert runtime.stop_background_tasks(timeout=1.0) is False
    assert calls == ["live", "diagnostic", "timeseries", "ssl", "adblock"]
