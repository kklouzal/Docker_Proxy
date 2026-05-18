
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from .mysql_test_utils import ensure_proxy_runtime_import_path


def test_proxy_policy_sync_reports_webcat_snapshot_degraded_when_already_current(tmp_path, monkeypatch):
    ensure_proxy_runtime_import_path()

    from proxy.runtime import ProxyRuntime, ProxyRuntimeServices  # type: ignore
    from services.policy_materializer import MaterializedPolicyFile, ProxyPolicyState, calculate_policy_sha  # type: ignore

    policy_file = MaterializedPolicyFile(
        path=str(tmp_path / "30-webfilter.conf"),
        content="# webfilter\nexternal_acl_type webcat_deadbeef children=2 ttl=0 negative_ttl=1 %SRC %DST %URI /usr/bin/python3 /app/tools/webcat_acl.py --fail open\n",
    )
    policy_sha = calculate_policy_sha((policy_file,))

    services = ProxyRuntimeServices(
        controller=SimpleNamespace(),
        registry=SimpleNamespace(),
        revisions=SimpleNamespace(),
        certificate_bundles=SimpleNamespace(),
        adblock_artifacts=SimpleNamespace(compiled_dir=str(tmp_path / "adblock")),
        cert_manager=SimpleNamespace(),
        adblock_store=SimpleNamespace(),
        live_stats_store=SimpleNamespace(),
        diagnostic_store=SimpleNamespace(),
        timeseries_store=SimpleNamespace(),
        ssl_errors_store=SimpleNamespace(),
        stats_provider=lambda: {},
        runtime_services_builder=lambda: {},
        policy_state_builder=lambda proxy_id: ProxyPolicyState(proxy_id=proxy_id, policy_sha256=policy_sha, files=(policy_file,)),
        pac_state_builder=lambda proxy_id: None,
        current_policy_sha_reader=lambda: policy_sha,
    )
    runtime = ProxyRuntime(services=services)
    monkeypatch.setattr(runtime, "_publish_webcat_snapshot_for_policy_sync", lambda: (False, "snapshot publish failed"))

    result = runtime.sync_policy_state()

    assert result["ok"] is True
    assert result["changed"] is False
    assert result["degraded"] is True
    assert result["detail"] == "snapshot publish failed"

def test_proxy_policy_sync_skips_webcat_snapshot_when_policy_does_not_need_it(tmp_path, monkeypatch):
    ensure_proxy_runtime_import_path()

    from proxy.runtime import ProxyRuntime, ProxyRuntimeServices  # type: ignore
    from services.policy_materializer import MaterializedPolicyFile, ProxyPolicyState, calculate_policy_sha  # type: ignore

    policy_file = MaterializedPolicyFile(path=str(tmp_path / "30-webfilter.conf"), content="# webfilter\nhttp_access allow all\n")
    policy_sha = calculate_policy_sha((policy_file,))
    snapshot_calls: list[bool] = []

    services = ProxyRuntimeServices(
        controller=SimpleNamespace(),
        registry=SimpleNamespace(),
        revisions=SimpleNamespace(),
        certificate_bundles=SimpleNamespace(),
        adblock_artifacts=SimpleNamespace(compiled_dir=str(tmp_path / "adblock")),
        cert_manager=SimpleNamespace(),
        adblock_store=SimpleNamespace(),
        live_stats_store=SimpleNamespace(),
        diagnostic_store=SimpleNamespace(),
        timeseries_store=SimpleNamespace(),
        ssl_errors_store=SimpleNamespace(),
        stats_provider=lambda: {},
        runtime_services_builder=lambda: {},
        policy_state_builder=lambda proxy_id: ProxyPolicyState(proxy_id=proxy_id, policy_sha256=policy_sha, files=(policy_file,)),
        pac_state_builder=lambda proxy_id: None,
        current_policy_sha_reader=lambda: policy_sha,
    )
    runtime = ProxyRuntime(services=services)
    monkeypatch.setattr(runtime, "_publish_webcat_snapshot_for_policy_sync", lambda: snapshot_calls.append(True) or (False, "snapshot publish failed"))

    result = runtime.sync_policy_state()

    assert snapshot_calls == []
    assert result["ok"] is True
    assert result["changed"] is False
    assert result["degraded"] is False
    assert result["detail"] == "Proxy is already using the active policy materialization."
