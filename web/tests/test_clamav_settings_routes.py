from __future__ import annotations

from .admin_route_test_utils import csrf_token, load_admin_app, login_client


def test_clamav_settings_success_reports_async_apply_not_proven(
    monkeypatch,
    tmp_path,
) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/clamav")

    response = client.post(
        "/clamav/settings",
        data={
            "csrf_token": token,
            "clamav_fail_mode": "open",
            "file_security_preset": "balanced",
            "file_security_scan_downloads": "on",
            "file_security_scan_uploads": "on",
        },
        follow_redirects=False,
    )

    assert response.status_code in {302, 303}
    assert "settings_ok=1" in response.location
    assert "Revision+1+saved" in response.location
    assert "operation+%231" in response.location

    operations = loaded.operation_ledger.list_operations("default", limit=10)
    assert len(operations) == 1
    operation = operations[0]
    assert operation.status == "pending"
    assert operation.operation_type == "config_apply"
    assert operation.target_kind == "config_revision"
    assert operation.target_ref == "1"

    page = client.get(response.location)
    assert page.status_code == 200
    text = page.get_data(as_text=True)
    assert "ClamAV/c-icap settings were validated and applied" not in text
    assert "Apply queued" in text
    assert "ClamAV/c-icap settings were validated and saved" in text
    assert "runtime application is queued asynchronously" in text
    assert "not proven yet" in text
    assert "Revision 1 saved; applying asynchronously as operation #1." in text


def test_clamav_settings_rejected_input_is_kept_for_correction(
    monkeypatch,
    tmp_path,
) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)
    token = csrf_token(client, "/clamav")

    response = client.post(
        "/clamav/settings",
        data={
            "csrf_token": token,
            "clamav_fail_mode": "closed",
            "file_security_preset": "balanced",
            "file_security_scan_uploads": "on",
            "file_security_max_download_size": "lots",
            "file_security_risky_extensions": "exe msi",
        },
        follow_redirects=False,
    )

    # Rendered in place (no redirect) so every submitted value survives.
    assert response.status_code == 200
    text = response.get_data(as_text=True)
    assert "Settings failed" in text
    assert "Maximum download size must be" in text
    assert 'value="lots"' in text
    assert 'value="exe msi"' in text
    assert '<option value="closed" selected>' in text
    assert loaded.operation_ledger.list_operations("default", limit=10) == []
