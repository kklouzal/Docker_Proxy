import pytest

from .flask_test_helpers import login, redirect_query_params


pytestmark = pytest.mark.legacy_simulated


def test_monitoring_pages_link_back_to_observability_hub(app_module):
    c = app_module.app.test_client()
    login(c)

    response = c.get("/ssl-errors", follow_redirects=False)
    assert response.status_code in (301, 302, 303, 307, 308)
    assert redirect_query_params(response).get("pane") == ["ssl"]


def test_policy_pages_link_back_to_observability_hub(app_module):
    c = app_module.app.test_client()
    login(c)

    for path in ("/clamav", "/adblock", "/webfilter"):
        response = c.get(path)
        assert response.status_code == 200
        body = response.data.decode("utf-8", errors="replace")
        assert "Observability hub" in body
