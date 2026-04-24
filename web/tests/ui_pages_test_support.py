import pytest

from .flask_test_helpers import import_local_app_module
from .route_test_support import install_common_ui_test_doubles


@pytest.fixture()
def app_module(monkeypatch):
    app_module = import_local_app_module()
    return install_common_ui_test_doubles(monkeypatch, app_module)
