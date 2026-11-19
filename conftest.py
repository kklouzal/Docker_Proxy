from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent
for _import_root in (_REPO_ROOT / "web", _REPO_ROOT / "docker"):
    if str(_import_root) not in sys.path:
        sys.path.insert(0, str(_import_root))

pytest_plugins = ("web.tests.live_test_helpers",)


@pytest.fixture(autouse=True)
def _reset_mysql_connect_circuits():
    """Keep the process-wide MySQL connect circuit from leaking across tests."""
    yield
    db = sys.modules.get("services.db")
    reset = getattr(db, "_reset_connect_circuits", None)
    if callable(reset):
        reset()


@pytest.fixture(autouse=True)
def _isolated_policy_last_known_good_dir(tmp_path_factory, monkeypatch):
    """Keep proxy policy mirrors out of the real durable volume path."""
    monkeypatch.setenv(
        "PROXY_POLICY_LKG_DIR",
        str(tmp_path_factory.mktemp("policy-last-known-good")),
    )


@pytest.fixture(autouse=True)
def _isolated_control_plane_ready_file(tmp_path_factory, monkeypatch):
    """Keep the agent readiness marker out of the real /run path."""
    monkeypatch.setenv(
        "PROXY_CONTROL_PLANE_READY_FILE",
        str(tmp_path_factory.mktemp("control-plane") / "ready"),
    )


@pytest.fixture(autouse=True)
def _isolate_mysql_test_configuration():
    """Undo ``configure_test_mysql_env`` side effects after each test.

    That helper purges runtime modules (so the test re-imports services against
    its private database) and points the process environment at that database.
    Left in place, later tests would mix collection-time and re-imported module
    objects and silently talk to the previous test's database, so results would
    depend on test order. Test modules import the helper as
    ``tests.mysql_test_utils`` (``web`` is the import base of the ``tests``
    package); restore whichever loaded copy exists.
    """
    environ_before = dict(os.environ)
    yield
    restored = False
    for name in ("tests.mysql_test_utils", "web.tests.mysql_test_utils"):
        helpers = sys.modules.get(name)
        if helpers is not None:
            restored = helpers.restore_runtime_modules() or restored
    if restored:
        os.environ.clear()
        os.environ.update(environ_before)
