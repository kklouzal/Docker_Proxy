from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

from .mysql_test_utils import REPO_ROOT, WEB_ROOT, configure_test_mysql_env


def ensure_proxy_runtime_import_path() -> None:
    for path in (str(REPO_ROOT), str(WEB_ROOT)):
        if path not in sys.path:
            sys.path.insert(0, path)


def import_proxy_runtime(
    tmp_path: Path,
    *,
    extra_env: dict[str, object] | None = None,
):
    ensure_proxy_runtime_import_path()

    os.environ["PROXY_INSTANCE_ID"] = "edge-1"
    os.environ["DEFAULT_PROXY_ID"] = "edge-1"
    os.environ["DISABLE_BACKGROUND"] = "1"

    for key, value in (extra_env or {}).items():
        os.environ[str(key)] = str(value)

    configure_test_mysql_env(tmp_path, secret_path=tmp_path / "flask_secret.key")

    import proxy.runtime as runtime_module  # type: ignore

    importlib.reload(runtime_module)
    return runtime_module