from __future__ import annotations

import importlib
import os
from pathlib import Path

from .mysql_test_utils import apply_test_environment, configure_test_mysql_env, ensure_proxy_runtime_import_path


def import_proxy_runtime(
    tmp_path: Path,
    *,
    extra_env: dict[str, object] | None = None,
):
    ensure_proxy_runtime_import_path()

    apply_test_environment(
        {
            "PROXY_INSTANCE_ID": "edge-1",
            "DEFAULT_PROXY_ID": "edge-1",
            "DISABLE_BACKGROUND": "1",
            **{str(key): value for key, value in (extra_env or {}).items()},
        }
    )

    configure_test_mysql_env(tmp_path, secret_path=tmp_path / "flask_secret.key")

    import proxy.runtime as runtime_module  # type: ignore

    importlib.reload(runtime_module)
    return runtime_module