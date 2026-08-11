from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent
for _import_root in (_REPO_ROOT / "web", _REPO_ROOT / "docker"):
    if str(_import_root) not in sys.path:
        sys.path.insert(0, str(_import_root))

pytest_plugins = ("web.tests.live_test_helpers",)
