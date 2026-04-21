from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
for candidate in (_ROOT / "web", _ROOT):
    if (candidate / "services").exists() and str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))
