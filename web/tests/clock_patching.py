"""Module-local clock patching for tests.

Patching ``module.time.sleep`` mutates the process-wide ``time`` module, so the
fake also reaches unrelated threads (background workers, pytest-timeout) and
other modules. ``patch_module_clock`` instead rebinds only ``module.time`` to a
private stand-in that serves the given overrides and delegates every other
attribute to the real ``time`` module. ``monkeypatch`` restores the module's
original binding at teardown.
"""

from __future__ import annotations

import importlib
import time as _real_time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from types import ModuleType


class _ModuleClock:
    """Stand-in for one module's ``time`` binding; overrides win, else real."""

    def __init__(self, overrides: dict[str, object]) -> None:
        self.__dict__.update(overrides)

    def __getattr__(self, name: str) -> object:
        return getattr(_real_time, name)


def patch_module_clock(
    monkeypatch, *modules: ModuleType | str, **overrides: object
) -> None:
    """Install ``overrides`` on each of ``modules``' own ``time`` binding.

    Each module is a module object or a dotted import path, resolved at call
    time like ``monkeypatch.setattr`` string targets. Pass every module whose
    code must observe the fake; they share the same override objects.
    Repeated calls for the same module within one test merge, later overrides
    winning.
    """
    if not modules:
        msg = "patch_module_clock needs at least one module"
        raise TypeError(msg)
    for module in modules:
        resolved = (
            importlib.import_module(module) if isinstance(module, str) else module
        )
        current = resolved.time
        if current is not _real_time and not isinstance(current, _ModuleClock):
            msg = f"{resolved.__name__}.time is not the time module"
            raise TypeError(msg)
        merged = dict(vars(current)) if isinstance(current, _ModuleClock) else {}
        merged.update(overrides)
        monkeypatch.setattr(resolved, "time", _ModuleClock(merged))
