"""Compatibility shim for proxy/runtime imports.

The canonical Squid controller implementation lives in `services.squid_core`.
Keep this module as a thin re-export layer for callers using the historical
runtime-specific import path.
"""

from services.squid_core import SquidController

__all__ = ["SquidController"]
