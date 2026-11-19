from __future__ import annotations

import math
import random
import threading
import time
import weakref
from dataclasses import dataclass, field

from services.db import add_mysql_recovery_listener
from services.runtime_helpers import env_float

# Live backoffs, so a MySQL reconnect can release them all at once instead of
# each writer waiting out its remaining (up to *_BACKOFF_MAX_SECONDS) delay.
_LIVE_BACKOFFS: weakref.WeakValueDictionary[int, DatabaseWriteBackoff] = (
    weakref.WeakValueDictionary()
)
# Writers create backoffs on their own threads while the probe thread releases
# them; inserting during that iteration would raise "changed size".
_LIVE_BACKOFFS_LOCK = threading.Lock()


@dataclass
class DatabaseWriteBackoff:
    """Small exponential backoff helper for background observability DB writes."""

    base_seconds: float = 5.0
    max_seconds: float = 60.0
    jitter_ratio: float = 0.2
    _failures: int = 0
    _next_attempt_at: float = 0.0
    _rand: object = field(default=random.random, repr=False)  # noqa: S311

    def __post_init__(self) -> None:
        with _LIVE_BACKOFFS_LOCK:
            _LIVE_BACKOFFS[id(self)] = self

    @classmethod
    def from_env(
        cls,
        prefix: str,
        *,
        default_base: float = 5.0,
        default_max: float = 60.0,
        default_jitter: float = 0.2,
    ) -> DatabaseWriteBackoff:
        base = env_float(
            f"{prefix}_BACKOFF_INITIAL_SECONDS",
            default_base,
            minimum=0.25,
            maximum=300.0,
        )
        maximum = env_float(
            f"{prefix}_BACKOFF_MAX_SECONDS",
            default_max,
            minimum=base,
            maximum=900.0,
        )
        jitter = env_float(
            f"{prefix}_BACKOFF_JITTER_RATIO",
            default_jitter,
            minimum=0.0,
            maximum=1.0,
        )
        return cls(base_seconds=base, max_seconds=maximum, jitter_ratio=jitter)

    def can_attempt(self, now: float | None = None) -> bool:
        return (
            float(now if now is not None else time.monotonic()) >= self._next_attempt_at
        )

    @property
    def failures(self) -> int:
        return self._failures

    @property
    def next_attempt_at(self) -> float:
        return self._next_attempt_at

    def record_success(self) -> None:
        self._failures = 0
        self._next_attempt_at = 0.0

    def record_failure(self, now: float | None = None) -> float:
        now_f = float(now if now is not None else time.monotonic())
        exponent = max(0, min(self._failures, 20))
        delay = min(self.max_seconds, self.base_seconds * (2**exponent))
        self._failures += 1
        if self.jitter_ratio > 0.0 and delay > 0.0:
            try:
                rand_value = float(self._rand())  # type: ignore[misc]
            except Exception:
                rand_value = 0.5
            if not math.isfinite(rand_value) or not 0.0 <= rand_value <= 1.0:
                rand_value = 0.5
            # Apply symmetric jitter without violating the configured maximum.
            jitter = (rand_value * 2.0 - 1.0) * self.jitter_ratio * delay
            delay = min(self.max_seconds, max(0.0, delay + jitter))
        self._next_attempt_at = now_f + delay
        return delay


def _release_backoffs_after_mysql_recovery() -> None:
    # Keep the failure count so a flapping database still backs off; only the
    # pending wait is released. A lost race with the owner thread at worst
    # defers one attempt by a single backoff step.
    with _LIVE_BACKOFFS_LOCK:
        backoffs = list(_LIVE_BACKOFFS.values())
    for backoff in backoffs:
        backoff._next_attempt_at = 0.0


add_mysql_recovery_listener(_release_backoffs_after_mysql_recovery)


def stagger_delay_from_env(
    env_name: str, default_seconds: float, *, maximum: float
) -> float:
    """Return a random startup/cadence stagger delay bounded by an env knob."""
    span = env_float(env_name, default_seconds, minimum=0.0, maximum=maximum)
    if span <= 0.0:
        return 0.0
    try:
        delay = float(random.uniform(0.0, span))  # noqa: S311
    except Exception:
        return 0.0
    if not math.isfinite(delay) or not 0.0 <= delay <= span:
        return 0.0
    return delay
