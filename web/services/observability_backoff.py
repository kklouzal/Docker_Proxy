from __future__ import annotations

import random
import time
from dataclasses import dataclass, field

from services.runtime_helpers import env_float


@dataclass
class DatabaseWriteBackoff:
    """Small exponential backoff helper for background observability DB writes."""

    base_seconds: float = 5.0
    max_seconds: float = 60.0
    jitter_ratio: float = 0.2
    _failures: int = 0
    _next_attempt_at: float = 0.0
    _rand: object = field(default=random.random, repr=False)  # noqa: S311

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
        return float(now if now is not None else time.monotonic()) >= self._next_attempt_at

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
            # Apply symmetric jitter and clamp at zero.
            jitter = (rand_value * 2.0 - 1.0) * self.jitter_ratio * delay
            delay = max(0.0, delay + jitter)
        self._next_attempt_at = now_f + delay
        return delay


def stagger_delay_from_env(env_name: str, default_seconds: float, *, maximum: float) -> float:
    """Return a random startup/cadence stagger delay bounded by an env knob."""
    span = env_float(env_name, default_seconds, minimum=0.0, maximum=maximum)
    if span <= 0.0:
        return 0.0
    try:
        return random.uniform(0.0, span)  # noqa: S311
    except Exception:
        return 0.0
