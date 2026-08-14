from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Sequence

DEFAULT_TEST_PROCESS_TIMEOUT_SECONDS = 30


def run_test_process(
    args: Sequence[str],
    *,
    timeout: float = DEFAULT_TEST_PROCESS_TIMEOUT_SECONDS,
    **kwargs: Any,
) -> subprocess.CompletedProcess[Any]:
    """Run a deterministic test child with a finite, attributable deadline."""
    return subprocess.run(args, timeout=timeout, **kwargs)


def check_test_process_output(
    args: Sequence[str],
    *,
    timeout: float = DEFAULT_TEST_PROCESS_TIMEOUT_SECONDS,
    **kwargs: Any,
) -> Any:
    """Return test-child output while enforcing the suite's default deadline."""
    return subprocess.check_output(args, timeout=timeout, **kwargs)
