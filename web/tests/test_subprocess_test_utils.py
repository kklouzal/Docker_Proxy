from __future__ import annotations

import subprocess
import sys

import pytest

from .subprocess_test_utils import (
    DEFAULT_TEST_PROCESS_TIMEOUT_SECONDS,
    check_test_process_output,
    run_test_process,
)


def test_run_test_process_applies_default_deadline(monkeypatch) -> None:
    observed = {}

    def fake_run(args, **kwargs):
        observed.update(kwargs)
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    run_test_process(["child"], check=True, text=True)

    assert observed == {
        "timeout": DEFAULT_TEST_PROCESS_TIMEOUT_SECONDS,
        "check": True,
        "text": True,
    }


def test_run_test_process_allows_explicit_larger_deadline(monkeypatch) -> None:
    observed = {}

    def fake_run(args, **kwargs):
        observed.update(kwargs)
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    run_test_process(["child"], timeout=120)

    assert observed["timeout"] == 120


def test_check_test_process_output_applies_default_deadline(monkeypatch) -> None:
    observed = {}

    def fake_check_output(args, **kwargs):
        observed.update(kwargs)
        return "output"

    monkeypatch.setattr(subprocess, "check_output", fake_check_output)

    assert check_test_process_output(["child"], text=True) == "output"
    assert observed == {
        "timeout": DEFAULT_TEST_PROCESS_TIMEOUT_SECONDS,
        "text": True,
    }


def test_timeout_error_identifies_the_child_command() -> None:
    command = [sys.executable, "-c", "import time; time.sleep(1)"]

    with pytest.raises(subprocess.TimeoutExpired) as error:
        run_test_process(command, timeout=0.01, capture_output=True, text=True)

    assert error.value.cmd == command
    assert error.value.timeout == pytest.approx(0.01)
