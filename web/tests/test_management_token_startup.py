from __future__ import annotations

import os
from pathlib import Path

import pytest

from .subprocess_test_utils import run_test_process

REPO_ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = REPO_ROOT / "docker" / "validate-management-token.sh"


@pytest.mark.parametrize(
    "token",
    [
        None,
        "",
        "   ",
        "change-me",
        " change-me ",
        "replace-with-a-long-random-token",
        " replace-with-a-long-random-token ",
        "replace_with_a_long_random_shared_token",
        " replace_with_a_long_random_shared_token ",
    ],
)
def test_management_token_validator_rejects_missing_and_public_placeholder(
    token: str | None,
) -> None:
    env = os.environ.copy()
    if token is None:
        env.pop("PROXY_MANAGEMENT_TOKEN", None)
    else:
        env["PROXY_MANAGEMENT_TOKEN"] = token

    result = run_test_process(
        ["sh", str(VALIDATOR)],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert "PROXY_MANAGEMENT_TOKEN must be set" in result.stderr
    if token and token.strip():
        assert token.strip() not in result.stderr


def test_management_token_validator_accepts_configured_token_without_output() -> None:
    env = {**os.environ, "PROXY_MANAGEMENT_TOKEN": "private-test-token"}

    result = run_test_process(
        ["sh", str(VALIDATOR)],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""
