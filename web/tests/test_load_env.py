from __future__ import annotations

import json
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_env_probe(app_env_path: Path) -> dict[str, str | None]:
    script = (REPO_ROOT / "docker" / "load-env.sh").read_text(encoding="utf-8")
    script = script.replace("/config/app.env", str(app_env_path))
    probe = f"""
{shlex.quote(sys.executable)} - <<'PY'
import json
import os

keys = [
    "SPACED_KEY",
    "QUOTED_HASH",
    "SINGLE_QUOTED",
    "TAB_EXPORT",
    "URL_FRAGMENT",
    "EMPTY",
]
print(json.dumps({{key: os.environ.get(key) for key in keys}}, sort_keys=True))
PY
"""
    result = subprocess.run(
        ["/bin/sh", "-c", script + probe],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def test_load_env_accepts_common_env_file_syntax_without_sourcing(
    tmp_path: Path,
) -> None:
    app_env = tmp_path / "app.env"
    app_env.write_bytes(
        b"\n".join(
            [
                b"# comment-only line",
                b" SPACED_KEY = unquoted value # inline comment",
                b'QUOTED_HASH="value # not a comment"',
                b"SINGLE_QUOTED='  padded # literal  '",
                b"export\tTAB_EXPORT=tabbed\r",
                b"URL_FRAGMENT=https://example.test/path#fragment",
                b"EMPTY =   ",
            ],
        )
        + b"\n",
    )

    env = _load_env_probe(app_env)

    assert env == {
        "SPACED_KEY": "unquoted value",
        "QUOTED_HASH": "value # not a comment",
        "SINGLE_QUOTED": "  padded # literal  ",
        "TAB_EXPORT": "tabbed",
        "URL_FRAGMENT": "https://example.test/path#fragment",
        "EMPTY": "",
    }


@pytest.mark.parametrize(
    ("content", "line_number", "diagnostic"),
    [
        (b"GOOD=ok\nnot an assignment\n", 2, "expected environment assignment"),
        (b"BAD-NAME=secret-value\n", 1, "invalid environment variable name"),
        (b'GOOD="unterminated secret\n', 1, "unterminated quoted value"),
        (b"GOOD='unterminated secret\n", 1, "unterminated quoted value"),
    ],
)
def test_load_env_rejects_malformed_input_without_echoing_values(
    tmp_path: Path,
    content: bytes,
    line_number: int,
    diagnostic: str,
) -> None:
    app_env = tmp_path / "app.env"
    app_env.write_bytes(content)
    script = (REPO_ROOT / "docker" / "load-env.sh").read_text(encoding="utf-8")
    script = script.replace("/config/app.env", str(app_env))

    result = subprocess.run(
        ["/bin/sh", "-c", script],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert f"line {line_number}: {diagnostic}" in result.stderr
    assert "secret" not in result.stderr
    assert result.stdout == ""
