from __future__ import annotations

import sys
from pathlib import Path


def _add_repo_paths() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    web_root = repo_root / "web"
    for path in (repo_root, web_root):
        path_str = str(path)
        if path_str not in sys.path:
            sys.path.insert(0, path_str)


_add_repo_paths()
from services.diagnostic_store import _split_tsv  # type: ignore  # noqa: E402


def test_split_tsv_fast_path_accepts_tab_separated_rows() -> None:
    row = _split_tsv(
        "1710000000	15	10.0.0.5	GET	http://example.com/a	TCP_HIT/200	1234"
    )

    assert row == [
        "1710000000",
        "15",
        "10.0.0.5",
        "GET",
        "http://example.com/a",
        "TCP_HIT/200",
        "1234",
    ]


def test_split_tsv_fast_path_accepts_escaped_tab_rows() -> None:
    row = _split_tsv(
        "1710000001\t20\t10.0.0.6\tPOST\thttp://example.org/login\tTCP_MISS/200\t42"
    )

    assert row == [
        "1710000001",
        "20",
        "10.0.0.6",
        "POST",
        "http://example.org/login",
        "TCP_MISS/200",
        "42",
    ]


def test_split_tsv_escaped_tabs_preserve_quoted_fields() -> None:
    row = _split_tsv(
        r'1710000002\t25\t10.0.0.7\tGET\t"http://example.net/a\tliteral"\tTCP_HIT/200\t84'
    )

    assert row == [
        "1710000002",
        "25",
        "10.0.0.7",
        "GET",
        r"http://example.net/a\tliteral",
        "TCP_HIT/200",
        "84",
    ]
