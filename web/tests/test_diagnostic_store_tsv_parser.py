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


def test_split_tsv_fast_path_accepts_tab_separated_rows() -> None:
    _add_repo_paths()
    from services.diagnostic_store import _split_tsv  # type: ignore

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
    _add_repo_paths()
    from services.diagnostic_store import _split_tsv  # type: ignore

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
