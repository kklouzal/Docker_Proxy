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


def test_parse_access_log_line_fast_path_accepts_tab_separated_liveui_rows() -> None:
    _add_repo_paths()
    from services.live_stats import _parse_access_log_line  # type: ignore

    row = _parse_access_log_line("1710000000\t0.0\t10.0.0.5\tGET\thttp://example.com/a\tTCP_HIT/200\t1234")

    assert row == (1710000000, "10.0.0.5", "TCP_HIT/200", 1234, "example.com", "GET")


def test_parse_access_log_line_fast_path_accepts_escaped_tab_rows() -> None:
    _add_repo_paths()
    from services.live_stats import _parse_access_log_line  # type: ignore

    row = _parse_access_log_line("1710000001\\t0.0\\t10.0.0.6\\tPOST\\thttp://example.org/login\\tTCP_MISS/200\\t42")

    assert row == (1710000001, "10.0.0.6", "TCP_MISS/200", 42, "example.org", "POST")
