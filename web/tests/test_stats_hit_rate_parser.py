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


def _write_log(tmp_path: Path, line: str) -> str:
    path = tmp_path / "access-observe.log"
    path.write_text(line + chr(10), encoding="utf-8")
    return str(path)


def test_parse_access_log_hit_rate_fast_path_accepts_tab_separated_rows(
    tmp_path,
) -> None:
    _add_repo_paths()
    from services.stats import parse_access_log_hit_rate  # type: ignore

    log = _write_log(
        tmp_path,
        "1710000000	0.0	10.0.0.5	GET	http://example.com/a	TCP_HIT/200	1234",
    )

    result = parse_access_log_hit_rate(log, max_lines=10)

    assert result == {"request_hit_ratio": 100.0, "byte_hit_ratio": 100.0}


def test_parse_access_log_hit_rate_fast_path_accepts_escaped_tab_rows(tmp_path) -> None:
    _add_repo_paths()
    from services.stats import parse_access_log_hit_rate  # type: ignore

    log = _write_log(
        tmp_path,
        "1710000001\t0.0\t10.0.0.6\tPOST\thttp://example.org/login\tTCP_MISS/200\t20",
    )

    result = parse_access_log_hit_rate(log, max_lines=10)

    assert result == {"request_hit_ratio": 0.0, "byte_hit_ratio": 0.0}
