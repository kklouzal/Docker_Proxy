from __future__ import annotations

from typing import TYPE_CHECKING

from services.stats import parse_access_log_hit_rate

if TYPE_CHECKING:
    from pathlib import Path


def _write_log(tmp_path: Path, line: str) -> str:
    path = tmp_path / "access-observe.log"
    path.write_text(line + chr(10), encoding="utf-8")
    return str(path)


def test_parse_access_log_hit_rate_fast_path_accepts_tab_separated_rows(
    tmp_path,
) -> None:
    log = _write_log(
        tmp_path,
        "1710000000	0.0	10.0.0.5	GET	http://example.com/a	TCP_HIT/200	1234",
    )

    result = parse_access_log_hit_rate(log, max_lines=10)

    assert result == {"request_hit_ratio": 100.0, "byte_hit_ratio": 100.0}


def test_parse_access_log_hit_rate_fast_path_accepts_escaped_tab_rows(tmp_path) -> None:
    log = _write_log(
        tmp_path,
        r"1710000001\t0.0\t10.0.0.6\tPOST\thttp://example.org/login\tTCP_MISS/200\t20",
    )

    result = parse_access_log_hit_rate(log, max_lines=10)

    assert result == {"request_hit_ratio": 0.0, "byte_hit_ratio": 0.0}


def test_parse_access_log_hit_rate_escaped_tabs_preserve_quoted_fields(tmp_path) -> None:
    log = _write_log(
        tmp_path,
        r'1710000002\t0.0\t10.0.0.7\tGET\t"http://example.net/a\tliteral"\tTCP_HIT/200\t40',
    )

    result = parse_access_log_hit_rate(log, max_lines=10)

    assert result == {"request_hit_ratio": 100.0, "byte_hit_ratio": 100.0}
