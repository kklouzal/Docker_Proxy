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


def test_parse_access_log_hit_rate_counts_real_first_full_row_when_tail_starts_at_zero(
    tmp_path,
) -> None:
    log = tmp_path / "access-observe.log"
    log.write_text(
        "1710000003	0.0	10.0.0.8	GET	http://example.com/hit	TCP_HIT/200	100\n"
        "1710000004	0.0	10.0.0.9	GET	http://example.com/miss	TCP_MISS/200	100\n",
        encoding="utf-8",
    )

    result = parse_access_log_hit_rate(str(log), max_lines=2)

    assert result == {"request_hit_ratio": 50.0, "byte_hit_ratio": 50.0}


def test_parse_access_log_hit_rate_keeps_full_row_when_byte_tail_starts_on_line_boundary(
    tmp_path,
) -> None:
    log = tmp_path / "access-observe.log"
    base_tailed_row = (
        "1710000005\t0.0\t10.0.0.12\tGET\thttp://example.com/boundary"
        "\tTCP_HIT/200\t100\n"
    )
    padding_len = 512 - len(base_tailed_row.encode("utf-8"))
    tailed_row = base_tailed_row.replace("boundary", "boundary" + ("a" * padding_len))
    assert len(tailed_row.encode("utf-8")) == 512
    filler_row = "0\t0\t0\tGET\thttp://example.com/filler\tTCP_MISS/200\t1\n"
    log.write_text(filler_row + tailed_row, encoding="utf-8")

    result = parse_access_log_hit_rate(str(log), max_lines=1)

    assert result == {"request_hit_ratio": 100.0, "byte_hit_ratio": 100.0}


def test_parse_access_log_hit_rate_drops_truncated_leading_row_from_byte_tail(
    tmp_path,
) -> None:
    log = tmp_path / "access-observe.log"
    long_timestamp = "1" * 1100
    log.write_text(
        f"{long_timestamp}	0.0	10.0.0.10	GET	http://example.com/hit	TCP_HIT/200	100\n"
        "1710000006	0.0	10.0.0.11	GET	http://example.com/miss	TCP_MISS/200	100\n",
        encoding="utf-8",
    )

    result = parse_access_log_hit_rate(str(log), max_lines=2)

    assert result == {"request_hit_ratio": 0.0, "byte_hit_ratio": 0.0}
