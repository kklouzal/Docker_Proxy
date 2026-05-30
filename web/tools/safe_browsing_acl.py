#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import pathlib
import sys
from typing import TYPE_CHECKING

HERE = pathlib.Path(pathlib.Path(__file__).parent).resolve()
APP_ROOT = pathlib.Path(os.path.join(HERE, "..")).resolve()
if APP_ROOT not in sys.path:
    sys.path.insert(0, APP_ROOT)

import contextlib  # noqa: E402

from services.helper_runtime import (  # noqa: E402
    HelperStats,
    helper_event,
    split_acl_channel,
    write_acl_response,
)
from services.safe_browsing_v5 import SafeBrowsingLocalChecker  # noqa: E402

if TYPE_CHECKING:
    from collections.abc import Sequence

try:
    from tools.webcat_acl import _BlockedLogDb  # type: ignore
except Exception:  # pragma: no cover - logging is best-effort in helper startup
    _BlockedLogDb = None  # type: ignore


def _parse_line(line: str) -> tuple[str | None, str, str]:
    channel_id, parts = split_acl_channel(line)
    if not parts:
        return None, "", ""
    # external_acl_type passes %SRC %DST %URI. Prefer URI; fall back to DST
    # when Squid supplies a placeholder for CONNECT-style traffic.
    if len(parts) >= 3:
        url = parts[2]
        if url in {"", "-"}:
            url = parts[1]
        return channel_id, parts[0], url
    if len(parts) >= 2:
        return channel_id, parts[0], parts[1]
    if parts:
        return channel_id, "", parts[0]
    return channel_id, "", ""


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Squid external ACL helper for Google Safe Browsing v5 cached/local-list checks.",
    )
    ap.add_argument(
        "--list",
        dest="selected_lists",
        action="append",
        default=[],
        help="Safe Browsing hash list to enforce. Repeat for each selected list.",
    )
    ap.add_argument(
        "--fail",
        choices=["open", "closed"],
        default=os.environ.get("SAFE_BROWSING_FAIL", "open"),
    )
    ap.add_argument(
        "--log-max-rows",
        type=int,
        default=int(os.environ.get("WEBFILTER_LOG_MAX_ROWS", "5000")),
    )
    args = ap.parse_args(list(argv) if argv is not None else None)
    fail_open = args.fail == "open"
    checker = SafeBrowsingLocalChecker(selected_lists=args.selected_lists or None)
    stats = HelperStats("safe_browsing_acl")
    helper_event(
        "safe_browsing_acl",
        "startup",
        fail_mode=args.fail,
        selected_lists=",".join(args.selected_lists or []),
    )
    log_db = (
        _BlockedLogDb(max_rows=int(args.log_max_rows))
        if _BlockedLogDb is not None
        else None
    )
    if log_db is not None:
        log_db.start()
    for raw in sys.stdin:
        channel_id, src_ip, url = _parse_line(raw)
        if not url:
            stats.increment("parse_miss")
            write_acl_response(channel_id, not fail_open)
            stats.emit_if_due()
            continue
        try:
            verdict = checker.check_url(url)
            unsafe = verdict.verdict == "unsafe"
            stats.increment("requests")
            if unsafe and log_db is not None:
                stats.increment("unsafe")
                category = "google-safe-browsing"
                if verdict.threat_type:
                    category += "/" + verdict.threat_type.lower().replace("_", "-")
                with contextlib.suppress(Exception):
                    log_db.insert(
                        ts=int(__import__("time").time()),
                        src_ip=src_ip,
                        url=url,
                        category=category,
                    )
            write_acl_response(channel_id, unsafe)
        except Exception:
            stats.increment("errors")
            write_acl_response(channel_id, not fail_open)
        stats.emit_if_due()
    stats.emit_if_due(force=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
