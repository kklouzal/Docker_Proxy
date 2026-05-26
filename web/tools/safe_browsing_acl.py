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

from services.safe_browsing_v5 import SafeBrowsingLocalChecker  # noqa: E402

if TYPE_CHECKING:
    from collections.abc import Sequence

try:
    from tools.webcat_acl import _BlockedLogDb  # type: ignore
except Exception:  # pragma: no cover - logging is best-effort in helper startup
    _BlockedLogDb = None  # type: ignore


def _parse_line(line: str) -> tuple[str | None, str, str]:
    text = (line or "").strip()
    if not text:
        return None, "", ""
    parts = text.split()
    channel_id: str | None = None
    if parts and parts[0].isdigit():
        channel_id = parts.pop(0)
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


def _write(channel_id: str | None, ok: bool) -> None:
    if channel_id is not None:
        sys.stdout.write(f"{channel_id} {'OK' if ok else 'ERR'}\n")
    else:
        sys.stdout.write(f"{'OK' if ok else 'ERR'}\n")
    sys.stdout.flush()


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Squid external ACL helper for Google Safe Browsing v5 cached/local-list checks.",
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
    checker = SafeBrowsingLocalChecker()
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
            _write(channel_id, not fail_open)
            continue
        try:
            verdict = checker.check_url(url)
            unsafe = verdict.verdict == "unsafe"
            if unsafe and log_db is not None:
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
            _write(channel_id, unsafe)
        except Exception:
            _write(channel_id, not fail_open)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
