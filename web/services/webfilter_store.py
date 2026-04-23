from __future__ import annotations

import logging
import threading
import time
from subprocess import run
from typing import Dict, List, Optional, Set, Tuple

from services.db import column_exists, create_index_if_not_exists
from services.errors import public_error_message
from services.logutil import log_exception_throttled
from services.proxy_context import get_proxy_id
from services.webfilter_core import _DEFAULT_BLOCKED_CATEGORIES, _DEFAULT_SOURCE_URL, _env_int, _looks_like_host, _next_midnight_ts, _norm_domain, _now, _parent_domains, _parse_whitelist_lines, _whitelist_match, WebFilterStoreBase


logger = logging.getLogger(__name__)


class WebFilterStore(WebFilterStoreBase):
    TABLE_MAP: dict[str, str] = {
        "settings": "webfilter_settings",
        "meta": "webfilter_meta",
        "whitelist": "webfilter_whitelist",
        "blocked_log": "webfilter_blocked_log",
    }

    def __init__(
        self,
        squid_include_path: str = "/etc/squid/conf.d/30-webfilter.conf",
        whitelist_path: str = "/var/lib/squid-flask-proxy/webfilter_whitelist.txt",
    ):
        super().__init__(squid_include_path=squid_include_path, whitelist_path=whitelist_path)
        self._started = False
        self._lock = threading.Lock()

    def _migrate_defaults(self, conn) -> None:
        meta_table = self._table("meta")
        applied = conn.execute(f"SELECT v FROM {meta_table} WHERE k='defaults_v1_applied'").fetchone()
        if applied:
            return
        current_source = self._get(conn, "source_url", "")
        current_categories = self._get(conn, "blocked_categories", "")
        if not str(current_source or "").strip():
            self._set(conn, "source_url", _DEFAULT_SOURCE_URL)
        if not str(current_categories or "").strip():
            self._set(conn, "blocked_categories", ",".join(_DEFAULT_BLOCKED_CATEGORIES))
        self._set_meta(conn, "defaults_v1_applied", "1")

    def _init_extra_schema(self, conn) -> None:
        blocked_log_table = self._table("blocked_log")
        conn.execute(
            f"CREATE TABLE IF NOT EXISTS {blocked_log_table}("
            "id BIGINT PRIMARY KEY AUTO_INCREMENT, "
            "proxy_id VARCHAR(64) NOT NULL DEFAULT 'default', "
            "ts BIGINT NOT NULL, "
            "src_ip VARCHAR(64) NOT NULL, "
            "url TEXT NOT NULL, "
            "category VARCHAR(128) NOT NULL"
            ")"
        )
        if not column_exists(conn, blocked_log_table, "proxy_id"):
            conn.execute(f"ALTER TABLE {blocked_log_table} ADD COLUMN proxy_id VARCHAR(64) NOT NULL DEFAULT 'default' AFTER id")
        create_index_if_not_exists(
            conn,
            table_name=blocked_log_table,
            index_name=f"idx_{blocked_log_table}_proxy_ts",
            columns_sql="proxy_id, ts, id",
        )

    def list_blocked_log(self, limit: int = 200) -> List[Dict[str, object]]:
        try:
            self.init_db()
        except Exception:
            return []

        try:
            with self._connect() as conn:
                rows = conn.execute(
                    f"SELECT ts, src_ip, url, category FROM {self._table('blocked_log')} WHERE proxy_id=? ORDER BY ts DESC LIMIT ?",
                    (get_proxy_id(), int(limit)),
                ).fetchall()
                out: List[Dict[str, object]] = []
                for row in rows:
                    out.append(
                        {
                            "ts": int(row[0]) if row[0] is not None else 0,
                            "src_ip": str(row[1] or ""),
                            "url": str(row[2] or ""),
                            "category": str(row[3] or ""),
                        }
                    )
                return out
        except Exception:
            return []

    def set_settings(
        self,
        *,
        enabled: bool,
        source_url: str,
        blocked_categories: List[str],
    ) -> None:
        self.init_db()
        source = (source_url or "").strip()
        categories = [item.strip() for item in (blocked_categories or []) if (item or "").strip()]
        categories = self._resolve_category_aliases(categories)
        categories_csv = ",".join(sorted(set(categories)))

        with self._connect() as conn:
            previous_enabled = self._get(conn, "enabled", "0") == "1"
            previous_source = self._get_global_setting_conn(conn, "source_url", "")

            self._set(conn, "enabled", "1" if enabled else "0")
            self._set(conn, "source_url", source)
            self._set(conn, "blocked_categories", categories_csv)

            if source and source != previous_source:
                self._set_meta(conn, "refresh_requested", "1")
                self._set(conn, "next_run_ts", str(_next_midnight_ts(_now())))
            elif enabled and not previous_enabled:
                self._set_meta(conn, "refresh_requested", "1")
                self._set(conn, "next_run_ts", str(_next_midnight_ts(_now())))
            elif enabled:
                current_next = int(self._get(conn, "next_run_ts", "0") or 0)
                if current_next <= 0:
                    self._set(conn, "next_run_ts", str(_next_midnight_ts(_now())))

    def request_refresh_now(self) -> None:
        self.init_db()
        with self._connect() as conn:
            self._set_meta(conn, "refresh_requested", "1")

    def list_available_categories(self, limit: int = 5000) -> List[Tuple[str, int]]:
        try:
            with self._connect_webcat() as conn:
                rows = conn.execute(
                    "SELECT category, domains FROM webcat_categories ORDER BY category ASC LIMIT ?",
                    (int(limit),),
                ).fetchall()
            out: List[Tuple[str, int]] = []
            for row in rows:
                out.append((str(row[0]), int(row[1]) if row[1] is not None else 0))
            return out
        except Exception:
            return []

    def _lookup_domain_categories(self, domain: str) -> Set[str]:
        if not _looks_like_host(domain):
            return set()

        try:
            with self._connect_webcat() as conn:
                for candidate in _parent_domains(domain):
                    row = conn.execute(
                        "SELECT categories FROM webcat_domains WHERE domain=?",
                        (candidate,),
                    ).fetchone()
                    if row and row[0]:
                        return {category for category in str(row[0]).split("|") if category}
        except Exception:
            return set()
        return set()

    def test_domain(self, domain: str) -> Dict[str, object]:
        normalized = _norm_domain(domain)
        if not _looks_like_host(normalized):
            return {
                "ok": False,
                "domain": normalized,
                "verdict": "invalid",
                "reason": "Enter a domain like example.com",
                "whitelisted": False,
                "whitelist_match": "",
                "domain_categories": [],
                "matched_blocked": [],
                "blocked_by": "",
            }

        settings = self.get_settings()
        whitelist_match = _whitelist_match(normalized, self.get_whitelist_patterns())
        if whitelist_match:
            return {
                "ok": True,
                "domain": normalized,
                "verdict": "allowed",
                "reason": "Whitelisted",
                "whitelisted": True,
                "whitelist_match": whitelist_match,
                "domain_categories": [],
                "matched_blocked": [],
                "blocked_by": "",
            }

        if not settings.enabled:
            return {
                "ok": True,
                "domain": normalized,
                "verdict": "allowed",
                "reason": "Web filtering is disabled",
                "whitelisted": False,
                "whitelist_match": "",
                "domain_categories": [],
                "matched_blocked": [],
                "blocked_by": "",
            }

        blocked = set(self._resolve_category_aliases(list(settings.blocked_categories or [])))
        if not blocked:
            return {
                "ok": True,
                "domain": normalized,
                "verdict": "allowed",
                "reason": "No categories are currently blocked",
                "whitelisted": False,
                "whitelist_match": "",
                "domain_categories": [],
                "matched_blocked": [],
                "blocked_by": "",
            }

        categories = self._lookup_domain_categories(normalized)
        if not categories:
            return {
                "ok": True,
                "domain": normalized,
                "verdict": "allowed",
                "reason": "Domain not present in category database",
                "whitelisted": False,
                "whitelist_match": "",
                "domain_categories": [],
                "matched_blocked": [],
                "blocked_by": "",
            }

        matched = sorted(category for category in categories if category in blocked)
        verdict = "blocked" if matched else "allowed"
        reason = "Matched blocked category" if matched else "No blocked categories matched"
        return {
            "ok": True,
            "domain": normalized,
            "verdict": verdict,
            "reason": reason,
            "whitelisted": False,
            "whitelist_match": "",
            "domain_categories": sorted(categories),
            "matched_blocked": matched,
            "blocked_by": (matched[0] if matched else ""),
        }

    def _record_attempt(self, ok: bool, err: str) -> None:
        self.init_db()
        with self._connect() as conn:
            self._record_attempt_conn(conn, ok=ok, err=err)

    def _record_attempt_conn(self, conn, *, ok: bool, err: str) -> None:
        self._set(conn, "last_attempt", str(_now()))
        if ok:
            self._set(conn, "last_success", str(_now()))
            self._set(conn, "last_error", "")
        else:
            self._set(conn, "last_error", (err or "")[:500])

    def _set_next_run(self, ts: int) -> None:
        self.init_db()
        with self._connect() as conn:
            self._set_next_run_conn(conn, ts=int(ts))

    def _set_next_run_conn(self, conn, *, ts: int) -> None:
        self._set(conn, "next_run_ts", str(int(ts)))

    def _clear_refresh_requested(self) -> None:
        self.init_db()
        with self._connect() as conn:
            self._clear_refresh_requested_conn(conn)

    def _clear_refresh_requested_conn(self, conn) -> None:
        self._set_meta(conn, "refresh_requested", "0")

    def _refresh_requested(self) -> bool:
        self.init_db()
        with self._connect() as conn:
            return self._refresh_requested_conn(conn)

    def _refresh_requested_conn(self, conn) -> bool:
        return self._get_meta(conn, "refresh_requested", "0") == "1"

    def _run_build(self, source_url: str) -> Tuple[bool, str]:
        if not source_url:
            return False, "source_url is empty"

        try:
            proc = run(
                [
                    "python3",
                    "/app/tools/webcat_build.py",
                    "--source-url",
                    source_url,
                    "--download-to",
                    "/var/lib/squid-flask-proxy/webcat/source",
                ],
                capture_output=True,
                timeout=300,
            )
            if proc.returncode != 0:
                stdout = (proc.stdout or b"").decode("utf-8", errors="replace")
                stderr = (proc.stderr or b"").decode("utf-8", errors="replace")
                return False, (stderr or stdout or f"builder failed rc={proc.returncode}").strip()
            return True, ""
        except Exception as exc:
            logger.exception("webfilter build failed")
            return False, public_error_message(
                exc,
                default="Build failed. Check server logs for details.",
                max_len=400,
            )

    def start_background(self) -> None:
        with self._lock:
            if self._started:
                return
            self._started = True
            self.init_db()
            thread = threading.Thread(target=self._loop, name="webfilter-updater", daemon=True)
            thread.start()

    def _loop(self) -> None:
        disabled_sleep = float(_env_int("WEBFILTER_DISABLED_POLL_SECONDS", 60, minimum=5, maximum=3600))
        enabled_sleep = float(_env_int("WEBFILTER_ENABLED_POLL_SECONDS", 300, minimum=5, maximum=3600))
        error_sleep = float(_env_int("WEBFILTER_ERROR_BACKOFF_SECONDS", 30, minimum=5, maximum=300))
        while True:
            sleep_seconds = enabled_sleep
            try:
                self.init_db()
                with self._connect() as conn:
                    source_url = self._get_global_setting_conn(conn, "source_url", _DEFAULT_SOURCE_URL)
                    next_ts = int(self._get_global_setting_conn(conn, "next_run_ts", "0") or 0)
                    refresh = self._refresh_requested_conn(conn)
                    if next_ts <= 0:
                        next_ts = _next_midnight_ts(_now())
                        self._set_next_run_conn(conn, ts=next_ts)

                if not source_url:
                    sleep_seconds = disabled_sleep
                    time.sleep(sleep_seconds)
                    continue

                now = _now()
                if refresh:
                    do_build = True
                    next_after = _next_midnight_ts(now)
                    sleep_seconds = 5.0
                else:
                    do_build = now >= int(next_ts or 0)
                    next_after = _next_midnight_ts(now + 60)
                    if not do_build:
                        remaining = max(5, int(next_ts or 0) - now) if int(next_ts or 0) > 0 else int(enabled_sleep)
                        sleep_seconds = min(enabled_sleep, float(remaining))

                if do_build:
                    ok, err = self._run_build(source_url)
                    with self._connect() as conn:
                        self._record_attempt_conn(conn, ok=ok, err=err)
                        if refresh:
                            self._clear_refresh_requested_conn(conn)
                        self._set_next_run_conn(conn, ts=next_after)
                    sleep_seconds = 5.0
            except Exception:
                log_exception_throttled(
                    logger,
                    "webfilter_store.loop",
                    interval_seconds=30,
                    message="webfilter background loop iteration failed",
                )
                sleep_seconds = error_sleep
            time.sleep(sleep_seconds)


_store: Optional[WebFilterStore] = None
_store_lock = threading.Lock()


def get_webfilter_store() -> WebFilterStore:
    global _store
    if _store is not None:
        return _store
    with _store_lock:
        if _store is None:
            _store = WebFilterStore()
            _store.init_db()
        return _store


__all__ = [
    "WebFilterStore",
    "get_webfilter_store",
    "_norm_domain",
    "_looks_like_host",
    "_parse_whitelist_lines",
    "_whitelist_match",
]
