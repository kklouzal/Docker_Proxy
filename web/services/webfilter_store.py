from __future__ import annotations

import logging
import threading
import time
from subprocess import run
from typing import ClassVar

from services.db import DATABASE_ERRORS
from services.errors import public_error_message
from services.logutil import log_database_unavailable, log_exception_throttled
from services.proxy_context import get_proxy_id
from services.safe_browsing_v5 import (
    DEFAULT_SAFE_BROWSING_LISTS,
    SafeBrowsingLocalChecker,
    SafeBrowsingStore,
)
from services.webfilter_core import (
    _DEFAULT_SOURCE_URL,
    _GLOBAL_SCOPE,
    WebFilterStoreBase,
    _env_int,
    _looks_like_host,
    _next_midnight_ts,
    _norm_domain,
    _now,
    _parent_domains,
    _parse_whitelist_lines,
    _whitelist_match,
    validate_source_url,
)

logger = logging.getLogger(__name__)


class WebFilterStore(WebFilterStoreBase):
    TABLE_MAP: ClassVar[dict[str, str]] = {
        "settings": "webfilter_settings",
        "meta": "webfilter_meta",
        "whitelist": "webfilter_whitelist",
        "blocked_log": "webfilter_blocked_log",
    }

    def __init__(
        self,
        squid_include_path: str = "/etc/squid/conf.d/30-webfilter.conf",
        whitelist_path: str = "/var/lib/squid-flask-proxy/webfilter_whitelist.txt",
    ) -> None:
        super().__init__(
            squid_include_path=squid_include_path,
            whitelist_path=whitelist_path,
        )
        self._started = False
        self._lock = threading.Lock()

    def _init_extra_schema(self, conn) -> None:
        blocked_log_table = self._table("blocked_log")
        conn.execute(
            f"CREATE TABLE IF NOT EXISTS {blocked_log_table}("
            "id BIGINT PRIMARY KEY AUTO_INCREMENT, "
            "proxy_id VARCHAR(64) NOT NULL DEFAULT 'default', "
            "ts BIGINT NOT NULL, "
            "src_ip VARCHAR(64) NOT NULL, "
            "url TEXT NOT NULL, "
            "category VARCHAR(128) NOT NULL, "
            f"KEY idx_{blocked_log_table}_proxy_ts (proxy_id, ts, id)"
            ")",
        )

    def list_blocked_log(self, limit: int = 200) -> list[dict[str, object]]:
        try:
            self.init_db()
        except Exception:
            return []

        try:
            with self._connect() as conn:
                rows = conn.execute(
                    f"SELECT ts, src_ip, url, category FROM {self._table('blocked_log')} WHERE proxy_id=%s ORDER BY ts DESC LIMIT %s",
                    (get_proxy_id(), int(limit)),
                ).fetchall()
                out: list[dict[str, object]] = [
                    {
                        "ts": int(row[0]) if row[0] is not None else 0,
                        "src_ip": str(row[1] or ""),
                        "url": str(row[2] or ""),
                        "category": str(row[3] or ""),
                    }
                    for row in rows
                ]
                return out
        except Exception:
            return []

    def set_settings(
        self,
        *,
        enabled: bool,
        source_url: str,
        blocked_categories: list[str],
        source_provider: str = "auto",
        safe_browsing_enabled: bool = False,
        safe_browsing_api_key: str = "",
        safe_browsing_lists: list[str] | None = None,
    ) -> None:
        self.init_db()
        source_candidate = (source_url or "").strip()
        provider = (source_provider or "auto").strip().lower()
        if provider not in {"auto", "ut1", "category-dir", "csv"}:
            provider = "auto"
        categories = [
            item.strip() for item in (blocked_categories or []) if (item or "").strip()
        ]
        categories = self._resolve_category_aliases(categories)
        categories_csv = ",".join(sorted(set(categories)))
        if safe_browsing_lists is None:
            gsb_lists = SafeBrowsingStore.normalize_lists(DEFAULT_SAFE_BROWSING_LISTS)
        else:
            gsb_lists = SafeBrowsingStore.selected_lists(safe_browsing_lists)
        if safe_browsing_enabled and not gsb_lists:
            msg = (
                "At least one valid Google Safe Browsing threat list is required "
                "when Safe Browsing is enabled."
            )
            raise ValueError(msg)
        if not gsb_lists:
            gsb_lists = SafeBrowsingStore.normalize_lists(DEFAULT_SAFE_BROWSING_LISTS)

        with self._connect() as conn:
            previous_enabled = self._get(conn, "enabled", "0") == "1"
            previous_source = self._get_global_setting_conn(conn, "source_url", "")
            previous_provider = self._get_global_setting_conn(
                conn,
                "source_provider",
                "auto",
            )

            previous_safe_browsing_enabled = (
                self._get_global_setting_conn(conn, "safe_browsing_enabled", "0") == "1"
            )
            previous_safe_browsing_api_key = self._get_global_setting_conn(
                conn,
                "safe_browsing_api_key",
                "",
            )
            previous_safe_browsing_lists = SafeBrowsingStore.normalize_lists(
                self._get_global_setting_conn(conn, "safe_browsing_lists", "")
            )

            category_build_needed = self._category_build_needed_conn(
                conn,
                override_proxy_id=get_proxy_id(),
                override_enabled=enabled,
                override_blocked_categories=categories_csv,
            )
            source = (
                validate_source_url(source_candidate)
                if source_candidate and (enabled or category_build_needed)
                else source_candidate
            )

            self._set(conn, "enabled", "1" if enabled else "0")
            self._set(conn, "source_url", source)
            self._set(conn, "source_provider", provider)
            self._set(conn, "blocked_categories", categories_csv)
            self._set(
                conn,
                "safe_browsing_enabled",
                "1" if safe_browsing_enabled else "0",
            )
            self._set(
                conn,
                "safe_browsing_api_key",
                (safe_browsing_api_key or "").strip(),
            )
            self._set(conn, "safe_browsing_lists", ",".join(gsb_lists))
            safe_browsing_next_run = self._get_global_setting_conn(
                conn,
                "safe_browsing_next_run_ts",
                "0",
            )
            safe_browsing_changed = (
                not previous_safe_browsing_enabled
                or previous_safe_browsing_api_key
                != (safe_browsing_api_key or "").strip()
                or previous_safe_browsing_lists != gsb_lists
            )
            if safe_browsing_enabled and (
                safe_browsing_changed
                or not safe_browsing_next_run
                or safe_browsing_next_run == "0"
            ):
                self._set(conn, "safe_browsing_next_run_ts", str(_now()))

            if (
                category_build_needed
                and source
                and (
                    (source != previous_source or provider != previous_provider)
                    or (enabled and not previous_enabled)
                )
            ):
                self._set_meta(conn, "refresh_requested", "1")
                self._set(conn, "next_run_ts", str(_next_midnight_ts(_now())))
            elif category_build_needed:
                current_next = int(self._get(conn, "next_run_ts", "0") or 0)
                if current_next <= 0:
                    self._set(conn, "next_run_ts", str(_next_midnight_ts(_now())))
            else:
                self._clear_refresh_requested_conn(conn)

    def request_refresh_now(self) -> None:
        self.init_db()
        with self._connect() as conn:
            self._set_meta(conn, "refresh_requested", "1")

    def clear_refresh_requested(self) -> None:
        self._clear_refresh_requested()

    def list_available_categories(self, limit: int = 5000) -> list[tuple[str, int]]:
        try:
            with self._connect_webcat() as conn:
                rows = conn.execute(
                    "SELECT category, domains FROM webcat_categories ORDER BY category ASC LIMIT %s",
                    (int(limit),),
                ).fetchall()
            out: list[tuple[str, int]] = [
                (str(row[0]), int(row[1]) if row[1] is not None else 0) for row in rows
            ]
            return out
        except Exception:
            return []

    def _lookup_domain_categories(self, domain: str) -> set[str]:
        if not _looks_like_host(domain):
            return set()

        try:
            with self._connect_webcat() as conn:
                for candidate in _parent_domains(domain):
                    row = conn.execute(
                        "SELECT categories FROM webcat_domains WHERE domain=%s",
                        (candidate,),
                    ).fetchone()
                    if row and row[0]:
                        return {
                            category for category in str(row[0]).split("|") if category
                        }
        except Exception:
            return set()
        return set()

    def _test_safe_browsing_domain(self, domain: str, settings) -> dict[str, str]:
        if not (
            getattr(settings, "safe_browsing_enabled", False)
            and getattr(settings, "safe_browsing_api_key", "")
        ):
            return {
                "verdict": "not_configured",
                "reason": "Safe Browsing is not configured",
                "threat_type": "",
                "list_name": "",
            }
        try:
            with SafeBrowsingLocalChecker(
                api_key=str(getattr(settings, "safe_browsing_api_key", "") or ""),
                selected_lists=getattr(settings, "safe_browsing_lists", None),
            ) as checker:
                verdict = checker.check_url(f"http://{domain}/")
        except Exception as exc:
            return {
                "verdict": "unavailable",
                "reason": public_error_message(
                    exc,
                    default="Safe Browsing test unavailable.",
                    max_len=200,
                ),
                "threat_type": "",
                "list_name": "",
            }
        return {
            "verdict": verdict.verdict,
            "reason": verdict.reason,
            "threat_type": verdict.threat_type,
            "list_name": verdict.list_name,
        }

    def test_domain(self, domain: str) -> dict[str, object]:
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

        blocked = set(
            self._resolve_category_aliases(list(settings.blocked_categories or [])),
        )
        safe_browsing = self._test_safe_browsing_domain(normalized, settings)
        if safe_browsing["verdict"] == "unsafe":
            threat = safe_browsing["threat_type"].lower().replace("_", "-")
            blocked_by = "google-safe-browsing" + (f"/{threat}" if threat else "")
            return {
                "ok": True,
                "domain": normalized,
                "verdict": "blocked",
                "reason": "Matched Google Safe Browsing threat",
                "whitelisted": False,
                "whitelist_match": "",
                "domain_categories": [],
                "matched_blocked": [],
                "blocked_by": blocked_by,
                "safe_browsing": safe_browsing,
            }
        if not blocked:
            reason = "No categories are currently blocked"
            if safe_browsing["verdict"] == "safe":
                reason = "No categories are blocked; Safe Browsing did not match"
            return {
                "ok": True,
                "domain": normalized,
                "verdict": "allowed",
                "reason": reason,
                "whitelisted": False,
                "whitelist_match": "",
                "domain_categories": [],
                "matched_blocked": [],
                "blocked_by": "",
                "safe_browsing": safe_browsing,
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
                "safe_browsing": safe_browsing,
            }

        matched = sorted(category for category in categories if category in blocked)
        verdict = "blocked" if matched else "allowed"
        reason = (
            "Matched blocked category" if matched else "No blocked categories matched"
        )
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
            "safe_browsing": safe_browsing,
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

    def _category_build_needed_conn(
        self,
        conn,
        *,
        override_proxy_id: object | None = None,
        override_enabled: bool | None = None,
        override_blocked_categories: str | None = None,
    ) -> bool:
        rows = conn.execute(
            f"SELECT proxy_id, k, v FROM {self._table('settings')} WHERE proxy_id<>%s AND k IN ('enabled','blocked_categories')",
            (_GLOBAL_SCOPE,),
        ).fetchall()
        by_proxy: dict[str, dict[str, str]] = {}
        for row in rows:
            proxy_id = str(row[0] or "")
            key = str(row[1] or "")
            value = str(row[2]) if row[2] is not None else ""
            by_proxy.setdefault(proxy_id, {})[key] = value

        if override_proxy_id is not None:
            override_id = str(override_proxy_id or "").strip() or "default"
            values = by_proxy.setdefault(override_id, {})
            if override_enabled is not None:
                values["enabled"] = "1" if override_enabled else "0"
            if override_blocked_categories is not None:
                values["blocked_categories"] = override_blocked_categories

        for values in by_proxy.values():
            if values.get("enabled") != "1":
                continue
            categories = [
                item.strip()
                for item in values.get("blocked_categories", "")
                .replace("\n", ",")
                .split(",")
                if item.strip()
            ]
            if categories:
                return True
        return False

    def _run_build(
        self,
        source_url: str,
        *,
        source_provider: str = "auto",
    ) -> tuple[bool, str]:
        if not source_url:
            return False, "source_url is empty"

        try:
            provider = (source_provider or "auto").strip().lower()
            if provider not in {"auto", "ut1", "category-dir", "csv"}:
                provider = "auto"
            proc = run(
                [
                    "python3",
                    "/app/tools/webcat_build.py",
                    "--source-url",
                    source_url,
                    "--provider",
                    provider,
                    "--download-to",
                    "/var/lib/squid-flask-proxy/webcat/source",
                ],
                capture_output=True,
                timeout=1800,
            )
            if proc.returncode != 0:
                stdout = (proc.stdout or b"").decode("utf-8", errors="replace")
                stderr = (proc.stderr or b"").decode("utf-8", errors="replace")
                return False, (
                    stderr or stdout or f"builder failed rc={proc.returncode}"
                ).strip()
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
            thread = threading.Thread(
                target=self._loop,
                name="webfilter-updater",
                daemon=True,
            )
            thread.start()
            self._started = True
            SafeBrowsingStore().start_background(
                self._safe_browsing_settings,
                self._record_safe_browsing_status,
            )

    def _safe_browsing_settings(self):
        self.init_db()
        with self._connect() as conn:
            return SafeBrowsingStore.settings_from_webfilter(
                conn,
                self._get_global_setting_conn,
            )

    def safe_browsing_status(self):
        return SafeBrowsingStore().status(self._safe_browsing_settings())

    def _record_safe_browsing_status(
        self,
        ok: bool,
        err: str,
        next_run_ts: int,
    ) -> None:
        self.init_db()
        with self._connect() as conn:
            self._set(conn, "safe_browsing_last_attempt", str(_now()))
            if ok:
                self._set(conn, "safe_browsing_last_success", str(_now()))
                self._set(conn, "safe_browsing_last_error", "")
            else:
                self._set(conn, "safe_browsing_last_error", (err or "")[:500])
            self._set(conn, "safe_browsing_next_run_ts", str(int(next_run_ts or 0)))

    def _loop(self) -> None:
        disabled_sleep = float(
            _env_int("WEBFILTER_DISABLED_POLL_SECONDS", 60, minimum=5, maximum=3600),
        )
        enabled_sleep = float(
            _env_int("WEBFILTER_ENABLED_POLL_SECONDS", 300, minimum=5, maximum=3600),
        )
        error_sleep = float(
            _env_int("WEBFILTER_ERROR_BACKOFF_SECONDS", 30, minimum=5, maximum=300),
        )
        while True:
            sleep_seconds = enabled_sleep
            try:
                self.init_db()
                with self._connect() as conn:
                    source_url = self._get_global_setting_conn(
                        conn,
                        "source_url",
                        _DEFAULT_SOURCE_URL,
                    )
                    source_provider = self._get_global_setting_conn(
                        conn,
                        "source_provider",
                        "auto",
                    )
                    next_ts = int(
                        self._get_global_setting_conn(conn, "next_run_ts", "0") or 0,
                    )
                    refresh = self._refresh_requested_conn(conn)
                    if next_ts <= 0:
                        next_ts = _next_midnight_ts(_now())
                        self._set_next_run_conn(conn, ts=next_ts)
                    category_build_needed = self._category_build_needed_conn(conn)

                if not category_build_needed or not source_url:
                    if refresh:
                        with self._connect() as conn:
                            self._clear_refresh_requested_conn(conn)
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
                        remaining = (
                            max(5, int(next_ts or 0) - now)
                            if int(next_ts or 0) > 0
                            else int(enabled_sleep)
                        )
                        sleep_seconds = min(enabled_sleep, float(remaining))

                if do_build:
                    ok, err = self._run_build(
                        source_url,
                        source_provider=source_provider,
                    )
                    with self._connect() as conn:
                        self._record_attempt_conn(conn, ok=ok, err=err)
                        if refresh:
                            self._clear_refresh_requested_conn(conn)
                        self._set_next_run_conn(conn, ts=next_after)
                    sleep_seconds = 5.0
            except DATABASE_ERRORS as exc:
                log_database_unavailable(
                    logger,
                    "webfilter_store.loop.db_unavailable",
                    "Webfilter background updater deferred database work while MySQL is unavailable",
                    exc,
                )
            except Exception:
                log_exception_throttled(
                    logger,
                    "webfilter_store.loop",
                    interval_seconds=30,
                    message="webfilter background loop iteration failed",
                )
                sleep_seconds = error_sleep
            time.sleep(sleep_seconds)


_store: WebFilterStore | None = None
_store_lock = threading.Lock()


def get_webfilter_store() -> WebFilterStore:
    global _store
    if _store is not None:
        return _store
    with _store_lock:
        if _store is None:
            _store = WebFilterStore()
        return _store


__all__ = [
    "WebFilterStore",
    "_looks_like_host",
    "_norm_domain",
    "_parse_whitelist_lines",
    "_whitelist_match",
    "get_webfilter_store",
]
