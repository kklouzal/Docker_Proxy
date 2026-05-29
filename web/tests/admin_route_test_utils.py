from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any


def add_web_to_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


class FakeAuthStore:
    def __init__(self) -> None:
        self.passwords: dict[str, str] = {"admin": "admin"}
        self.added: list[tuple[str, str]] = []
        self.password_changes: list[tuple[str, str]] = []
        self.deleted: list[str] = []

    def ensure_default_admin(self) -> None:
        self.passwords.setdefault("admin", "admin")

    def get_or_create_secret_key(self) -> str:
        return "test-secret-key"

    def verify_user(self, username: str, password: str) -> bool:
        return self.passwords.get((username or "").strip()) == password

    def list_users(self) -> list[Any]:
        return [
            SimpleNamespace(username=username, created_ts=1, updated_ts=1)
            for username in sorted(self.passwords)
        ]

    def add_user(self, username: str, password: str) -> None:
        username = (username or "").strip()
        if not username:
            msg = "Username is required."
            raise ValueError(msg)
        if not password:
            msg = "Password is required."
            raise ValueError(msg)
        if username in self.passwords:
            msg = "User already exists."
            raise ValueError(msg)
        self.passwords[username] = password
        self.added.append((username, password))

    def set_password(self, username: str, new_password: str) -> None:
        username = (username or "").strip()
        if username not in self.passwords:
            msg = "User not found."
            raise ValueError(msg)
        if not new_password:
            msg = "Password is required."
            raise ValueError(msg)
        self.passwords[username] = new_password
        self.password_changes.append((username, new_password))

    def delete_user(self, username: str) -> None:
        username = (username or "").strip()
        if username not in self.passwords:
            msg = "User not found."
            raise ValueError(msg)
        del self.passwords[username]
        self.deleted.append(username)


class FakeAuditStore:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.records: list[dict[str, Any]] = []

    def record(self, **payload: Any) -> None:
        if self.fail:
            msg = "audit unavailable"
            raise RuntimeError(msg)
        self.records.append(dict(payload))

    def latest_config_apply(self) -> None:
        return None


class FakeRegistry:
    def __init__(
        self,
        proxy_ids: list[str] | None = None,
        *,
        management_url: str = "http://proxy:5000",
    ) -> None:
        self.proxies = [
            self._proxy(proxy_id, management_url=management_url)
            for proxy_id in (proxy_ids or ["default"])
        ]

    def _proxy(
        self, proxy_id: str, *, management_url: str = "http://proxy:5000"
    ) -> Any:
        return SimpleNamespace(
            proxy_id=proxy_id,
            display_name=proxy_id.title(),
            hostname=f"{proxy_id}.example.test",
            management_url=management_url,
            public_host="proxy",
            public_pac_scheme="http",
            public_pac_port=80,
            public_http_proxy_port=3128,
            status="healthy",
            last_heartbeat=1,
            last_apply_ts=1,
            last_apply_ok=True,
            current_config_sha="abc",
            detail="",
            created_ts=1,
            updated_ts=1,
        )

    def init_db(self) -> None:
        return None

    def list_proxies(self) -> list[Any]:
        return list(self.proxies)

    def ensure_default_proxy(self) -> Any:
        if not self.proxies:
            self.proxies.append(self._proxy("default"))
        return self.proxies[0]

    def get_proxy(self, proxy_id: object | None) -> Any | None:
        key = str(proxy_id or "default")
        for proxy in self.proxies:
            if proxy.proxy_id == key:
                return proxy
        return None

    def resolve_proxy_id(self, preferred: object | None = None) -> str:
        if preferred is not None:
            proxy = self.get_proxy(preferred)
            if proxy is not None:
                return str(proxy.proxy_id)
        return str(self.ensure_default_proxy().proxy_id)

    def rename_proxy(
        self,
        old_proxy_id: object | None,
        new_proxy_id: object | None,
        *,
        display_name: str | None = None,
    ) -> Any:
        proxy = self.get_proxy(old_proxy_id)
        if proxy is None:
            msg = "proxy not found"
            raise ValueError(msg)
        if self.get_proxy(new_proxy_id) is not None:
            msg = "target exists"
            raise ValueError(msg)
        proxy.proxy_id = str(new_proxy_id or "default")
        proxy.display_name = display_name or proxy.proxy_id
        return proxy

    def remove_proxy(self, proxy_id: object | None) -> Any:
        key = str(proxy_id or "default")
        proxy = self.get_proxy(key)
        if proxy is None:
            msg = "proxy not found"
            raise ValueError(msg)
        self.proxies = [item for item in self.proxies if item.proxy_id != key]
        return SimpleNamespace(
            proxy_id=key,
            deleted_rows=3,
            table_counts={"proxy_instances": 1, "diagnostic_requests": 2},
        )

    def mark_apply_result(self, *_args: Any, **_kwargs: Any) -> Any:
        return self.ensure_default_proxy()


class FakeProxyClient:
    def __init__(self, admin_app: Any, *, fail: bool = False) -> None:
        self.admin_app = admin_app
        self.fail = fail
        self.synced: list[tuple[str, bool]] = []
        self.validated: list[tuple[str, str]] = []
        self.cleared: list[str] = []

    def _maybe_fail(self) -> None:
        if self.fail:
            msg = "proxy unavailable"
            raise self.admin_app.ProxyClientError(msg)

    def get_health(self, proxy_id: object, *_, **__) -> dict[str, Any]:
        self._maybe_fail()
        return {
            "ok": True,
            "status": "healthy",
            "proxy_id": str(proxy_id),
            "proxy_status": "running",
            "listener_ports": [3128, 3129],
            "listener_details": [
                {"port": 3128, "mode": "explicit"},
                {"port": 3129, "mode": "intercept"},
            ],
            "stats": {},
            "services": {
                "squid_listeners": {
                    "ok": True,
                    "detail": "explicit:3128, intercept:3129",
                },
                "icap": {"ok": True, "detail": "ok"},
                "clamav": {"ok": True, "detail": "ok"},
                "av_icap": {"ok": True, "detail": "ok"},
                "clamd": {"ok": True, "detail": "ok"},
            },
        }

    def get_clamav_health(self, proxy_id: object, *_, **__) -> dict[str, Any]:
        return self.get_health(proxy_id)

    def validate_config(self, proxy_id: object, config_text: str) -> dict[str, Any]:
        self._maybe_fail()
        self.validated.append((str(proxy_id), config_text))
        ok = "not_a_real_squid_directive" not in config_text and "*." not in config_text
        detail = "valid" if ok else "invalid directive or wildcard domain"
        return {"ok": ok, "detail": detail, "proxy_id": str(proxy_id)}

    def sync_proxy(
        self,
        proxy_id: object,
        *,
        force: bool = False,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        self._maybe_fail()
        self.synced.append((str(proxy_id), bool(force)))
        return {"ok": True, "detail": "sync requested"}

    def clear_proxy_cache(self, proxy_id: object) -> dict[str, Any]:
        self._maybe_fail()
        self.cleared.append(str(proxy_id))
        return {"ok": True, "detail": "cache cleared"}

    def test_clamav_eicar(self, proxy_id: object) -> dict[str, Any]:
        self._maybe_fail()
        return {"ok": False, "detail": f"EICAR unavailable on {proxy_id}"}

    def test_clamav_icap(self, proxy_id: object) -> dict[str, Any]:
        self._maybe_fail()
        return {"ok": True, "detail": "204 No Content"}


class FakeController:
    def __init__(self, config_text: str | None = None) -> None:
        self.config_text = (
            config_text
            or "http_port 3128\nssl_bump splice all\nadaptation_access av_resp_set allow icap_av_scanable\n"
        )
        self.applied: list[str] = []

    def _listener_lines_from_options(self, options: dict[str, Any]) -> list[str]:
        explicit_port = int(options.get("explicit_proxy_port") or 3128)
        intercept_enabled = bool(
            options.get("intercept_enabled_on") or options.get("intercept_enabled")
        )
        intercept_port = int(
            options.get("intercept_port")
            or (explicit_port + 1 if explicit_port < 65535 else 3129)
        )
        if intercept_port == explicit_port:
            intercept_port = explicit_port + 1 if explicit_port < 65535 else 3129
            if intercept_port == explicit_port:
                intercept_port = 3129 if explicit_port != 3129 else 3130
        lines = [f"http_port {explicit_port}"]
        if intercept_enabled:
            lines.append(f"http_port 0.0.0.0:{intercept_port} intercept")
        return lines

    def get_current_config(self) -> str:
        return self.config_text

    def normalize_config_text(self, text: str) -> str:
        return (text or "").rstrip() + "\n"

    def validate_config_text(self, text: str) -> tuple[bool, str]:
        return (
            "not_a_real_squid_directive" not in (text or ""),
            "valid" if "not_a_real_squid_directive" not in (text or "") else "invalid",
        )

    def apply_config_text(self, text: str) -> tuple[bool, str]:
        self.applied.append(text)
        self.config_text = text
        return True, "applied locally"

    def reload_squid(self):
        return b"reloaded", b""

    def get_tunable_options(self, _text: str) -> dict[str, Any]:
        intercept_enabled = " intercept" in (self.config_text or "")
        return {
            "workers": 1,
            "cache_mem_mb": 64,
            "cache_dir_size_mb": 128,
            "explicit_proxy_port": 3128,
            "intercept_enabled": intercept_enabled,
            "intercept_enabled_on": intercept_enabled,
            "intercept_port": 3129,
        }

    def get_cache_override_options(self, _text: str) -> dict[str, bool]:
        return {
            "override_expire": False,
            "override_lastmod": False,
            "reload_into_ims": False,
            "ignore_reload": False,
            "ignore_no_store": False,
            "ignore_private": False,
        }

    def generate_config_from_template(self, options: dict[str, Any]) -> str:
        lines = self._listener_lines_from_options(options)
        lines.append(f"cache_mem {int(options.get('cache_mem_mb') or 64)} MB")
        return "\n".join(lines) + "\n"

    def apply_cache_overrides(self, text: str, overrides: dict[str, bool]) -> str:
        suffix = "".join(
            f"# override_{key}={1 if value else 0}\n"
            for key, value in sorted(overrides.items())
        )
        return text.rstrip() + "\n" + suffix

    def get_caching_lines(self, _text: str) -> list[str]:
        return []

    get_timeout_lines = get_caching_lines
    get_logging_lines = get_caching_lines
    get_network_lines = get_caching_lines
    get_dns_lines = get_caching_lines
    get_ssl_lines = get_caching_lines
    get_icap_lines = get_caching_lines
    get_privacy_lines = get_caching_lines
    get_limits_lines = get_caching_lines
    get_performance_lines = get_caching_lines
    get_http_lines = get_caching_lines


class FakeOperationLedger:
    def __init__(self) -> None:
        self.operations: list[Any] = []
        self.next_id = 1

    def create_operation(self, proxy_id: object, **kwargs: Any) -> Any:
        import time

        now = int(time.time())
        op = SimpleNamespace(
            operation_id=self.next_id,
            proxy_id=str(proxy_id),
            status="pending",
            operation_type=str(kwargs.get("operation_type") or "sync"),
            subject=str(kwargs.get("subject") or ""),
            summary=str(kwargs.get("summary") or ""),
            target_kind=str(kwargs.get("target_kind") or ""),
            target_ref=str(kwargs.get("target_ref") or ""),
            rollback_kind=str(kwargs.get("rollback_kind") or ""),
            rollback_ref=str(kwargs.get("rollback_ref") or ""),
            request_hash=str(kwargs.get("request_hash") or ""),
            detail=str(kwargs.get("detail") or ""),
            created_by=str(kwargs.get("created_by") or ""),
            created_ts=now,
            started_ts=0,
            completed_ts=0,
            updated_ts=now,
            force=bool(kwargs.get("force")),
        )
        op.can_revert = bool(op.rollback_kind and op.rollback_ref)
        op.to_dict = lambda op=op: dict(op.__dict__)
        self.next_id += 1
        self.operations.append(op)
        return op

    def list_operations(
        self, proxy_id: object, *, limit: int = 100, statuses: list[str] | None = None
    ) -> list[Any]:
        rows = [op for op in self.operations if op.proxy_id == str(proxy_id)]
        if statuses:
            rows = [op for op in rows if op.status in statuses]
        return list(reversed(rows))[:limit]

    def counts_by_status(self, proxy_id: object) -> dict[str, int]:
        counts = {
            "pending": 0,
            "applying": 0,
            "applied": 0,
            "superseded": 0,
            "failed": 0,
        }
        for op in self.operations:
            if op.proxy_id == str(proxy_id) and op.status in counts:
                counts[op.status] += 1
        return counts

    def list_recent_since(
        self,
        proxy_id: object,
        *,
        after_updated_ts: int = 0,
        after_id: int = 0,
        limit: int = 100,
    ) -> list[Any]:
        return [
            op
            for op in self.list_operations(proxy_id, limit=limit)
            if op.updated_ts > after_updated_ts
            or (op.updated_ts == after_updated_ts and op.operation_id > after_id)
        ]

    def get_operation(self, operation_id: object) -> Any | None:
        target = int(operation_id or 0)
        return next((op for op in self.operations if op.operation_id == target), None)


class FakeConfigRevisions:
    def __init__(self, config_text: str | None = None) -> None:
        self.config_text = (
            config_text
            or "http_port 3128\nssl_bump splice all\nadaptation_access av_resp_set allow icap_av_scanable\n"
        )
        self.created: list[dict[str, Any]] = []
        self.applied: list[dict[str, Any]] = []

    def get_active_config_text(self, _proxy_id: object | None) -> str:
        return self.config_text

    def ensure_active_revision(
        self, proxy_id: object, config_text: str, **kwargs: Any
    ) -> Any:
        return self.create_revision(proxy_id, config_text, activate=True, **kwargs)

    def create_revision(self, proxy_id: object, config_text: str, **kwargs: Any) -> Any:
        self.config_text = config_text
        revision_id = len(self.created) + 1
        self.created.append(
            {
                "proxy_id": proxy_id,
                "config_text": config_text,
                "revision_id": revision_id,
                **kwargs,
            }
        )
        return SimpleNamespace(
            revision_id=revision_id, config_sha256="sha", config_text=config_text
        )

    def record_apply_result(
        self, proxy_id: object, revision_id: int, **kwargs: Any
    ) -> Any:
        row = {"proxy_id": proxy_id, "revision_id": revision_id, **kwargs}
        self.applied.append(row)
        return SimpleNamespace(
            application_id=len(self.applied),
            applied_ts=1,
            ok=bool(kwargs.get("ok")),
            detail=kwargs.get("detail", ""),
        )

    def latest_apply(self, _proxy_id: object | None) -> Any | None:
        if not self.applied:
            return None
        row = self.applied[-1]
        return SimpleNamespace(
            applied_ts=1,
            ok=bool(row.get("ok")),
            detail=row.get("detail", ""),
            applied_by="test",
        )


class FakeTimeseriesStore:
    def summary(self) -> dict[str, Any]:
        return {}

    def query(self, **_kwargs: Any) -> list[Any]:
        return []


class FakeDiagnosticStore:
    def activity_summary(self, **_kwargs: Any) -> dict[str, Any]:
        return {}

    def icap_summary(self, **_kwargs: Any) -> dict[str, Any]:
        return {"events": 0, "avg_icap_time_ms": 0, "max_icap_time_ms": 0}


class FakeSslErrorsStore:
    def list_recent(self, **_kwargs: Any) -> list[Any]:
        return []


class FakeObservabilityQueries:
    def summary(self, **_kwargs: Any) -> dict[str, Any]:
        return {}

    def overview_bundle(self, **_kwargs: Any) -> dict[str, Any]:
        return {
            "summary": {},
            "destinations": [],
            "clients": [],
            "cache_reasons": [],
            "ssl": {},
            "security": {},
            "performance": {},
        }

    def top_clients(self, **_kwargs: Any) -> list[Any]:
        return []

    def top_cache_reasons(self, **_kwargs: Any) -> list[Any]:
        return []

    def ssl_overview(self, **_kwargs: Any) -> dict[str, Any]:
        return {"rows": [], "summary": {}}

    def security_overview(self, **_kwargs: Any) -> dict[str, Any]:
        return {"av_rows": [], "adblock_rows": [], "webfilter_rows": []}

    def performance_overview(self, **_kwargs: Any) -> dict[str, Any]:
        return {"slow_requests": [], "slow_icap_events": []}

    def remediation_overview(self, **_kwargs: Any) -> dict[str, Any]:
        return {
            "summary": {
                "suggestions": 0,
                "high_confidence": 0,
                "observations": 0,
                "domains": 0,
                "latest": 0,
                "http3_candidates": 0,
            },
            "rows": [],
            "top_components": [],
            "top_kinds": [],
            "quic_guidance": [],
        }

    def top_destinations(self, **_kwargs: Any) -> list[Any]:
        return []


class FakeAdblockArtifacts:
    def __init__(self, summary: Any | None = None) -> None:
        self.summary = summary

    def get_active_artifact_summary(self) -> Any | None:
        return self.summary


class FakeAdblockStore:
    def __init__(self) -> None:
        self.settings = {"enabled": True, "cache_ttl": 3600, "cache_max": 200000}
        self.statuses = [
            SimpleNamespace(
                key="default",
                url="https://example.invalid/list.txt",
                enabled=True,
                rules=0,
                bytes=0,
                last_success=0,
                last_attempt=0,
                last_error="",
            )
        ]
        self.refresh_requested = 0
        self.cache_flush_requested = 0

    def init_db(self) -> None:
        return None

    def list_statuses(self) -> list[Any]:
        return list(self.statuses)

    def set_enabled(self, enabled_map: dict[str, bool]) -> None:
        for status in self.statuses:
            status.enabled = bool(enabled_map.get(status.key))

    def get_settings(self) -> dict[str, Any]:
        return dict(self.settings)

    def set_settings(self, **kwargs: Any) -> None:
        self.settings.update(kwargs)

    def request_refresh_now(self) -> None:
        self.refresh_requested += 1

    def request_cache_flush(self) -> None:
        self.cache_flush_requested += 1

    def stats(self) -> dict[str, Any]:
        return {"total": 0, "last_24h": 0, "by_list": {}, "by_list_24h": {}}

    def cache_stats(self) -> dict[str, Any]:
        return {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "current_size": 0,
            "last_flush": 0,
            "last_flush_req": 0,
        }

    def get_update_interval_seconds(self) -> int:
        return 3600


class FakeWebfilterStore:
    def __init__(self) -> None:
        self.settings = SimpleNamespace(
            enabled=False,
            source_url="",
            source_provider="auto",
            blocked_categories=[],
            safe_browsing_enabled=False,
            safe_browsing_api_key="",
            safe_browsing_lists=[],
            safe_browsing_last_success=0,
            safe_browsing_last_attempt=0,
            safe_browsing_last_error="",
            safe_browsing_next_run_ts=0,
        )
        self.whitelist: list[tuple[str, int]] = []

    def init_db(self) -> None:
        return None

    def get_settings(self) -> Any:
        return self.settings

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
        safe_browsing_lists = safe_browsing_lists or []
        self.settings = SimpleNamespace(
            enabled=enabled,
            source_url=source_url,
            source_provider=source_provider,
            blocked_categories=blocked_categories,
            safe_browsing_enabled=safe_browsing_enabled,
            safe_browsing_api_key=safe_browsing_api_key,
            safe_browsing_lists=safe_browsing_lists,
            safe_browsing_last_success=0,
            safe_browsing_last_attempt=0,
            safe_browsing_last_error="",
            safe_browsing_next_run_ts=0,
        )
        self.last_set_settings = {
            "enabled": enabled,
            "source_url": source_url,
            "source_provider": source_provider,
            "blocked_categories": blocked_categories,
            "safe_browsing_enabled": safe_browsing_enabled,
            "safe_browsing_api_key": safe_browsing_api_key,
            "safe_browsing_lists": safe_browsing_lists,
        }

    def list_available_categories(self) -> list[Any]:
        return [
            SimpleNamespace(key="adult", label="Adult"),
            SimpleNamespace(key="games", label="Games"),
        ]

    def list_whitelist(self) -> list[Any]:
        return list(self.whitelist)

    def add_whitelist(self, entry: str) -> tuple[bool, str, str]:
        entry = (entry or "").strip().lower()
        if not entry or " " in entry:
            return False, "Invalid whitelist entry.", ""
        self.whitelist.append((entry, 1))
        return True, "", entry

    def remove_whitelist(self, pattern: str) -> None:
        self.whitelist = [row for row in self.whitelist if row[0] != pattern]

    def test_domain(self, domain: str) -> dict[str, Any]:
        if not (domain or "").strip():
            return {"ok": False, "verdict": "invalid", "reason": "Domain is required."}
        return {"ok": True, "verdict": "allow", "domain": domain.strip().lower()}


class FakeSslfilterStore:
    def __init__(self) -> None:
        self.no_bump_domains: list[str] = []
        self.no_cache_domains: list[str] = []
        self.no_bump_src_nets: list[str] = []
        self.no_cache_src_nets: list[str] = []
        self.exclude_private_nets = False

    @property
    def private_dst_nets(self) -> list[str]:
        return ["10.0.0.0/8", "192.168.0.0/16"]

    def init_db(self) -> None:
        return None

    def list_all(self) -> Any:
        return SimpleNamespace(
            no_bump_domains=list(self.no_bump_domains),
            no_cache_domains=list(self.no_cache_domains),
            no_bump_src_nets=list(self.no_bump_src_nets),
            no_cache_src_nets=list(self.no_cache_src_nets),
            exclude_private_nets=self.exclude_private_nets,
        )

    def list_nobump(self) -> list[tuple[str, int]]:
        return [(cidr, 1) for cidr in self.no_bump_src_nets]

    def add_domain(
        self, policy: str, value: str | None = None
    ) -> tuple[bool, str, str]:
        if value is None:
            value = policy
            policy = "nobump"
        value = (value or "").strip().lower()
        if not value or " " in value or "/" in value:
            return False, "Invalid domain.", ""
        target = (
            self.no_bump_domains
            if policy == "nobump"
            else self.no_cache_domains
            if policy == "nocache"
            else None
        )
        if target is None:
            return False, "Invalid domain policy.", ""
        if value not in target:
            target.append(value)
        return True, "", value

    def remove_domain(self, policy: str, value: str | None = None) -> None:
        if value is None:
            value = policy
            policy = "nobump"
        target = self.no_bump_domains if policy == "nobump" else self.no_cache_domains
        target[:] = [item for item in target if item != (value or "").strip().lower()]

    def add_src_net(self, policy: str, cidr: str) -> tuple[bool, str, str]:
        cidr = (cidr or "").strip()
        if not cidr or "bad" in cidr:
            return False, "Invalid CIDR.", ""
        target = (
            self.no_bump_src_nets
            if policy == "nobump"
            else self.no_cache_src_nets
            if policy == "nocache"
            else None
        )
        if target is None:
            return False, "Invalid CIDR policy.", ""
        if cidr not in target:
            target.append(cidr)
        return True, "", cidr

    def remove_src_net(self, policy: str, cidr: str) -> None:
        target = self.no_bump_src_nets if policy == "nobump" else self.no_cache_src_nets
        target[:] = [item for item in target if item != cidr]

    def add_nobump(self, cidr: str) -> tuple[bool, str, str]:
        return self.add_src_net("nobump", cidr)

    def remove_nobump(self, cidr: str) -> None:
        self.remove_src_net("nobump", cidr)

    def set_exclude_private_nets(self, enabled: bool) -> None:
        self.exclude_private_nets = bool(enabled)

    def list_compatibility_presets(self) -> list[dict[str, Any]]:
        return [
            {
                "id": "discord",
                "title": "Discord",
                "description": "Discord domains",
                "domains": ["discord.com"],
                "installed": 1 if "discord.com" in self.no_bump_domains else 0,
                "missing": 0 if "discord.com" in self.no_bump_domains else 1,
                "total": 1,
                "complete": "discord.com" in self.no_bump_domains,
            }
        ]

    def install_compatibility_preset(self, _preset_id: str) -> tuple[int, int, str]:
        before = set(self.no_bump_domains)
        self.add_domain("nobump", "discord.com")
        return len(set(self.no_bump_domains) - before), 1, ""


class FakePacProfilesStore:
    def __init__(self) -> None:
        self.profiles: dict[int, Any] = {}
        self.backup_proxies: list[Any] = []
        self.next_id = 1
        self.next_backup_id = 1
        self.direct_enabled = True

    def list_profiles(self) -> list[Any]:
        return list(self.profiles.values())

    def list_proxy_chain_settings(self) -> Any:
        return SimpleNamespace(
            backup_proxies=list(self.backup_proxies), direct_enabled=self.direct_enabled
        )

    def add_backup_proxy(
        self, *, proxy_host: str, proxy_port: object | None = None
    ) -> tuple[bool, str, int | None]:
        host = (proxy_host or "").strip()
        if not host:
            return False, "Proxy host is required.", None
        try:
            port = int(str(proxy_port or "3128").strip() or "3128")
        except Exception:
            return False, "Invalid proxy port.", None
        bid = self.next_backup_id
        self.next_backup_id += 1
        self.backup_proxies.append(
            SimpleNamespace(
                id=bid,
                proxy_host=host,
                proxy_port=port,
                position=len(self.backup_proxies) + 1,
                created_ts=0,
            ),
        )
        return True, "", bid

    def delete_backup_proxy(self, backup_proxy_id: int) -> None:
        self.backup_proxies = [
            item for item in self.backup_proxies if item.id != int(backup_proxy_id)
        ]
        for idx, item in enumerate(self.backup_proxies, start=1):
            item.position = idx

    def move_backup_proxy(self, backup_proxy_id: int, direction: str) -> None:
        bid = int(backup_proxy_id)
        ids = [item.id for item in self.backup_proxies]
        if bid not in ids:
            return
        index = ids.index(bid)
        if direction == "up" and index > 0:
            self.backup_proxies[index - 1], self.backup_proxies[index] = (
                self.backup_proxies[index],
                self.backup_proxies[index - 1],
            )
        elif direction == "down" and index < len(self.backup_proxies) - 1:
            self.backup_proxies[index + 1], self.backup_proxies[index] = (
                self.backup_proxies[index],
                self.backup_proxies[index + 1],
            )
        for idx, item in enumerate(self.backup_proxies, start=1):
            item.position = idx

    def set_direct_enabled(self, enabled: bool) -> None:
        self.direct_enabled = bool(enabled)

    def upsert_profile(
        self,
        *,
        profile_id: int | None,
        name: str,
        client_cidr: str,
        direct_domains_text: str,
        direct_dst_nets_text: str,
    ) -> tuple[bool, str, int | None]:
        if client_cidr and "/" not in client_cidr:
            return False, "Invalid CIDR.", None
        if profile_id is not None and profile_id not in self.profiles:
            return False, "Profile not found.", None
        pid = profile_id or self.next_id
        if profile_id is None:
            self.next_id += 1
        domains = [
            line.strip() for line in direct_domains_text.splitlines() if line.strip()
        ]
        nets = [
            line.strip() for line in direct_dst_nets_text.splitlines() if line.strip()
        ]
        self.profiles[pid] = SimpleNamespace(
            id=pid,
            name=name,
            client_cidr=client_cidr,
            direct_domains=domains,
            direct_dst_nets=nets,
        )
        return True, "", pid

    def delete_profile(self, profile_id: int) -> None:
        self.profiles.pop(profile_id, None)


class FakeCertificateBundles:
    def __init__(self, bundle: Any | None = None) -> None:
        self.bundle = bundle
        self.created: list[Any] = []
        self.applied: list[dict[str, Any]] = []

    def get_active_bundle(self) -> Any | None:
        return self.bundle

    def create_revision(self, bundle: Any, **_kwargs: Any) -> Any:
        self.bundle = bundle
        revision = SimpleNamespace(
            revision_id=len(self.created) + 1,
            bundle_sha256=getattr(bundle, "bundle_sha256", "bundle-sha"),
        )
        self.created.append(revision)
        return revision

    def record_apply_result(
        self, proxy_id: object, revision_id: int, **kwargs: Any
    ) -> Any:
        self.applied.append(
            {"proxy_id": proxy_id, "revision_id": revision_id, **kwargs}
        )
        return SimpleNamespace(application_id=len(self.applied))

    def latest_apply(self, _proxy_id: object | None) -> Any | None:
        if not self.applied:
            return None
        row = self.applied[-1]
        return SimpleNamespace(
            ok=bool(row.get("ok")), detail=row.get("detail", ""), applied_ts=1
        )


def load_admin_app(monkeypatch: Any, tmp_path: Path, **overrides: Any) -> Any:
    add_web_to_path()
    monkeypatch.setenv("DISABLE_BACKGROUND", "1")
    monkeypatch.setenv("FLASK_SECRET_PATH", str(tmp_path / "flask_secret.key"))
    monkeypatch.setenv("DEFAULT_PROXY_ID", "default")
    sys.modules.pop("app", None)
    import app as admin_app  # type: ignore

    admin_app = importlib.reload(admin_app)

    fake_auth = overrides.get("auth_store") or FakeAuthStore()
    fake_audit = overrides.get("audit_store") or FakeAuditStore()
    fake_registry = overrides.get("registry") or FakeRegistry()
    fake_controller = overrides.get("controller") or FakeController()
    fake_revisions = overrides.get("config_revisions") or FakeConfigRevisions(
        fake_controller.get_current_config()
    )
    fake_proxy_client = overrides.get("proxy_client") or FakeProxyClient(admin_app)
    fake_certificates = overrides.get("certificate_bundles") or FakeCertificateBundles()
    fake_adblock_artifacts = overrides.get("adblock_artifacts") or FakeAdblockArtifacts()
    fake_operation_ledger = overrides.get("operation_ledger") or FakeOperationLedger()

    services = admin_app.AppRuntimeServices(
        controller=fake_controller,
        get_certificate_bundles=lambda: fake_certificates,
        get_config_revisions=lambda: fake_revisions,
        get_diagnostic_store=lambda: (
            overrides.get("diagnostic_store") or FakeDiagnosticStore()
        ),
        get_audit_store=lambda: fake_audit,
        get_timeseries_store=lambda: (
            overrides.get("timeseries_store") or FakeTimeseriesStore()
        ),
        get_ssl_errors_store=lambda: (
            overrides.get("ssl_errors_store") or FakeSslErrorsStore()
        ),
        get_adblock_store=lambda: overrides.get("adblock_store") or FakeAdblockStore(),
        get_webfilter_store=lambda: (
            overrides.get("webfilter_store") or FakeWebfilterStore()
        ),
        get_policy_request_store=lambda: overrides.get("policy_request_store") or None,
        get_sslfilter_store=lambda: (
            overrides.get("sslfilter_store") or FakeSslfilterStore()
        ),
        get_pac_profiles_store=lambda: (
            overrides.get("pac_profiles_store") or FakePacProfilesStore()
        ),
        get_proxy_client=lambda: fake_proxy_client,
        get_proxy_registry=lambda: fake_registry,
        get_observability_queries=lambda: (
            overrides.get("observability_queries") or FakeObservabilityQueries()
        ),
        clear_observability_logs=overrides.get("clear_observability_logs")
        or (lambda: {"ok": True, "deleted_rows": 0, "tables": []}),
        run_observability_maintenance=overrides.get("run_observability_maintenance")
        or (
            lambda *, analyze=False, optimize=False: {
                "ok": True,
                "retention_days": 30,
                "maintenance": {"maintained_tables": 0, "tables": []},
            }
        ),
        get_observability_retention_settings=overrides.get(
            "get_observability_retention_settings"
        )
        or (lambda: {"retention_days": 30, "updated_ts": 0}),
        set_observability_retention_settings=overrides.get(
            "set_observability_retention_settings"
        )
        or (
            lambda *, retention_days: {
                "retention_days": int(retention_days),
                "updated_ts": 1,
            }
        ),
        check_icap_adblock=lambda: {"ok": True, "detail": "ok"},
        check_icap_av=lambda: {"ok": True, "detail": "ok"},
        check_clamd=lambda: {"ok": True, "detail": "ok"},
        send_sample_av_icap=lambda: {"ok": True, "detail": "204 No Content"},
        test_eicar=lambda: {"ok": False, "detail": "EICAR unavailable"},
    )

    monkeypatch.setattr(admin_app, "_auth_store", fake_auth)
    monkeypatch.setattr(
        admin_app,
        "_directory_auth_store",
        overrides.get("directory_auth_store")
        or SimpleNamespace(
            ensure_default_profiles=lambda: None,
            authenticate_admin=lambda username, password: SimpleNamespace(
                ok=False,
                provider="local",
                username=username,
                detail="No active directory provider.",
            ),
            get_status=lambda: {
                "active_provider": "local",
                "active_label": "Local accounts",
                "profiles": {},
                "providers": (),
                "provider_labels": {},
            },
        ),
    )
    monkeypatch.setattr(
        admin_app, "get_operation_ledger", lambda: fake_operation_ledger
    )
    from services import proxy_sync

    monkeypatch.setattr(
        proxy_sync, "get_operation_ledger", lambda: fake_operation_ledger
    )
    monkeypatch.setattr(admin_app, "_app_runtime_services", lambda: services)
    monkeypatch.setattr(
        admin_app,
        "get_adblock_artifacts",
        lambda: fake_adblock_artifacts,
    )
    admin_app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    return SimpleNamespace(
        module=admin_app,
        auth_store=fake_auth,
        audit_store=fake_audit,
        registry=fake_registry,
        controller=fake_controller,
        config_revisions=fake_revisions,
        proxy_client=fake_proxy_client,
        certificate_bundles=fake_certificates,
        adblock_artifacts=fake_adblock_artifacts,
        operation_ledger=fake_operation_ledger,
    )


def csrf_token(client: Any, path: str = "/") -> str:
    response = client.get(path)
    text = response.get_data(as_text=True)
    marker = 'name="csrf-token" content="'
    if marker in text:
        return text.split(marker, 1)[1].split('"', 1)[0]
    marker = 'name="csrf_token" value="'
    if marker in text:
        return text.split(marker, 1)[1].split('"', 1)[0]
    msg = f"Could not find CSRF token in response for {path}: {text[:200]!r}"
    raise AssertionError(msg)


def login_client(client: Any, username: str = "admin", password: str = "admin") -> Any:
    token = csrf_token(client, "/login")
    response = client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": token},
        follow_redirects=False,
    )
    assert response.status_code in {302, 303}
    return response
