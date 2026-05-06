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
        return [SimpleNamespace(username=username, created_ts=1, updated_ts=1) for username in sorted(self.passwords)]

    def add_user(self, username: str, password: str) -> None:
        username = (username or "").strip()
        if not username:
            raise ValueError("Username is required.")
        if not password:
            raise ValueError("Password is required.")
        if username in self.passwords:
            raise ValueError("User already exists.")
        self.passwords[username] = password
        self.added.append((username, password))

    def set_password(self, username: str, new_password: str) -> None:
        username = (username or "").strip()
        if username not in self.passwords:
            raise ValueError("User not found.")
        if not new_password:
            raise ValueError("Password is required.")
        self.passwords[username] = new_password
        self.password_changes.append((username, new_password))

    def delete_user(self, username: str) -> None:
        username = (username or "").strip()
        if username not in self.passwords:
            raise ValueError("User not found.")
        del self.passwords[username]
        self.deleted.append(username)


class FakeAuditStore:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.records: list[dict[str, Any]] = []

    def record(self, **payload: Any) -> None:
        if self.fail:
            raise RuntimeError("audit unavailable")
        self.records.append(dict(payload))

    def latest_config_apply(self):
        return None


class FakeRegistry:
    def __init__(self, proxy_ids: list[str] | None = None, *, management_url: str = "http://proxy:5000") -> None:
        self.proxies = [self._proxy(proxy_id, management_url=management_url) for proxy_id in (proxy_ids or ["default"])]

    def _proxy(self, proxy_id: str, *, management_url: str = "http://proxy:5000") -> Any:
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

    def mark_apply_result(self, *_args: Any, **_kwargs: Any) -> Any:
        return self.ensure_default_proxy()


class FakeProxyClient:
    def __init__(self, admin_app: Any, *, fail: bool = False) -> None:
        self.admin_app = admin_app
        self.fail = fail
        self.synced: list[tuple[str, bool]] = []
        self.cleared: list[str] = []

    def _maybe_fail(self) -> None:
        if self.fail:
            raise self.admin_app.ProxyClientError("proxy unavailable")

    def get_health(self, proxy_id: object, *_, **__) -> dict[str, Any]:
        self._maybe_fail()
        return {
            "ok": True,
            "status": "healthy",
            "proxy_id": str(proxy_id),
            "proxy_status": "running",
            "stats": {},
            "services": {
                "icap": {"ok": True, "detail": "ok"},
                "clamav": {"ok": True, "detail": "ok"},
                "av_icap": {"ok": True, "detail": "ok"},
                "clamd": {"ok": True, "detail": "ok"},
            },
        }

    def validate_config(self, proxy_id: object, config_text: str) -> dict[str, Any]:
        self._maybe_fail()
        ok = "not_a_real_squid_directive" not in config_text
        return {"ok": ok, "detail": "valid" if ok else "invalid directive", "proxy_id": str(proxy_id)}

    def sync_proxy(self, proxy_id: object, *, force: bool = False) -> dict[str, Any]:
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
        self.config_text = config_text or "http_port 3128\nssl_bump splice all\nadaptation_access av_resp_set allow icap_av_scanable\n"
        self.applied: list[str] = []

    def get_current_config(self) -> str:
        return self.config_text

    def normalize_config_text(self, text: str) -> str:
        return (text or "").rstrip() + "\n"

    def validate_config_text(self, text: str) -> tuple[bool, str]:
        return ("not_a_real_squid_directive" not in (text or ""), "valid" if "not_a_real_squid_directive" not in (text or "") else "invalid")

    def apply_config_text(self, text: str) -> tuple[bool, str]:
        self.applied.append(text)
        self.config_text = text
        return True, "applied locally"

    def reload_squid(self):
        return b"reloaded", b""

    def get_tunable_options(self, _text: str) -> dict[str, Any]:
        return {"workers": 1, "cache_mem_mb": 64, "cache_dir_size_mb": 128}

    def get_cache_override_options(self, _text: str) -> dict[str, bool]:
        return {"client_no_cache": False, "origin_private": False, "client_no_store": False}

    def generate_config_from_template_with_exclusions(self, options: dict[str, Any], _exclusions: Any) -> str:
        return f"http_port 3128\ncache_mem {int(options.get('cache_mem_mb') or 64)} MB\n"

    def apply_cache_overrides(self, text: str, overrides: dict[str, bool]) -> str:
        suffix = "".join(f"# override_{key}={1 if value else 0}\n" for key, value in sorted(overrides.items()))
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


class FakeConfigRevisions:
    def __init__(self, config_text: str | None = None) -> None:
        self.config_text = config_text or "http_port 3128\nssl_bump splice all\nadaptation_access av_resp_set allow icap_av_scanable\n"
        self.created: list[dict[str, Any]] = []
        self.applied: list[dict[str, Any]] = []

    def get_active_config_text(self, _proxy_id: object | None) -> str:
        return self.config_text

    def ensure_active_revision(self, proxy_id: object, config_text: str, **kwargs: Any) -> Any:
        return self.create_revision(proxy_id, config_text, activate=True, **kwargs)

    def create_revision(self, proxy_id: object, config_text: str, **kwargs: Any) -> Any:
        self.config_text = config_text
        revision_id = len(self.created) + 1
        self.created.append({"proxy_id": proxy_id, "config_text": config_text, "revision_id": revision_id, **kwargs})
        return SimpleNamespace(revision_id=revision_id, config_sha256="sha", config_text=config_text)

    def record_apply_result(self, proxy_id: object, revision_id: int, **kwargs: Any) -> Any:
        row = {"proxy_id": proxy_id, "revision_id": revision_id, **kwargs}
        self.applied.append(row)
        return SimpleNamespace(application_id=len(self.applied), applied_ts=1, ok=bool(kwargs.get("ok")), detail=kwargs.get("detail", ""))

    def latest_apply(self, _proxy_id: object | None) -> Any | None:
        if not self.applied:
            return None
        row = self.applied[-1]
        return SimpleNamespace(applied_ts=1, ok=bool(row.get("ok")), detail=row.get("detail", ""), applied_by="test")


class EmptyExclusions:
    domains: list[str] = []
    src_nets: list[str] = []
    exclude_private_nets = False


class FakeExclusionsStore:
    def __init__(self) -> None:
        self.domains: list[str] = []
        self.src_nets: list[str] = []
        self.exclude_private_nets = False

    def list_all(self) -> Any:
        return SimpleNamespace(domains=list(self.domains), src_nets=list(self.src_nets), exclude_private_nets=self.exclude_private_nets)

    def add_domain(self, value: str) -> tuple[bool, str]:
        value = (value or "").strip().lower()
        if not value or " " in value or "/" in value:
            return False, "Invalid domain."
        if value not in self.domains:
            self.domains.append(value)
        return True, ""

    def remove_domain(self, value: str) -> None:
        value = (value or "").strip().lower()
        self.domains = [item for item in self.domains if item != value]

    def add_net(self, target: str, value: str) -> tuple[bool, str]:
        value = (value or "").strip()
        if target != "src_nets":
            return False, "Invalid target."
        if "/" not in value or "bad" in value:
            return False, "Invalid CIDR."
        if value not in self.src_nets:
            self.src_nets.append(value)
        return True, ""

    def remove_net(self, _target: str, value: str) -> None:
        self.src_nets = [item for item in self.src_nets if item != value]

    def set_exclude_private_nets(self, enabled: bool) -> None:
        self.exclude_private_nets = bool(enabled)


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
        return {"summary": {}, "destinations": [], "clients": [], "cache_reasons": [], "ssl": {}, "security": {}, "performance": {}}

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

    def top_destinations(self, **_kwargs: Any) -> list[Any]:
        return []


class FakeAdblockStore:
    def __init__(self) -> None:
        self.settings = {"enabled": True, "cache_ttl": 3600, "cache_max": 200000}
        self.statuses = [SimpleNamespace(key="default", url="https://example.invalid/list.txt", enabled=True, rules=0, bytes=0, last_success=0, last_attempt=0, last_error="")]
        self.refresh_requested = 0
        self.cache_flush_requested = 0

    def init_db(self) -> None:
        return None

    def list_statuses(self) -> list[Any]:
        return list(self.statuses)

    def set_enabled(self, enabled_map: dict[str, bool]) -> None:
        for status in self.statuses:
            status.enabled = bool(enabled_map.get(status.key, False))

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
        return {"hits": 0, "misses": 0, "evictions": 0, "current_size": 0, "last_flush": 0, "last_flush_req": 0}

    def get_update_interval_seconds(self) -> int:
        return 3600


class FakeWebfilterStore:
    def __init__(self) -> None:
        self.settings = SimpleNamespace(enabled=False, source_url="", blocked_categories=[])
        self.whitelist: list[tuple[str, int]] = []

    def init_db(self) -> None:
        return None

    def get_settings(self) -> Any:
        return self.settings

    def set_settings(self, *, enabled: bool, source_url: str, blocked_categories: list[str]) -> None:
        self.settings = SimpleNamespace(enabled=enabled, source_url=source_url, blocked_categories=blocked_categories)

    def list_available_categories(self) -> list[Any]:
        return [SimpleNamespace(key="adult", label="Adult"), SimpleNamespace(key="games", label="Games")]

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
        self.rows: list[tuple[str, int]] = []

    def init_db(self) -> None:
        return None

    def list_nobump(self) -> list[tuple[str, int]]:
        return list(self.rows)

    def add_nobump(self, cidr: str) -> tuple[bool, str, str]:
        cidr = (cidr or "").strip()
        if not cidr or "bad" in cidr:
            return False, "Invalid CIDR.", ""
        self.rows.append((cidr, 1))
        return True, "", cidr

    def remove_nobump(self, cidr: str) -> None:
        self.rows = [row for row in self.rows if row[0] != cidr]


class FakePacProfilesStore:
    def __init__(self) -> None:
        self.profiles: dict[int, Any] = {}
        self.next_id = 1

    def list_profiles(self) -> list[Any]:
        return list(self.profiles.values())

    def upsert_profile(self, *, profile_id: int | None, name: str, client_cidr: str, direct_domains_text: str, direct_dst_nets_text: str) -> tuple[bool, str, int | None]:
        if client_cidr and "/" not in client_cidr:
            return False, "Invalid CIDR.", None
        if profile_id is not None and profile_id not in self.profiles:
            return False, "Profile not found.", None
        pid = profile_id or self.next_id
        if profile_id is None:
            self.next_id += 1
        domains = [line.strip() for line in direct_domains_text.splitlines() if line.strip()]
        nets = [line.strip() for line in direct_dst_nets_text.splitlines() if line.strip()]
        self.profiles[pid] = SimpleNamespace(id=pid, name=name, client_cidr=client_cidr, direct_domains=domains, direct_dst_nets=nets)
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
        revision = SimpleNamespace(revision_id=len(self.created) + 1, bundle_sha256=getattr(bundle, "bundle_sha256", "bundle-sha"))
        self.created.append(revision)
        return revision

    def record_apply_result(self, proxy_id: object, revision_id: int, **kwargs: Any) -> Any:
        self.applied.append({"proxy_id": proxy_id, "revision_id": revision_id, **kwargs})
        return SimpleNamespace(application_id=len(self.applied))

    def latest_apply(self, _proxy_id: object | None) -> Any | None:
        if not self.applied:
            return None
        row = self.applied[-1]
        return SimpleNamespace(ok=bool(row.get("ok")), detail=row.get("detail", ""), applied_ts=1)


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
    fake_revisions = overrides.get("config_revisions") or FakeConfigRevisions(fake_controller.get_current_config())
    fake_proxy_client = overrides.get("proxy_client") or FakeProxyClient(admin_app)
    fake_certificates = overrides.get("certificate_bundles") or FakeCertificateBundles()

    services = admin_app.AppRuntimeServices(
        controller=fake_controller,
        get_certificate_bundles=lambda: fake_certificates,
        get_config_revisions=lambda: fake_revisions,
        get_diagnostic_store=lambda: overrides.get("diagnostic_store") or FakeDiagnosticStore(),
        get_exclusions_store=lambda: overrides.get("exclusions_store") or FakeExclusionsStore(),
        get_audit_store=lambda: fake_audit,
        get_timeseries_store=lambda: overrides.get("timeseries_store") or FakeTimeseriesStore(),
        get_ssl_errors_store=lambda: overrides.get("ssl_errors_store") or FakeSslErrorsStore(),
        get_adblock_store=lambda: overrides.get("adblock_store") or FakeAdblockStore(),
        get_webfilter_store=lambda: overrides.get("webfilter_store") or FakeWebfilterStore(),
        get_sslfilter_store=lambda: overrides.get("sslfilter_store") or FakeSslfilterStore(),
        get_pac_profiles_store=lambda: overrides.get("pac_profiles_store") or FakePacProfilesStore(),
        get_proxy_client=lambda: fake_proxy_client,
        get_proxy_registry=lambda: fake_registry,
        get_observability_queries=lambda: overrides.get("observability_queries") or FakeObservabilityQueries(),
        check_icap_adblock=lambda: {"ok": True, "detail": "ok"},
        check_icap_av=lambda: {"ok": True, "detail": "ok"},
        check_clamd=lambda: {"ok": True, "detail": "ok"},
        send_sample_av_icap=lambda: {"ok": True, "detail": "204 No Content"},
        test_eicar=lambda: {"ok": False, "detail": "EICAR unavailable"},
    )

    monkeypatch.setattr(admin_app, "_auth_store", fake_auth)
    monkeypatch.setattr(admin_app, "_app_runtime_services", lambda: services)
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
    raise AssertionError(f"Could not find CSRF token in response for {path}: {text[:200]!r}")


def login_client(client: Any, username: str = "admin", password: str = "admin") -> Any:
    token = csrf_token(client, "/login")
    response = client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": token},
        follow_redirects=False,
    )
    assert response.status_code in {302, 303}
    return response
