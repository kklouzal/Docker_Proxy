from __future__ import annotations

import pytest

from .admin_route_test_utils import (
    FakeController,
    FakeExclusionsStore,
    load_admin_app,
    login_client,
)


class ExclusionRenderingController(FakeController):
    def generate_config_from_template_with_exclusions(self, options, exclusions):
        lines = self._listener_lines_from_options(options)
        domains = [
            self._normalize_for_squid(domain)
            for domain in (getattr(exclusions, "domains", []) or [])
            if (domain or "").strip()
        ]
        if domains:
            lines.append("acl excluded_domains dstdomain " + " ".join(domains))
            lines.append("ssl_bump splice excluded_domains")
            lines.append("cache deny excluded_domains")
        lines.append(f"cache_mem {int(options.get('cache_mem_mb') or 64)} MB")
        return "\n".join(lines) + "\n"

    @staticmethod
    def _normalize_for_squid(domain: str) -> str:
        value = (domain or "").strip().lower()
        if value.startswith("*."):
            return "." + value[2:].lstrip(".")
        if value.startswith("."):
            return "." + value.lstrip(".")
        return value.lstrip(".")


def _login(client) -> None:
    login_client(client)


def _post(client, path: str, data: dict[str, object], *, csrf_path: str | None = None):
    return client.post(path, data=dict(data), follow_redirects=False)


def _loaded(monkeypatch, tmp_path, *, controller=None):
    monkeypatch.setenv("DISABLE_CSRF", "1")
    exclusions_store = FakeExclusionsStore()
    loaded = load_admin_app(
        monkeypatch,
        tmp_path,
        controller=controller or ExclusionRenderingController(),
        exclusions_store=exclusions_store,
    )
    loaded.exclusions_store = exclusions_store
    client = loaded.module.app.test_client()
    _login(client)
    return loaded, client


def _assert_redirect_success(response) -> None:
    assert response.status_code in {302, 303}
    location = response.headers.get("Location", "")
    assert "error=1" not in location


def test_destination_domain_exclusion_apply_validates_generated_squid_config(monkeypatch, tmp_path) -> None:
    loaded, client = _loaded(monkeypatch, tmp_path)

    response = _post(client, "/exclusions", {"action": "add_domain", "domain": "*.discord.com"})
    _assert_redirect_success(response)
    assert loaded.exclusions_store.domains == ["*.discord.com"]

    response = _post(client, "/exclusions", {"action": "apply"})

    _assert_redirect_success(response)
    assert len(loaded.proxy_client.validated) == 1
    proxy_id, config_text = loaded.proxy_client.validated[0]
    assert proxy_id == "default"
    assert "acl excluded_domains dstdomain .discord.com" in config_text
    assert "*.discord.com" not in config_text
    assert loaded.config_revisions.created[-1]["source_kind"] == "exclusions"
    assert loaded.proxy_client.synced[-1] == ("default", True)


@pytest.mark.parametrize(
    ("path", "data", "expected_source_kind"),
    [
        ("/squid/config/apply-safe", {"form_kind": "caching"}, "template"),
        ("/squid/config/apply-overrides", {"client_no_cache": "on"}, "overrides"),
        ("/clamav/toggle", {"action": "enable"}, "clamav"),
    ],
)
def test_program_controlled_admin_config_mutations_validate_before_sync(monkeypatch, tmp_path, path, data, expected_source_kind) -> None:
    loaded, client = _loaded(monkeypatch, tmp_path)

    csrf_path = "/squid/config" if path.startswith("/squid/config/") else ("/clamav" if path == "/clamav/toggle" else path)
    response = _post(client, path, data, csrf_path=csrf_path)

    _assert_redirect_success(response)
    assert len(loaded.proxy_client.validated) == 1
    assert loaded.config_revisions.created[-1]["source_kind"] == expected_source_kind
    assert loaded.proxy_client.synced == [("default", True)]


@pytest.mark.parametrize(
    ("path", "data"),
    [
        ("/webfilter", {"action": "save", "enabled": "on", "source_url": "https://example.test/categories.txt", "categories": ["adult"]}),
        ("/webfilter", {"action": "whitelist_add", "whitelist_domain": "discord.com"}),
        ("/sslfilter", {"action": "add", "cidr": "192.168.1.0/24"}),
    ],
)
def test_managed_policy_mutations_request_proxy_distribution(monkeypatch, tmp_path, path, data) -> None:
    loaded, client = _loaded(monkeypatch, tmp_path)

    csrf_path = "/squid/config" if path.startswith("/squid/config/") else ("/clamav" if path == "/clamav/toggle" else path)
    response = _post(client, path, data, csrf_path=csrf_path)

    _assert_redirect_success(response)
    assert loaded.proxy_client.synced == [("default", True)]
