from .flask_test_helpers import login, redirect_query_params
from .ui_pages_test_support import app_module  # noqa: F401


def test_index_post_actions_work(app_module):
    c = app_module.app.test_client()
    csrf = login(c)

    r1 = c.post("/reload", headers={"X-CSRF-Token": csrf}, data={}, follow_redirects=False)
    assert r1.status_code in (301, 302, 303, 307, 308)

    r2 = c.post("/cache/clear", headers={"X-CSRF-Token": csrf}, data={}, follow_redirects=False)
    assert r2.status_code in (301, 302, 303, 307, 308)

    calls = getattr(app_module, "_test_calls")
    assert calls["reload"] == 1
    assert calls["clear"] == 1


def test_ssl_errors_exclude_posts_domain(app_module):
    c = app_module.app.test_client()
    csrf = login(c)

    r = c.post(
        "/ssl-errors/exclude",
        headers={"X-CSRF-Token": csrf},
        data={"domain": "Example.COM"},
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)

    store = getattr(app_module, "_test_fake_ex_store")
    assert "example.com" in store.added_domains


def test_ssl_errors_page_shows_operator_friendly_summary(app_module, monkeypatch):
    from types import SimpleNamespace

    class FakeSSL:
        def list_recent(self, *, since: int, search: str, limit: int):
            return [
                SimpleNamespace(
                    domain="Example.com",
                    category="CERT_VERIFY",
                    reason="certificate verify failed",
                    count=4,
                    first_seen=1713446400,
                    last_seen=1713448200,
                    sample="CONNECT example.com:443",
                ),
                SimpleNamespace(
                    domain="",
                    category="TLS_OTHER",
                    reason="error detail: SQUID_TLS_ERR_ACCEPT+TLS_LIB_ERR=A000119+TLS_IO_ERR=1",
                    count=2,
                    first_seen=1713446500,
                    last_seen=1713448300,
                    sample="error detail: SQUID_TLS_ERR_ACCEPT+TLS_LIB_ERR=A000119+TLS_IO_ERR=1\nconnection: conn23 local=10.0.0.5:3128 remote=192.0.2.10:54432",
                ),
            ]

        def top_domains(self, *, since: int, search: str, limit: int):
            return [
                {"domain": "example.com", "total": 4, "buckets": 1, "last_seen": 1713448200},
                {"domain": "", "total": 2, "buckets": 1, "last_seen": 1713448300},
            ]

    monkeypatch.setattr(app_module, "get_ssl_errors_store", lambda: FakeSSL())

    c = app_module.app.test_client()
    login(c)

    r = c.get("/ssl-errors?window=3600")
    assert r.status_code == 200
    body = r.data.decode("utf-8", errors="replace")
    assert "At a glance" in body
    assert "Operator guidance" in body
    assert "Treat exclusions as a last-mile workaround" in body
    assert "Client-side TLS accept failure" in body
    assert "Start with client trust and bump compatibility" in body
    assert "Decoded TLS library code A000119" in body
    assert "decryption failed or bad record MAC" in body
    assert "This happened on the client -&gt; proxy TLS leg" in body or "This happened on the client -> proxy TLS leg" in body
    assert "Latest connection context: client 192.0.2.10:54432 -&gt; proxy 10.0.0.5:3128 (conn23)." in body or "Latest connection context: client 192.0.2.10:54432 -> proxy 10.0.0.5:3128 (conn23)." in body
    assert "Trust / chain failure" in body
    assert "Hostname not captured" in body
    assert "Correlate first; there is no domain to exclude yet." in body
    assert "Top domains worth checking" in body
    assert "example.com" in body


def test_ssl_errors_page_explains_missing_followup_context_for_tls_accept(app_module, monkeypatch):
    from types import SimpleNamespace

    class FakeSSL:
        def list_recent(self, *, since: int, search: str, limit: int):
            return [
                SimpleNamespace(
                    domain="",
                    category="TLS_OTHER",
                    reason="2026/04/21 23:37:04 kid1| ERROR: Cannot accept a TLS connection",
                    count=2,
                    first_seen=1713446500,
                    last_seen=1713448300,
                    sample="error detail: SQUID_TLS_ERR_ACCEPT+TLS_LIB_ERR=A000119+TLS_IO_ERR=1",
                ),
            ]

        def top_domains(self, *, since: int, search: str, limit: int):
            return []

    monkeypatch.setattr(app_module, "get_ssl_errors_store", lambda: FakeSSL())

    c = app_module.app.test_client()
    login(c)

    r = c.get("/ssl-errors?window=3600")
    assert r.status_code == 200
    body = r.data.decode("utf-8", errors="replace")
    assert "Client-side TLS accept failure" in body
    assert "Squid did not emit any follow-up connection or master-transaction context" in body


def test_live_page_offers_quick_exclusion_actions(app_module, monkeypatch):
    class FakeLive:
        def get_totals(self, *, since: int):
            return {"domain_requests": 10, "domain_hit_requests": 7, "client_requests": 4, "client_hit_requests": 1}

        def list_domains(self, *, sort: str, order: str, limit: int, since: int, search: str):
            return [{"domain": "example.com", "requests": 10, "pct": 100.0, "cache_pct": 70.0, "last_seen": 1713448200}]

        def list_clients(self, *, sort: str, order: str, limit: int, since: int, search: str):
            return []

        def list_client_domains(self, *, ip: str, sort: str):
            return []

        def list_client_not_cached(self, *, ip: str, limit: int):
            return []

        def list_domain_not_cached_reasons(self, *, domain: str, limit: int):
            return []

        def list_global_not_cached_reasons(self, *, limit: int):
            return 0, []

    monkeypatch.setattr(app_module, "get_store", lambda: FakeLive())

    c = app_module.app.test_client()
    login(c)

    r = c.get("/live?mode=domains&window=3600")
    assert r.status_code == 200
    body = r.data.decode("utf-8", errors="replace")
    assert "At a glance" in body
    assert "Add to exclusions" in body
    assert "SSL errors" in body
    assert 'name="return_to"' in body


def test_live_page_shows_recent_diagnostic_transactions(app_module, monkeypatch):
    class FakeLive:
        def get_totals(self, *, since: int):
            return {"domain_requests": 10, "domain_hit_requests": 7, "client_requests": 4, "client_hit_requests": 1}

        def list_domains(self, *, sort: str, order: str, limit: int, since: int, search: str):
            return [{"domain": "example.com", "requests": 10, "pct": 100.0, "cache_pct": 70.0, "last_seen": 1713448200}]

        def list_clients(self, *, sort: str, order: str, limit: int, since: int, search: str):
            return []

        def list_client_domains(self, *, ip: str, sort: str):
            return []

        def list_client_not_cached(self, *, ip: str, limit: int):
            return []

        def list_domain_not_cached_reasons(self, *, domain: str, limit: int):
            return []

        def list_global_not_cached_reasons(self, *, limit: int):
            return 0, []

    class FakeDiagnostic:
        def list_recent_transactions(self, *, since: int | None = None, search: str = "", client_ip: str = "", domain: str = "", master_xaction: str = "", service: str = "", limit: int = 50, icap_limit_per_transaction: int = 5):
            return [
                {
                    "ts": 1713448200,
                    "duration_ms": 125,
                    "client_ip": "192.0.2.10",
                    "method": "GET",
                    "target_display": "example.com",
                    "url": "https://example.com/download.bin",
                    "result_code": "TCP_MISS/200",
                    "hierarchy_status": "DIRECT",
                    "bytes": 1024,
                    "tls_summary": "bump=bump · sni=example.com",
                    "tls_server_version": "TLSv1.3",
                    "tls_server_cipher": "TLS_AES_256_GCM_SHA384",
                    "tls_client_version": "TLSv1.3",
                    "tls_client_cipher": "TLS_AES_128_GCM_SHA256",
                    "host": "example.com",
                    "user_agent": "Mozilla/5.0",
                    "referer": "https://portal.example.com/",
                    "policy_tags": ["ssl:steam"],
                    "master_xaction": "tx123",
                    "domain": "example.com",
                    "related_icap": [
                        {
                            "service_family": "av",
                            "service_label": "AV / ClamAV",
                            "icap_time_ms": 42,
                            "adapt_summary": "avrespmod / virus_scan allow",
                            "adapt_details": "clamd clean",
                            "policy_tags": ["cache:cookie"],
                            "master_xaction": "tx123",
                            "host": "example.com",
                            "sni": "example.com",
                            "user_agent": "Mozilla/5.0",
                            "referer": "-",
                        }
                    ],
                }
            ]

        def top_request_dimension(self, dimension: str, *, since: int | None = None, limit: int = 10):
            return [{"value": "Mozilla/5.0" if dimension == "user_agent" else "bump", "count": 3, "last_seen": 1713448200}]

        def top_policy_tags(self, *, since: int | None = None, limit: int = 10):
            return [{"tag": "ssl:steam", "count": 3, "last_seen": 1713448200}]

        def slowest_requests(self, *, since: int | None = None, limit: int = 10):
            return self.list_recent_transactions(limit=limit)

        def slowest_icap_events(self, *, since: int | None = None, service: str = "", limit: int = 10):
            return self.list_recent_transactions(limit=1)[0]["related_icap"]

    monkeypatch.setattr(app_module, "get_store", lambda: FakeLive())
    monkeypatch.setattr(app_module, "get_diagnostic_store", lambda: FakeDiagnostic())

    c = app_module.app.test_client()
    login(c)

    r = c.get("/live?mode=domains&window=3600")
    assert r.status_code == 200
    body = r.data.decode("utf-8", errors="replace")
    assert "Recent diagnostic transactions" in body
    assert "tx123" in body
    assert "TCP_MISS/200" in body
    assert "bump=bump" in body
    assert "AV / ClamAV" in body
    assert "Master transaction (optional)" in body
    assert "Referer:" in body
    assert "Traffic facets" in body
    assert "Slow paths" in body


def test_ssl_errors_page_shows_correlated_request_and_icap_activity(app_module, monkeypatch):
    from types import SimpleNamespace

    class FakeSSL:
        def list_recent(self, *, since: int, search: str, limit: int):
            return [
                SimpleNamespace(
                    domain="example.com",
                    category="TLS_OTHER",
                    reason="error detail: SQUID_TLS_ERR_ACCEPT+TLS_LIB_ERR=A000119+TLS_IO_ERR=1",
                    count=2,
                    first_seen=1713446500,
                    last_seen=1713448300,
                    sample="error detail: SQUID_TLS_ERR_ACCEPT+TLS_LIB_ERR=A000119+TLS_IO_ERR=1\ncurrent master transaction: tx999",
                ),
            ]

        def top_domains(self, *, since: int, search: str, limit: int):
            return []

    class FakeDiagnostic:
        def find_request_by_master_xaction(self, master_xaction: str):
            return {
                "method": "CONNECT",
                "target_display": "example.com",
                "client_ip": "192.0.2.55",
                "result_code": "TCP_TUNNEL/200",
                "tls_summary": "bump=splice · sni=example.com",
                "policy_tags": ["ssl:sslfilter_nobump"],
            }

        def list_icap_by_master_xaction(self, master_xaction: str, *, limit: int = 10):
            return [
                {
                    "service_label": "AV / ClamAV",
                    "icap_time_ms": 42,
                    "adapt_summary": "avrespmod / virus_scan allow",
                }
            ]

    monkeypatch.setattr(app_module, "get_ssl_errors_store", lambda: FakeSSL())
    monkeypatch.setattr(app_module, "get_diagnostic_store", lambda: FakeDiagnostic())

    c = app_module.app.test_client()
    login(c)

    r = c.get("/ssl-errors?window=3600")
    assert r.status_code == 200
    body = r.data.decode("utf-8", errors="replace")
    assert "Master transaction: tx999" in body
    assert "Correlated request:" in body
    assert "AV / ClamAV" in body
    assert "Exact master transaction match" in body


def test_ssl_errors_page_shows_possible_matches_when_transaction_missing(app_module, monkeypatch):
    from types import SimpleNamespace

    class FakeSSL:
        def list_recent(self, *, since: int, search: str, limit: int):
            return [
                SimpleNamespace(
                    domain="example.com",
                    category="TLS_OTHER",
                    reason="handshake failure",
                    count=1,
                    first_seen=1713446500,
                    last_seen=1713448300,
                    sample="CONNECT example.com:443",
                ),
            ]

        def top_domains(self, *, since: int, search: str, limit: int):
            return []

    class FakeDiagnostic:
        def find_request_by_master_xaction(self, master_xaction: str):
            return None

        def list_icap_by_master_xaction(self, master_xaction: str, *, limit: int = 10):
            return []

        def list_request_candidates_for_domain_near_ts(self, *, domain: str, around_ts: int, window_seconds: int = 300, limit: int = 3):
            return [
                {
                    "ts": 1713448290,
                    "duration_ms": 90,
                    "client_ip": "192.0.2.90",
                    "method": "CONNECT",
                    "target_display": "example.com",
                    "url": "example.com:443",
                    "result_code": "TCP_TUNNEL/200",
                    "http_status": 200,
                    "bytes": 2048,
                    "master_xaction": "tx-possible",
                    "hierarchy_status": "DIRECT",
                    "bump_mode": "splice",
                    "sni": "example.com",
                    "tls_server_version": "TLSv1.3",
                    "tls_server_cipher": "TLS_AES_256_GCM_SHA384",
                    "tls_client_version": "TLSv1.3",
                    "tls_client_cipher": "TLS_AES_128_GCM_SHA256",
                    "host": "example.com",
                    "user_agent": "App/1.0",
                    "referer": "-",
                    "policy_tags": ["ssl:sslfilter_nobump"],
                    "related_icap": [],
                    "correlation_kind": "domain_time",
                    "time_delta_seconds": 10,
                }
            ]

        def list_icap_candidates_for_domain_near_ts(self, *, domain: str, around_ts: int, window_seconds: int = 300, limit: int = 3):
            return []

    monkeypatch.setattr(app_module, "get_ssl_errors_store", lambda: FakeSSL())
    monkeypatch.setattr(app_module, "get_diagnostic_store", lambda: FakeDiagnostic())

    c = app_module.app.test_client()
    login(c)

    r = c.get("/ssl-errors?window=3600")
    assert r.status_code == 200
    body = r.data.decode("utf-8", errors="replace")
    assert "Possible related transactions:" in body
    assert "Possible match (domain + time)" in body
    assert "sslfilter_nobump" in body


def test_clamav_page_shows_recent_av_icap_transactions(app_module, monkeypatch):
    class FakeDiagnostic:
        def list_recent_icap(self, *, since: int | None = None, search: str = "", client_ip: str = "", domain: str = "", master_xaction: str = "", service: str = "", limit: int = 50):
            return [
                {
                    "ts": 1713448200,
                    "client_ip": "192.0.2.10",
                    "method": "GET",
                    "target_display": "downloads.example.com",
                    "url": "https://downloads.example.com/file.exe",
                    "icap_time_ms": 87,
                    "service_label": "AV / ClamAV",
                    "adapt_summary": "avrespmod / virus_scan allow",
                    "adapt_details": "clamd clean",
                    "policy_tags": ["cache:cookie"],
                    "master_xaction": "tx777",
                    "host": "downloads.example.com",
                    "sni": "downloads.example.com",
                    "user_agent": "Mozilla/5.0",
                    "referer": "-",
                }
            ]

        def find_request_by_master_xaction(self, master_xaction: str):
            return {
                "ts": 1713448198,
                "duration_ms": 140,
                "client_ip": "192.0.2.10",
                "method": "GET",
                "target_display": "downloads.example.com",
                "url": "https://downloads.example.com/file.exe",
                "result_code": "TCP_MISS/200",
                "http_status": 200,
                "bytes": 4096,
                "master_xaction": master_xaction,
                "hierarchy_status": "DIRECT",
                "bump_mode": "bump",
                "sni": "downloads.example.com",
                "tls_server_version": "TLSv1.3",
                "tls_server_cipher": "TLS_AES_256_GCM_SHA384",
                "tls_client_version": "TLSv1.3",
                "tls_client_cipher": "TLS_AES_128_GCM_SHA256",
                "host": "downloads.example.com",
                "user_agent": "Mozilla/5.0",
                "referer": "-",
                "policy_tags": ["cache:cookie"],
                "related_icap": [],
            }

        def icap_summary(self, *, since: int | None = None, service: str = ""):
            return {"events": 1, "avg_icap_time_ms": 87, "max_icap_time_ms": 87}

        def slowest_icap_events(self, *, since: int | None = None, service: str = "", limit: int = 10):
            return self.list_recent_icap(limit=limit)

    monkeypatch.setattr(app_module, "get_diagnostic_store", lambda: FakeDiagnostic())

    c = app_module.app.test_client()
    login(c)

    r = c.get("/clamav?window=3600")
    assert r.status_code == 200
    body = r.data.decode("utf-8", errors="replace")
    assert "Recent AV ICAP transactions" in body
    assert "AV / ClamAV" in body
    assert "tx777" in body
    assert "Request:" in body
    assert "Master transaction (optional)" in body
    assert "Average ICAP time" in body


def test_ssl_errors_page_shows_affected_client_rollups(app_module, monkeypatch):
    from types import SimpleNamespace

    class FakeSSL:
        def list_recent(self, *, since: int, search: str, limit: int):
            return [
                SimpleNamespace(
                    domain="example.com",
                    category="TLS_OTHER",
                    reason="broken",
                    count=2,
                    first_seen=1713446400,
                    last_seen=1713448200,
                    sample="current master transaction: txabc",
                ),
            ]

        def top_domains(self, *, since: int, search: str, limit: int):
            return []

    class FakeDiagnostic:
        def find_request_by_master_xaction(self, master_xaction: str):
            return {
                "method": "CONNECT",
                "target_display": "example.com",
                "client_ip": "192.0.2.22",
                "result_code": "TCP_TUNNEL/200",
                "http_status": 200,
                "bump_mode": "splice",
                "user_agent": "ExampleApp/1.0",
                "policy_tags": ["ssl:sslfilter_nobump"],
            }

        def list_icap_by_master_xaction(self, master_xaction: str, *, limit: int = 10):
            return []

    monkeypatch.setattr(app_module, "get_ssl_errors_store", lambda: FakeSSL())
    monkeypatch.setattr(app_module, "get_diagnostic_store", lambda: FakeDiagnostic())

    c = app_module.app.test_client()
    login(c)

    r = c.get("/ssl-errors?window=3600")
    assert r.status_code == 200
    body = r.data.decode("utf-8", errors="replace")
    assert "Affected clients and apps" in body
    assert "192.0.2.22" in body
    assert "ExampleApp/1.0" in body


def test_index_page_shows_observability_shortcuts(app_module):
    c = app_module.app.test_client()
    login(c)

    r = c.get("/")
    assert r.status_code == 200
    body = r.data.decode("utf-8", errors="replace")
    assert "Observability" in body
    assert "Investigate Live" in body
    assert "Review SSL errors" in body
    assert "Trace AV ICAP" in body


def test_exclusions_bulk_add_redirects_with_feedback(app_module):
    c = app_module.app.test_client()
    csrf = login(c)

    r = c.post(
        "/exclusions",
        headers={"X-CSRF-Token": csrf},
        data={
            "action": "add_domain_bulk",
            "domains_bulk": "example.com\ninternal.example\n",
        },
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)

    store = getattr(app_module, "_test_fake_ex_store")
    assert "example.com" in store.added_domains
    assert "internal.example" in store.added_domains
    qs = redirect_query_params(r)
    assert qs.get("bulk_added") == ["2"]


def test_live_quick_add_exclusion_returns_to_live(app_module):
    c = app_module.app.test_client()
    csrf = login(c)

    r = c.post(
        "/exclusions",
        headers={"X-CSRF-Token": csrf},
        data={
            "action": "add_domain",
            "domain": "Example.com",
            "return_to": "/live?mode=domains&window=3600",
        },
        follow_redirects=False,
    )
    assert r.status_code in (301, 302, 303, 307, 308)

    store = getattr(app_module, "_test_fake_ex_store")
    assert "example.com" in store.added_domains
    location = r.headers.get("Location", "") or ""
    assert location.startswith("/live?")
    assert "exclude_added=example.com" in location


def test_clamav_page_separates_policy_and_backend_status(app_module):
    c = app_module.app.test_client()
    login(c)

    r = c.get("/clamav")
    assert r.status_code == 200
    body = r.data.decode("utf-8", errors="replace")
    assert "AV c-icap service" in body
    assert "Clamd backend" in body
    assert "Enable changes the Squid adaptation rule only" in body
