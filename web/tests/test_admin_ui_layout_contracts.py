from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
STYLE = REPO_ROOT / "web" / "static" / "style.css"
TEMPLATES = REPO_ROOT / "web" / "templates"


def test_card_split_widths_are_opt_in_layouts() -> None:
    css = STYLE.read_text(encoding="utf-8")

    assert "width: min(1600px, calc(100% - 32px));" in css
    assert ".grid > .split-left," in css
    assert ".grid > .split-right" in css
    assert ".grid.split-layout > .card.split-left" in css
    assert ".grid.sidebar-wide-layout > .card.split-left" in css
    assert ".grid.data-pair-layout > .card.split-left" in css
    assert ".card.split-left{ grid-column" not in css
    assert ".card.split-right{ grid-column" not in css


def test_pages_with_sidebars_declare_their_layout_intent() -> None:
    expected = {
        "adblock.html": "grid split-layout",
        "administration.html": "grid sidebar-wide-layout",
        "certs.html": "grid sidebar-wide-layout",
        "index.html": "grid sidebar-wide-layout",
        "webfilter.html": "grid sidebar-wide-layout",
    }

    for template_name, grid_class in expected.items():
        html = (TEMPLATES / template_name).read_text(encoding="utf-8")
        assert f'class="{grid_class}"' in html


def test_observability_data_tables_use_balanced_pairs() -> None:
    html = (TEMPLATES / "observability.html").read_text(encoding="utf-8")

    assert html.count('class="grid data-pair-layout"') == 4
    assert "Top clients" in html
    assert "Slowest ICAP events" in html


def test_observability_overview_explains_fleet_wide_clear_logs() -> None:
    html = (TEMPLATES / "observability.html").read_text(encoding="utf-8")

    assert "Clear Logs" in html
    assert "fleet-wide database maintenance action" in html
    assert "stored MySQL request, SSL, security, web-filter, ad-block, and performance log history" in html
    assert "Wiped stored MySQL observability history from" in html
    assert "without changing proxy configuration or policy settings" in html


def test_clamav_page_explains_configurable_failure_behavior() -> None:
    html = (TEMPLATES / "clamav.html").read_text(encoding="utf-8")

    assert "fail-{{ clamav_options.clamav_fail_mode }}" in html
    assert "bypass=on" in html
    assert "bypass=off" in html
    assert "virus_scan.PassOnError on" in html
    assert "PassOnError off" in html


def test_ssl_policy_rule_cards_are_not_forced_into_sidebar_widths() -> None:
    html = (TEMPLATES / "sslfilter.html").read_text(encoding="utf-8")

    assert '<div class="grid">' in html
    assert 'class="grid split-layout"' not in html
    assert 'class="grid sidebar-wide-layout"' not in html


def test_relevant_ui_pages_warn_that_http3_quic_uses_udp_443() -> None:
    expected = {
        "squid_config.html": "HTTP/3/QUIC uses <strong>UDP/443</strong>",
        "sslfilter.html": "HTTP/3/QUIC uses UDP/443",
        "pac.html": "HTTP/3/QUIC over UDP/443",
    }

    for template_name, phrase in expected.items():
        html = (TEMPLATES / template_name).read_text(encoding="utf-8")
        assert phrase in html, template_name


def test_templates_do_not_force_full_width_with_inline_styles() -> None:
    for template in TEMPLATES.glob("*.html"):
        html = template.read_text(encoding="utf-8")
        assert 'style="grid-column: 1 / -1; justify-self: stretch; width: 100%;"' not in html, template.name


def test_login_page_does_not_advertise_default_credentials_or_fixed_port() -> None:
    html = (TEMPLATES / "login.html").read_text(encoding="utf-8")

    assert "admin / admin" not in html
    assert "Default credentials" not in html
    assert "Port 5000" not in html
    assert "admin UI" in html


def test_pac_nav_has_server_rendered_active_state() -> None:
    html = (TEMPLATES / "layout.html").read_text(encoding="utf-8")

    assert "request.endpoint == 'pac_builder'" in html


def test_proxy_management_lives_in_context_strip_not_top_nav() -> None:
    html = (TEMPLATES / "layout.html").read_text(encoding="utf-8")

    assert ">Manage proxies</a>" in html
    assert ">Proxies</a>" not in html


def test_layout_uses_docker_proxy_visible_branding_and_titles() -> None:
    html = (TEMPLATES / "layout.html").read_text(encoding="utf-8")

    assert "Docker Proxy" in html
    assert "Squid Flask Proxy" not in html
    assert "{% block title %}Docker Proxy{% endblock %}" in html
    assert 'aria-label="Docker Proxy home"' in html


def test_operations_template_uses_shared_shell_and_ledger_classes() -> None:
    html = (TEMPLATES / "operations.html").read_text(encoding="utf-8")

    assert "Operations | Docker Proxy" in html
    assert 'class="page-hero-copy"' in html
    assert 'class="stats-grid compact-stats operation-counts"' in html
    assert 'class="card operations-ledger-card"' in html
    assert 'class="card-body operations-ledger"' in html
    assert 'class="metric-label"' in html


def test_policy_requests_template_uses_shared_shell_and_table_classes() -> None:
    html = (TEMPLATES / "requests.html").read_text(encoding="utf-8")

    assert "Policy Requests | Docker Proxy" in html
    assert 'class="page-hero-copy"' in html
    assert 'class="card-title"' in html
    assert 'class="card-body"' in html
    assert 'class="table"' in html
    assert 'class="checkbox-inline"' in html
    assert 'aria-labelledby="pending-requests-heading"' in html
    assert 'aria-label="Review request {{ r.id }} for {{ r.domain }}"' in html
    assert 'aria-label="Revoke exception {{ e.id }} for {{ e.domain }}"' in html


def test_admin_dockerfile_packages_observability_maintenance_service() -> None:
    dockerfile = (REPO_ROOT / "docker" / "Dockerfile.admin").read_text(encoding="utf-8")

    assert "web/services/observability_maintenance.py" in dockerfile
