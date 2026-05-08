from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
STYLE = REPO_ROOT / "web" / "static" / "style.css"
TEMPLATES = REPO_ROOT / "web" / "templates"


def test_card_split_widths_are_opt_in_layouts() -> None:
    css = STYLE.read_text(encoding="utf-8")

    assert "width: min(1600px, calc(100% - 32px));" in css
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


def test_ssl_policy_rule_cards_are_not_forced_into_sidebar_widths() -> None:
    html = (TEMPLATES / "sslfilter.html").read_text(encoding="utf-8")

    assert '<div class="grid">' in html
    assert 'class="grid split-layout"' not in html
    assert 'class="grid sidebar-wide-layout"' not in html
