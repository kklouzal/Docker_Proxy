from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "web"
if str(WEB) not in sys.path:
    sys.path.insert(0, str(WEB))

from services.squid_config_forms import build_template_options, build_template_options_from_form, get_config_ui_field_map  # type: ignore  # noqa: E402
from services.squidctl import SquidController  # type: ignore  # noqa: E402


def test_cache_mgr_default_metadata_and_rendered_config() -> None:
    options = build_template_options({}, max_workers=4)
    assert options["cache_mgr_email"] == "proxy-admin@example.invalid"
    field = get_config_ui_field_map()["cache_mgr_email"]
    assert field.directive == "cache_mgr"
    assert field.section == "http"
    controller = SquidController()
    controller.squid_conf_template_path = str(ROOT / "squid" / "squid.conf.template")
    assert "cache_mgr proxy-admin@example.invalid" in controller.generate_config_from_template(options)


def test_cache_mgr_form_override_renders_cache_mgr() -> None:
    options = build_template_options_from_form({}, {"cache_mgr_email": "helpdesk@example.test"}, form_kind="http", max_workers=4)
    controller = SquidController()
    controller.squid_conf_template_path = str(ROOT / "squid" / "squid.conf.template")
    assert "cache_mgr helpdesk@example.test" in controller.generate_config_from_template(options)


def test_branded_error_pages_have_user_guidance_before_request_details() -> None:
    pages = list((ROOT / "squid" / "error_pages" / "en").glob("ERR_*"))
    assert pages
    for page in pages:
        text = page.read_text(encoding="utf-8")
        assert "<strong>User guidance</strong>" in text
        assert "rgba(52,211,153" in text
        assert text.index('<div class="user">') < text.index('aria-label="Request details"')
        assert "%U" in text
        assert "%T" in text
    dns = (ROOT / "squid" / "error_pages" / "en" / "ERR_DNS_FAIL").read_text(encoding="utf-8")
    assert "could not find that site name" in dns
