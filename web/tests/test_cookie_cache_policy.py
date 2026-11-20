"""Contract tests for caching static assets on cookie-bearing requests.

The live behaviour (hits across cookies, refusal of Set-Cookie/private/no-store/
document replies, collapsed forwarding) is verified against a real Squid; these
tests pin the rendered rules and the migration of stored revisions that still
carry the old blanket `cache deny has_cookie`.
"""

from __future__ import annotations

import re
from pathlib import Path

from services.squid_config_forms import (  # type: ignore
    DEFAULT_CACHE_POLICY_RULES,
    build_template_options,
)
from services.squid_core import (  # type: ignore
    COOKIE_STATIC_CACHE_RULES,
    migrate_legacy_cookie_cache_deny,
)
from services.squidctl import SquidController  # type: ignore

REPO_ROOT = Path(__file__).resolve().parents[2]

# Shape of the cache policy in revisions stored before this change (production
# revision 2026-11-20), flat as it is stored without managed-block comments.
LEGACY_FLAT_POLICY = (
    "acl has_auth req_header Authorization .\n"
    "acl has_cookie req_header Cookie .\n"
    "note cache_bypass auth has_auth\n"
    "note cache_bypass cookie has_cookie\n"
    "cache deny has_auth\n"
    "cache deny has_cookie\n"
    "acl has_vary rep_header Vary .\n"
    "acl vary_encoding_only rep_header Vary ^Accept-Encoding$\n"
    "store_miss deny has_vary !vary_encoding_only\n"
)
LEGACY_REVISION = (
    "http_port 3128\n"
    "cache_mem 256 MB\n"
    "collapsed_forwarding on\n"
    + LEGACY_FLAT_POLICY
    + "refresh_pattern -i \\.(css|js|mjs|map|wasm)(\\?.*)?$ 0 80% 43200 store-stale "
    "override-expire reload-into-ims ignore-no-store\n"
    "http_access allow all\n"
)


def _controller() -> SquidController:
    controller = SquidController()
    controller.squid_conf_template_path = str(
        REPO_ROOT / "squid" / "squid.conf.template"
    )
    return controller


def _directive_lines(text: str) -> list[str]:
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def test_cookie_rules_cache_only_static_urls_and_shareable_replies() -> None:
    lines = _directive_lines(COOKIE_STATIC_CACHE_RULES)

    # Request-time: cookie traffic outside static asset URLs never uses the cache.
    assert "cache deny has_cookie !cookie_static_url" in lines
    # Reply-time: refused replies are never stored for a cookie-bearing request.
    assert "store_miss deny has_cookie cookie_reply_unshareable" in lines
    unshareable = next(
        line for line in lines if line.startswith("acl cookie_reply_unshareable ")
    )
    assert unshareable.split()[3:] == [
        "cookie_reply_sets_cookie",
        "cookie_reply_private",
        "cookie_reply_document",
        "!cookie_reply_shared",
    ]
    private = next(
        line for line in lines if line.startswith("acl cookie_reply_private ")
    )
    for token in ("private", "no-store", "no-cache"):
        assert token in private
    # Diagnostics: request-level bypass first, reply refusal only for non-hits.
    notes = [line for line in lines if line.startswith("note cache_bypass ")]
    assert notes == [
        "note cache_bypass cookie has_cookie !cookie_static_url",
        "note cache_bypass cookie-reply has_cookie !cookie_cache_hit cookie_reply_unshareable",
    ]


def test_cookie_static_url_set_excludes_documents_and_api_types() -> None:
    acl = next(
        line
        for line in _directive_lines(COOKIE_STATIC_CACHE_RULES)
        if line.startswith("acl cookie_static_url ")
    )
    regex = re.compile(acl.split()[-1], re.IGNORECASE)

    for path in (
        "/a.woff2",
        "/b.css",
        "/c.js?v=3",
        "/d.mjs",
        "/e.wasm",
        "/f.SVG",
        "/g.webp",
        "/h.mp4",
        "/i.zip",
    ):
        assert regex.search(path), path
    for path in (
        "/index.html",
        "/page.htm",
        "/api/user",
        "/data.json",
        "/feed.xml",
        "/statement.pdf",
        "/report.xlsx",
        "/x.js/more",
    ):
        assert not regex.search(path), path


def test_cookie_shared_and_document_reply_patterns() -> None:
    lines = _directive_lines(COOKIE_STATIC_CACHE_RULES)

    def acl_regex(name: str) -> re.Pattern[str]:
        # The POSIX regex is the last token; only the space class differs in Python.
        line = next(line for line in lines if line.startswith(f"acl {name} "))
        return re.compile(line.split()[-1].replace("[:space:]", r"\s"), re.IGNORECASE)

    shared = acl_regex("cookie_reply_shared")
    for value in (
        "public, max-age=60",
        "max-age=31536000, immutable",
        "s-maxage=600",
        "max-age=1,s-maxage=10",
    ):
        assert shared.search(value), value
    for value in ("max-age=3600", "s-maxage=0", "max-age=60, s-maxage=00", "no-public"):
        assert not shared.search(value), value

    private = acl_regex("cookie_reply_private")
    for value in (
        "private",
        "public, no-store",
        "no-cache",
        'private="Set-Cookie"',
        "max-age=0,no-cache",
    ):
        assert private.search(value), value
    for value in ("public, max-age=60", "x-private-ext=1", "no-transform"):
        assert not private.search(value), value

    document = acl_regex("cookie_reply_document")
    for value in (
        "text/html; charset=utf-8",
        "application/json",
        "application/ld+json",
        "text/xml",
    ):
        assert document.search(value), value
    for value in (
        "image/svg+xml",
        "application/javascript",
        "text/css",
        "font/woff2",
        "image/png",
    ):
        assert not document.search(value), value


def test_default_policy_and_template_carry_cookie_rules() -> None:
    assert COOKIE_STATIC_CACHE_RULES in DEFAULT_CACHE_POLICY_RULES
    default_lines = _directive_lines(DEFAULT_CACHE_POLICY_RULES)
    assert "cache deny has_cookie" not in default_lines
    assert "cache deny has_auth" in default_lines
    # ACLs must be defined before the rules that use them.
    assert default_lines.index(
        "acl has_cookie req_header Cookie ."
    ) < default_lines.index("cache deny has_cookie !cookie_static_url")
    # The auth note precedes the cookie notes: Squid logs the first matching value.
    assert default_lines.index("note cache_bypass auth has_auth") < default_lines.index(
        "note cache_bypass cookie has_cookie !cookie_static_url"
    )

    template = (REPO_ROOT / "squid" / "squid.conf.template").read_text(encoding="utf-8")
    assert (
        "# BEGIN SQUID-UI BLOCK: CACHE_POLICY\n"
        + DEFAULT_CACHE_POLICY_RULES
        + "\n# END SQUID-UI BLOCK: CACHE_POLICY"
    ) in template

    rendered = _controller().generate_config_from_template(
        build_template_options({}, max_workers=4)
    )
    assert DEFAULT_CACHE_POLICY_RULES in rendered
    assert "ignore-private" not in "\n".join(_directive_lines(rendered))


def test_normalize_migrates_legacy_flat_cookie_deny_idempotently() -> None:
    controller = _controller()

    normalized = controller.normalize_config_text(LEGACY_REVISION)
    lines = _directive_lines(normalized)

    assert "cache deny has_cookie" not in lines
    assert "note cache_bypass cookie has_cookie" not in lines
    assert COOKIE_STATIC_CACHE_RULES in normalized
    assert "cache deny has_auth" in lines
    assert "note cache_bypass auth has_auth" in lines
    assert lines.count("acl has_cookie req_header Cookie .") == 1
    assert lines.index("acl has_cookie req_header Cookie .") < lines.index(
        "cache deny has_cookie !cookie_static_url"
    )
    assert lines.index(
        "store_miss deny has_cookie cookie_reply_unshareable"
    ) < lines.index("store_miss deny has_vary !vary_encoding_only")
    # Idempotent: a second pass (proxy sync compares normalized SHAs) changes nothing.
    assert controller.normalize_config_text(normalized) == normalized


def test_normalize_migrates_legacy_managed_block_and_form_shows_migrated_rules() -> (
    None
):
    controller = _controller()
    legacy_block = (
        "# BEGIN SQUID-UI MANAGED SETTINGS\n"
        "# BEGIN SQUID-UI BLOCK: CACHE_POLICY\n"
        "# Never cache authenticated or cookie-bearing traffic.\n"
        + LEGACY_FLAT_POLICY
        + "# END SQUID-UI BLOCK: CACHE_POLICY\n"
        "# END SQUID-UI MANAGED SETTINGS\n"
    )
    revision = "http_port 3128\n" + legacy_block + "http_access allow all\n"

    normalized = controller.normalize_config_text(revision)
    assert "cache deny has_cookie\n" not in normalized
    assert COOKIE_STATIC_CACHE_RULES in normalized
    assert controller.normalize_config_text(normalized) == normalized

    form_rules = controller.get_tunable_options(revision)["cache_policy_rules_text"]
    assert form_rules is not None
    assert COOKIE_STATIC_CACHE_RULES in form_rules
    assert "cache deny has_cookie" not in _directive_lines(form_rules)


def test_migration_leaves_operator_cookie_policies_alone() -> None:
    # Operator already runs its own static rules: never duplicate the ACLs.
    custom = "acl has_cookie req_header Cookie .\nacl cookie_static_url urlpath_regex \\.png$\ncache deny has_cookie\n"
    assert migrate_legacy_cookie_cache_deny(custom) == custom
    # The deny references an ACL defined later (or elsewhere): inserting rules
    # that use has_cookie before its definition would break parsing.
    undefined_first = "cache deny has_cookie\nacl has_cookie req_header Cookie .\n"
    assert migrate_legacy_cookie_cache_deny(undefined_first) == undefined_first
    # A narrower operator deny is not the legacy blanket rule.
    narrower = "acl has_cookie req_header Cookie .\ncache deny has_cookie all\n"
    assert migrate_legacy_cookie_cache_deny(narrower) == narrower


def test_normalize_still_adds_cookie_note_for_bare_cookie_acl() -> None:
    normalized = _controller().normalize_config_text(
        "acl has_cookie req_header Cookie .\nhttp_access allow all\n",
    )
    assert "note cache_bypass cookie has_cookie" in _directive_lines(normalized)
    assert "acl cookie_static_url" not in normalized
