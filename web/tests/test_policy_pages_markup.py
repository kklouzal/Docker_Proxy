from __future__ import annotations

from html.parser import HTMLParser

import pytest

from .admin_route_test_utils import load_admin_app, login_client

# Container elements whose mismatched nesting silently reflows a whole page
# (an unclosed banner once swallowed the entire WinHTTP form).
_CHECKED_TAGS = frozenset({"div", "section", "form", "table", "aside", "main"})


class _NestingChecker(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.stack: list[tuple[str, int]] = []
        self.errors: list[str] = []

    def handle_starttag(self, tag: str, _attrs) -> None:
        if tag in _CHECKED_TAGS:
            self.stack.append((tag, self.getpos()[0]))

    def handle_endtag(self, tag: str) -> None:
        if tag not in _CHECKED_TAGS:
            return
        if not self.stack:
            self.errors.append(f"line {self.getpos()[0]}: stray </{tag}>")
            return
        open_tag, line = self.stack.pop()
        if open_tag != tag:
            self.errors.append(
                f"line {self.getpos()[0]}: </{tag}> closes <{open_tag}> "
                f"opened on line {line}"
            )


@pytest.mark.parametrize(
    "path",
    [
        "/adblock",
        "/webfilter",
        "/webfilter?tab=whitelist",
        "/sslfilter",
        "/clamav",
        "/pac",
        "/error-pages",
        "/tools/winhttp-registry",
        "/squid/config",
        "/squid/config?tab=network",
        "/squid/config?tab=caching&subtab=overrides",
    ],
)
def test_policy_pages_have_balanced_container_markup(
    monkeypatch, tmp_path, path: str
) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get(path)

    assert response.status_code == 200
    checker = _NestingChecker()
    checker.feed(response.get_data(as_text=True))
    checker.close()
    assert checker.errors == []
    assert checker.stack == []
