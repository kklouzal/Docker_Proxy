import os
import pathlib
import sys
import unittest


def _import_webfilter_store_module():
    web_dir = pathlib.Path(os.path.join(pathlib.Path(__file__).parent, "..")).resolve()
    if web_dir not in sys.path:
        sys.path.insert(0, web_dir)
    from services import webfilter_store  # type: ignore

    return webfilter_store


class TestWebfilterWhitelist(unittest.TestCase):
    def test_parse_whitelist_lines(self) -> None:
        m = _import_webfilter_store_module()

        patterns = m._parse_whitelist_lines(
            [
                "example.com",
                "  sub.example.com  ",
                "*.example.com",
                ".foo.example.com",
                "not a domain",
                "# comment",
                "example.com  # trailing comment",
            ]
        )

        assert patterns == [
            "example.com",
            "sub.example.com",
            "*.example.com",
            "*.foo.example.com",
        ]

    def test_whitelist_match_exact_then_wildcard(self) -> None:
        m = _import_webfilter_store_module()

        patterns = ["example.com", "*.example.com", "sub.domain.com"]
        assert m._whitelist_match("example.com", patterns) == "example.com"
        assert m._whitelist_match("a.example.com", patterns) == "*.example.com"
        assert m._whitelist_match("sub.domain.com", patterns) == "sub.domain.com"
        assert m._whitelist_match("x.sub.domain.com", patterns) == ""


if __name__ == "__main__":
    unittest.main()
