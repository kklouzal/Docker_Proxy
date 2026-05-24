from __future__ import annotations

import sys
from pathlib import Path

import pytest


def _import_webfilter_store_module():
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))
    from services import webfilter_store  # type: ignore

    return webfilter_store


def test_webfilter_core_uses_shared_idna_normalization() -> None:
    m = _import_webfilter_store_module()

    assert m._norm_domain("http://Bücher.Example:8080/path") == "xn--bcher-kva.example"
    assert m._looks_like_host("http://Bücher.Example:8080/path") is True


def test_webfilter_run_build_passes_provider_to_builder() -> None:
    m = _import_webfilter_store_module()
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv

        class Result:
            returncode = 0
            stdout = b""
            stderr = b""

        return Result()

    old_run = m.run
    try:
        m.run = fake_run
        ok, err = m.WebFilterStore()._run_build(
            "https://example.test/feed.csv", source_provider="csv"
        )
    finally:
        m.run = old_run

    assert ok is True
    assert err == ""
    assert "--provider" in captured["argv"]
    assert captured["argv"][captured["argv"].index("--provider") + 1] == "csv"


def test_webfilter_run_build_defaults_invalid_provider_to_auto() -> None:
    m = _import_webfilter_store_module()
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv

        class Result:
            returncode = 0
            stdout = b""
            stderr = b""

        return Result()

    old_run = m.run
    try:
        m.run = fake_run
        ok, _err = m.WebFilterStore()._run_build(
            "https://example.test/feed.csv", source_provider="bad-provider"
        )
    finally:
        m.run = old_run

    assert ok is True
    assert captured["argv"][captured["argv"].index("--provider") + 1] == "auto"


@pytest.mark.parametrize(
    "source_url",
    [
        "file:///etc/passwd",
        "http://127.0.0.1/feed.csv",
        "http://localhost/feed.csv",
        "http://proxy.internal/feed.csv",
    ],
)
def test_webfilter_source_url_validation_rejects_unsafe_targets(source_url) -> None:
    m = _import_webfilter_store_module()

    with pytest.raises(ValueError):
        m.validate_source_url(source_url)

    assert m.validate_source_url(" https://example.test/feed.csv ") == "https://example.test/feed.csv"
