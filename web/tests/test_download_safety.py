from __future__ import annotations

import socket
import sys
from pathlib import Path

import pytest


def _import_download_safety():
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))
    from services import download_safety  # type: ignore

    return download_safety


def test_validate_download_url_accepts_public_absolute_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    download_safety = _import_download_safety()

    def fake_getaddrinfo(host: str, *_args, **_kwargs):
        assert host == "public.example"
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                0,
                "",
                ("93.184.216.34", 0),
            ),
        ]

    monkeypatch.setattr(download_safety.socket, "getaddrinfo", fake_getaddrinfo)

    parsed = download_safety.validate_download_url(
        "https://public.example/feed.csv",
    )

    assert parsed.scheme == "https"
    assert parsed.hostname == "public.example"


@pytest.mark.parametrize(
    "source_url",
    [
        "http://example.com\t/feed.csv",
        "http://example.com\n.evil/feed.csv",
        "https://public.example:bad/feed.csv",
        "https:///feed.csv",
        "https://[::1/feed.csv",
    ],
)
def test_validate_download_url_rejects_malformed_absolute_url_before_dns(
    source_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    download_safety = _import_download_safety()

    monkeypatch.setattr(
        download_safety.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("malformed URLs should not reach DNS")
        ),
    )

    with pytest.raises(ValueError, match="valid absolute HTTP/HTTPS"):
        download_safety.validate_download_url(source_url)


def test_validate_download_url_preserves_scheme_error_without_dns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    download_safety = _import_download_safety()

    monkeypatch.setattr(
        download_safety.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("unsupported schemes should not reach DNS")
        ),
    )

    with pytest.raises(ValueError, match="custom scheme message"):
        download_safety.validate_download_url(
            "ftp://public.example/feed.csv",
            scheme_error="custom scheme message",
        )
