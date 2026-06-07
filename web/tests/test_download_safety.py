from __future__ import annotations

import socket
import sys
from email.message import Message
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


def test_validate_download_url_rejects_embedded_credentials_before_dns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    download_safety = _import_download_safety()

    monkeypatch.setattr(
        download_safety.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("credential-bearing URLs should not reach DNS")
        ),
    )

    with pytest.raises(ValueError, match="embedded credentials"):
        download_safety.validate_download_url(
            "https://feed-user:feed-pass@public.example/feed.csv",
        )


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


def test_open_download_url_strips_extra_headers_on_cross_origin_redirect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    download_safety = _import_download_safety()

    def fake_getaddrinfo(host: str, *_args, **_kwargs):
        assert host in {"public.example", "mirror.example"}
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                0,
                "",
                ("93.184.216.34", 0),
            ),
        ]

    seen_headers: list[dict[str, str]] = []
    redirect_headers = Message()
    redirect_headers["Location"] = "https://mirror.example/feed.csv"

    class _Opener:
        def open(self, req, **_kwargs):
            seen_headers.append(dict(req.header_items()))
            if len(seen_headers) == 1:
                raise download_safety.urllib.error.HTTPError(
                    req.full_url,
                    302,
                    "Found",
                    redirect_headers,
                    None,
                )
            msg = "stop"
            raise RuntimeError(msg)

    monkeypatch.setattr(download_safety.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(
        download_safety.urllib.request,
        "build_opener",
        lambda *_args, **_kwargs: _Opener(),
    )

    with pytest.raises(RuntimeError, match="stop"):
        download_safety.open_download_url(
            "https://public.example/feed.csv",
            timeout=1,
            user_agent="unit-test-agent",
            headers={
                "If-None-Match": "etag-1",
                "If-Modified-Since": "Mon, 01 Jan 2024 00:00:00 GMT",
            },
        )

    assert len(seen_headers) == 2
    first = {k.lower(): v for k, v in seen_headers[0].items()}
    redirected = {k.lower(): v for k, v in seen_headers[1].items()}
    assert first["if-none-match"] == "etag-1"
    assert first["if-modified-since"] == "Mon, 01 Jan 2024 00:00:00 GMT"
    assert redirected["user-agent"] == "unit-test-agent"
    assert "if-none-match" not in redirected
    assert "if-modified-since" not in redirected


def test_open_download_url_preserves_extra_headers_on_same_origin_redirect(
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

    seen_headers: list[dict[str, str]] = []
    redirect_headers = Message()
    redirect_headers["Location"] = "/mirror/feed.csv"

    class _Opener:
        def open(self, req, **_kwargs):
            seen_headers.append(dict(req.header_items()))
            if len(seen_headers) == 1:
                raise download_safety.urllib.error.HTTPError(
                    req.full_url,
                    302,
                    "Found",
                    redirect_headers,
                    None,
                )
            msg = "stop"
            raise RuntimeError(msg)

    monkeypatch.setattr(download_safety.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(
        download_safety.urllib.request,
        "build_opener",
        lambda *_args, **_kwargs: _Opener(),
    )

    with pytest.raises(RuntimeError, match="stop"):
        download_safety.open_download_url(
            "https://public.example/feed.csv",
            timeout=1,
            user_agent="unit-test-agent",
            headers={"If-None-Match": "etag-1"},
        )

    assert len(seen_headers) == 2
    redirected = {k.lower(): v for k, v in seen_headers[1].items()}
    assert redirected["user-agent"] == "unit-test-agent"
    assert redirected["if-none-match"] == "etag-1"
