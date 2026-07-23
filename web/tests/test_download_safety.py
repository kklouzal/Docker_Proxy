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
        "http://100.64.0.1/feed.csv",
        "http://100.127.255.254/feed.csv",
    ],
)
def test_validate_download_url_rejects_non_global_ip_literals(
    source_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    download_safety = _import_download_safety()

    monkeypatch.setattr(
        download_safety.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("IP literals should not reach DNS")
        ),
    )

    with pytest.raises(ValueError, match="internal/localhost"):
        download_safety.validate_download_url(source_url)


@pytest.mark.parametrize(
    "source_url",
    [
        "http://1.2.3/feed.csv",
        "http://0177.0.0.1/feed.csv",
        "http://0x7f.0.0.1/feed.csv",
        "http://2130706433/feed.csv",
    ],
)
def test_validate_download_url_rejects_ambiguous_ipv4_hosts_before_dns(
    source_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    download_safety = _import_download_safety()

    monkeypatch.setattr(
        download_safety.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("ambiguous numeric IPv4 hosts should not reach DNS")
        ),
    )

    with pytest.raises(ValueError, match="internal/localhost"):
        download_safety.validate_download_url(source_url)


def test_validate_download_url_accepts_public_ipv4_literal_without_dns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    download_safety = _import_download_safety()

    monkeypatch.setattr(
        download_safety.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("canonical IPv4 literals should not reach DNS")
        ),
    )

    parsed = download_safety.validate_download_url("https://93.184.216.34/feed.csv")

    assert parsed.scheme == "https"
    assert parsed.hostname == "93.184.216.34"


def test_validate_download_url_rejects_hostname_resolving_to_non_global_ip(
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
                ("100.64.0.1", 0),
            ),
        ]

    monkeypatch.setattr(download_safety.socket, "getaddrinfo", fake_getaddrinfo)

    with pytest.raises(ValueError, match="internal/localhost"):
        download_safety.validate_download_url("https://public.example/feed.csv")


def test_validate_download_url_rejects_single_label_hostname_before_dns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    download_safety = _import_download_safety()

    monkeypatch.setattr(
        download_safety.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("single-label download hosts should not reach DNS")
        ),
    )

    with pytest.raises(ValueError, match="internal/localhost"):
        download_safety.validate_download_url("https://intranet/feed.csv")


@pytest.mark.parametrize(
    "source_url",
    [
        "https://api.localdomain/feed.csv",
        "https://gateway.home.arpa/feed.csv",
        "https://home.arpa/feed.csv",
    ],
)
def test_validate_download_url_rejects_reserved_internal_dns_suffixes_before_dns(
    source_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    download_safety = _import_download_safety()

    monkeypatch.setattr(
        download_safety.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("reserved internal download hosts should not reach DNS")
        ),
    )

    with pytest.raises(ValueError, match="internal/localhost"):
        download_safety.validate_download_url(source_url)


def test_validate_download_url_canonicalizes_unicode_dot_host_before_dns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    download_safety = _import_download_safety()

    seen_hosts: list[str] = []

    def fake_getaddrinfo(host: str, *_args, **_kwargs):
        seen_hosts.append(host)
        if host == "public.example":
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    0,
                    "",
                    ("93.184.216.34", 0),
                ),
            ]
        msg = f"unexpected DNS host: {host!r}"
        raise AssertionError(msg)

    monkeypatch.setattr(download_safety.socket, "getaddrinfo", fake_getaddrinfo)

    parsed = download_safety.validate_download_url(
        "https://public\u3002example/feed.csv",
    )

    assert parsed.hostname == "public\u3002example"
    assert seen_hosts == ["public.example"]


def test_open_download_url_uses_canonicalized_unicode_dot_request_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    download_safety = _import_download_safety()

    seen_hosts: list[str] = []
    seen_urls: list[str] = []

    def fake_getaddrinfo(host: str, *_args, **_kwargs):
        seen_hosts.append(host)
        if host == "public.example":
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    0,
                    "",
                    ("93.184.216.34", 0),
                ),
            ]
        msg = f"unexpected DNS host: {host!r}"
        raise AssertionError(msg)

    class _Opener:
        def open(self, req, **_kwargs):
            seen_urls.append(req.full_url)
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
            "https://public\u3002example/feed.csv",
            timeout=1,
            user_agent="unit-test-agent",
        )

    assert seen_hosts == ["public.example", "public.example"]
    assert seen_urls == ["https://public.example/feed.csv"]


def test_validate_download_url_rejects_percent_encoded_authority_before_dns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    download_safety = _import_download_safety()

    monkeypatch.setattr(
        download_safety.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("percent-encoded authority should not reach DNS")
        ),
    )

    with pytest.raises(ValueError, match="valid absolute HTTP/HTTPS"):
        download_safety.validate_download_url("https://public%2Fexample.com/feed.csv")


@pytest.mark.parametrize(
    "source_url",
    [
        "http://example.com\t/feed.csv",
        "http://example.com\n.evil/feed.csv",
        "https://public.example:bad/feed.csv",
        "http://public.example:0/feed.csv",
        "https://public.example:0/feed.csv",
        "https://public.example:/feed.csv",
        "http://public.example:/feed.csv",
        "https:///feed.csv",
        "https://[::1/feed.csv",
        r"https://public.example\@127.0.0.1/feed.csv",
        r"https://public.example\path/feed.csv",
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


def test_validate_download_url_rejects_fragment_before_dns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    download_safety = _import_download_safety()

    monkeypatch.setattr(
        download_safety.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("fragmented download URLs should not reach DNS")
        ),
    )

    with pytest.raises(ValueError, match="valid absolute HTTP/HTTPS"):
        download_safety.validate_download_url(
            "https://public.example/feed.csv#https://127.0.0.1/admin",
        )


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


def test_open_download_url_rejects_malformed_user_agent_before_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    download_safety = _import_download_safety()

    monkeypatch.setattr(
        download_safety.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("malformed user agent should not reach DNS")
        ),
    )

    with pytest.raises(ValueError, match="valid HTTP header value"):
        download_safety.open_download_url(
            "https://public.example/feed.csv",
            timeout=1,
            user_agent="unit-test-agent\r\nX-Injected: yes",
        )


def test_open_download_url_filters_unsafe_headers_on_first_request(
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

    class _Opener:
        def open(self, req, **_kwargs):
            seen_headers.append(dict(req.header_items()))
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
                "Authorization": "Bearer secret",
                "Cookie": "session=secret",
                "Host": "private.example",
                "If-Modified-Since": "Mon, 01 Jan 2024 00:00:00 GMT",
                "If-None-Match": "etag-1",
                "Proxy-Authorization": "Basic secret",
                "Set-Cookie": "session=secret",
                "User-Agent": "caller-agent",
            },
        )

    assert len(seen_headers) == 1
    sent = {k.lower(): v for k, v in seen_headers[0].items()}
    assert sent == {
        "if-modified-since": "Mon, 01 Jan 2024 00:00:00 GMT",
        "if-none-match": "etag-1",
        "user-agent": "unit-test-agent",
    }


def test_open_download_url_ignores_ambient_http_proxy_env(
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

    seen_connections: list[tuple[str, int]] = []

    def fake_create_connection(address, *_args, **_kwargs):
        seen_connections.append(address)
        msg = "stop before network"
        raise RuntimeError(msg)

    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9999")
    monkeypatch.delenv("HTTP_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.setattr(download_safety.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(
        download_safety.socket,
        "create_connection",
        fake_create_connection,
    )

    with pytest.raises(RuntimeError, match="stop before network"):
        download_safety.open_download_url(
            "http://public.example/feed.csv",
            timeout=1,
            user_agent="unit-test-agent",
        )

    assert seen_connections == [("93.184.216.34", 80)]


def test_open_download_url_rejects_rebind_between_validation_and_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    download_safety = _import_download_safety()

    lookups: list[tuple[str, int | None]] = []

    def fake_getaddrinfo(host: str, port, *_args, **_kwargs):
        assert host == "public.example"
        lookups.append((host, port))
        address = "93.184.216.34" if len(lookups) == 1 else "127.0.0.1"
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                0,
                "",
                (address, port or 0),
            ),
        ]

    monkeypatch.setattr(download_safety.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(
        download_safety.socket,
        "create_connection",
        lambda *_args: (_ for _ in ()).throw(
            AssertionError("private rebound address must be rejected before connect")
        ),
    )

    with pytest.raises(ValueError, match="internal/localhost"):
        download_safety.open_download_url(
            "http://public.example/feed.csv",
            timeout=1,
            user_agent="unit-test-agent",
        )

    assert lookups == [("public.example", None), ("public.example", 80)]


def test_https_download_connection_preserves_hostname_for_sni(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    download_safety = _import_download_safety()
    addresses = (
        download_safety._ResolvedDownloadAddress(
            socket.AF_INET,
            socket.SOCK_STREAM,
            0,
            ("93.184.216.34", 443),
        ),
    )
    seen_connections: list[tuple[str, int]] = []
    seen_sni: list[str] = []

    class _Socket:
        def setsockopt(self, *_args):
            pass

        def close(self):
            pass

    def fake_create_connection(address, *_args, **_kwargs):
        seen_connections.append(address)
        return _Socket()

    class _Context:
        def wrap_socket(self, sock, *, server_hostname):
            seen_sni.append(server_hostname)
            return sock

    monkeypatch.setattr(
        download_safety.socket,
        "create_connection",
        fake_create_connection,
    )

    conn_cls = download_safety._download_connection_class(
        download_safety.http.client.HTTPSConnection,
        addresses,
    )
    conn = conn_cls("public.example", timeout=1, context=_Context())

    conn.connect()

    assert seen_connections == [("93.184.216.34", 443)]
    assert seen_sni == ["public.example"]


def test_download_connection_uses_vetted_ipv6_sockaddr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    download_safety = _import_download_safety()
    addresses = (
        download_safety._ResolvedDownloadAddress(
            socket.AF_INET6,
            socket.SOCK_STREAM,
            0,
            ("2001:4860:4860::8888", 80, 0, 0),
        ),
    )
    seen_socket_args: list[tuple[int, int, int]] = []
    seen_timeouts: list[int] = []
    seen_connections: list[tuple[str, int, int, int]] = []

    class _Socket:
        def settimeout(self, timeout: int) -> None:
            seen_timeouts.append(timeout)

        def connect(self, sockaddr) -> None:
            seen_connections.append(sockaddr)

        def setsockopt(self, *_args) -> None:
            pass

        def close(self) -> None:
            pass

    def fake_socket(family: int, socktype: int, proto: int):
        seen_socket_args.append((family, socktype, proto))
        return _Socket()

    monkeypatch.setattr(
        download_safety.socket,
        "create_connection",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("IPv6 vetted sockaddr must not be sent to create_connection")
        ),
    )
    monkeypatch.setattr(download_safety.socket, "socket", fake_socket)

    conn_cls = download_safety._download_connection_class(
        download_safety.http.client.HTTPConnection,
        addresses,
    )
    conn = conn_cls("public-v6.example", timeout=3)

    conn.connect()

    assert seen_socket_args == [(socket.AF_INET6, socket.SOCK_STREAM, 0)]
    assert seen_timeouts == [3]
    assert seen_connections == [("2001:4860:4860::8888", 80, 0, 0)]


def test_open_download_url_drops_malformed_conditional_headers_before_request(
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

    class _Opener:
        def open(self, req, **_kwargs):
            seen_headers.append(dict(req.header_items()))
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
                "If-None-Match\n": "etag-name-control",
                "If-Modified-Since": "Mon, 01 Jan 2024\r\nX-Bad: 1",
                "\tIf-None-Match": "etag-leading-control",
                "If-None-Match ": "etag-trailing-space",
                "If-None-Match": "etag-safe",
                "User-Agent": "caller-agent",
            },
        )

    assert len(seen_headers) == 1
    sent = {k.lower(): v for k, v in seen_headers[0].items()}
    assert sent == {
        "if-none-match": "etag-safe",
        "user-agent": "unit-test-agent",
    }


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


def test_open_download_url_rejects_malformed_redirect_location_before_dns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    download_safety = _import_download_safety()

    lookups: list[str] = []

    def fake_getaddrinfo(host: str, *_args, **_kwargs):
        lookups.append(host)
        if host != "public.example":
            msg = "malformed redirect location should not reach DNS"
            raise AssertionError(msg)
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                0,
                "",
                ("93.184.216.34", 0),
            ),
        ]

    redirect_headers = Message()
    redirect_headers["Location"] = "\nhttps://mirror.example/feed.csv"

    class _Opener:
        def open(self, req, **_kwargs):
            raise download_safety.urllib.error.HTTPError(
                req.full_url,
                302,
                "Found",
                redirect_headers,
                None,
            )

    monkeypatch.setattr(download_safety.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(
        download_safety.urllib.request,
        "build_opener",
        lambda *_args, **_kwargs: _Opener(),
    )

    with pytest.raises(ValueError, match="valid HTTP URI reference"):
        download_safety.open_download_url(
            "https://public.example/feed.csv",
            timeout=1,
            user_agent="unit-test-agent",
        )

    assert lookups == ["public.example", "public.example"]


def test_open_download_url_uses_get_without_body_after_303_redirect(
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

    seen_requests: list[tuple[str, str, bytes | None, str | None]] = []
    redirect_headers = Message()
    redirect_headers["Location"] = "/mirror/feed.csv"

    original_request = download_safety.urllib.request.Request

    def recording_request(*args, **kwargs):
        req = original_request(*args, **kwargs)
        req._explicit_method = kwargs.get("method")
        return req

    class _Opener:
        def open(self, req, **_kwargs):
            seen_requests.append(
                (
                    req.full_url,
                    req.get_method(),
                    req.data,
                    getattr(req, "_explicit_method", None),
                )
            )
            if len(seen_requests) == 1:
                raise download_safety.urllib.error.HTTPError(
                    req.full_url,
                    303,
                    "See Other",
                    redirect_headers,
                    None,
                )
            msg = "stop"
            raise RuntimeError(msg)

    monkeypatch.setattr(download_safety.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(download_safety.urllib.request, "Request", recording_request)
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
        )

    assert seen_requests == [
        ("https://public.example/feed.csv", "GET", None, "GET"),
        ("https://public.example/mirror/feed.csv", "GET", None, "GET"),
    ]


def test_open_download_url_rejects_https_to_http_redirect(
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

    seen_urls: list[str] = []
    redirect_headers = Message()
    redirect_headers["Location"] = "http://public.example/feed.csv"

    class _Opener:
        def open(self, req, **_kwargs):
            seen_urls.append(req.full_url)
            raise download_safety.urllib.error.HTTPError(
                req.full_url,
                302,
                "Found",
                redirect_headers,
                None,
            )

    monkeypatch.setattr(download_safety.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(
        download_safety.urllib.request,
        "build_opener",
        lambda *_args, **_kwargs: _Opener(),
    )

    with pytest.raises(ValueError, match="downgrade from https to http"):
        download_safety.open_download_url(
            "https://public.example/feed.csv",
            timeout=1,
            user_agent="unit-test-agent",
        )

    assert seen_urls == ["https://public.example/feed.csv"]


def test_open_download_url_applies_total_timeout_across_redirects(
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

    redirect_headers = Message()
    redirect_headers["Location"] = "/next.csv"
    seen_timeouts: list[float] = []
    ticks = iter([100.0, 100.0, 100.0, 100.7, 100.7, 101.1])

    class _Opener:
        def open(self, req, **kwargs):
            seen_timeouts.append(kwargs["timeout"])
            raise download_safety.urllib.error.HTTPError(
                req.full_url,
                302,
                "Found",
                redirect_headers,
                None,
            )

    class _Clock:
        def monotonic(self):
            return next(ticks)

    monkeypatch.setattr(download_safety.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setitem(download_safety.__dict__, "time", _Clock())
    monkeypatch.setattr(
        download_safety.urllib.request,
        "build_opener",
        lambda *_args, **_kwargs: _Opener(),
    )

    with pytest.raises(TimeoutError, match="timed out"):
        download_safety.open_download_url(
            "https://public.example/feed.csv",
            timeout=1,
            user_agent="unit-test-agent",
        )

    assert seen_timeouts == [pytest.approx(1.0), pytest.approx(0.3)]


def test_open_download_url_preserves_extra_headers_when_same_origin_redirect_adds_default_port(
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
    redirect_headers["Location"] = "https://public.example:443/mirror/feed.csv"

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
