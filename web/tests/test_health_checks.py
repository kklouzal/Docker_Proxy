from __future__ import annotations

import sys
from pathlib import Path

import pytest


def _add_web_to_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


def _health_checks_module():
    _add_web_to_path()
    from services import health_checks  # type: ignore

    return health_checks


def _proxy_health_module():
    _add_web_to_path()
    from services import proxy_health  # type: ignore

    return proxy_health


class _FakeSocket:
    def __init__(self, chunks: list[bytes] | None = None) -> None:
        self.chunks = list(chunks or [])
        self.sent: list[bytes] = []
        self.timeout = None

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def settimeout(self, timeout) -> None:
        self.timeout = timeout

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, size: int) -> bytes:
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        if len(chunk) > size:
            self.chunks.insert(0, chunk[size:])
            return chunk[:size]
        return chunk


def _http_response(
    status: bytes = b"HTTP/1.1 200 OK",
    body: bytes = b'{"ok":true}\n',
) -> bytes:
    return (
        status
        + b"\r\nContent-Type: application/json\r\nContent-Length: "
        + str(len(body)).encode("ascii")
        + b"\r\n\r\n"
        + body
    )


def _forwarding_canary_response(
    status: bytes = b"HTTP/1.1 200 OK",
    body: bytes = (
        b'{"ok":true,"probe":"squid-respmod",'
        b'"service":"docker-proxy-forwarding-canary"}\n'
    ),
) -> bytes:
    return _http_response(status=status, body=body)


def test_health_check_local_host_listener_and_target_helpers(
    tmp_path, monkeypatch
) -> None:
    health_checks = _health_checks_module()

    assert health_checks.is_local_host("") is True
    assert health_checks.is_local_host("LOCALHOST") is True
    assert health_checks.is_local_host("proxy") is False

    proc_tcp = tmp_path / "tcp"
    proc_tcp.write_text(
        "sl local_address rem_address st\n0: 0100007F:36B0 00000000:0000 0A\n",
        encoding="utf-8",
    )
    assert health_checks.has_listen_socket(str(proc_tcp), 14000) is True
    assert health_checks.has_listen_socket(str(proc_tcp), 14001) is False
    assert health_checks.has_listen_socket(str(tmp_path / "missing"), 14000) is False

    assert health_checks.annotate_service_target(
        {"ok": 1, "detail": "ready"}, host="127.0.0.1", port=3310, service="clamd"
    ) == {
        "ok": True,
        "detail": "ready",
        "host": "127.0.0.1",
        "port": 3310,
        "target": "127.0.0.1:3310",
        "service": "clamd",
    }

    monkeypatch.setenv("TEST_HOST", "")
    monkeypatch.setenv("TEST_PORT", "not-int")
    assert health_checks.resolve_host_port(
        host_env="TEST_HOST",
        port_env="TEST_PORT",
        default_host="host",
        default_port=1234,
    ) == ("host", 1234)

    for invalid_port in ("0", "-1", "65536"):
        monkeypatch.setenv("TEST_PORT", invalid_port)
        assert health_checks.resolve_host_port(
            host_env="TEST_HOST",
            port_env="TEST_PORT",
            default_host="host",
            default_port=1234,
        ) == ("host", 1234)

    monkeypatch.setenv("TEST_PORT", "65535")
    assert health_checks.resolve_host_port(
        host_env="TEST_HOST",
        port_env="TEST_PORT",
        default_host="host",
        default_port=1234,
    ) == ("host", 65535)


def test_resolve_clamd_target_rejects_invalid_ports(monkeypatch) -> None:
    health_checks = _health_checks_module()

    monkeypatch.setenv("CLAMD_HOST", "clamd-host")
    for invalid_port in ("0", "-1", "65536", "not-int", ""):
        monkeypatch.setenv("CLAMD_PORT", invalid_port)
        assert health_checks._resolve_clamd_target() == ("clamd-host", 3310)

    monkeypatch.setenv("CLAMD_PORT", "65535")
    assert health_checks._resolve_clamd_target() == ("clamd-host", 65535)
    assert health_checks._resolve_clamd_target(port=0) == ("clamd-host", 3310)
    assert health_checks._resolve_clamd_target(port=1) == ("clamd-host", 1)


def test_proxy_health_resolved_override_rejects_invalid_ports(monkeypatch) -> None:
    proxy_health = _proxy_health_module()

    monkeypatch.setenv("CICAP_HOST", "icap-host")
    for invalid_port in ("0", "-1", "65536"):
        monkeypatch.setenv("CICAP_AV_PORT", invalid_port)
        assert proxy_health._resolve_host_port_override(
            host=None,
            port=None,
            host_env="CICAP_HOST",
            port_env="CICAP_AV_PORT",
            default_port=14001,
        ) == ("icap-host", 14001)

    assert proxy_health._resolve_host_port_override(
        host=None,
        port=65536,
        host_env="CICAP_HOST",
        port_env="CICAP_AV_PORT",
        default_port=14001,
    ) == ("icap-host", 14001)


def test_recv_clamd_reply_stops_on_null_or_newline() -> None:
    health_checks = _health_checks_module()

    assert (
        health_checks._recv_clamd_reply(_FakeSocket([b"PONG\0extra"]), max_bytes=64)
        == b"PONG\0extra"
    )
    assert (
        health_checks._recv_clamd_reply(_FakeSocket([b"OK\nmore"]), max_bytes=64)
        == b"OK\nmore"
    )
    assert (
        health_checks._recv_clamd_reply(_FakeSocket([b"ab", b"cd", b""]), max_bytes=3)
        == b"abc"
    )


def test_recv_status_line_handles_fragmented_icap_replies() -> None:
    health_checks = _health_checks_module()

    assert (
        health_checks._recv_status_line(
            _FakeSocket([b"ICAP/1.0 2", b"00 OK\r\nHeader: value\r\n"]),
            max_bytes=64,
        )
        == b"ICAP/1.0 200 OK"
    )
    assert (
        health_checks._recv_status_line(_FakeSocket([b"ICAP/1.0 404\nbody"]))
        == b"ICAP/1.0 404"
    )
    assert health_checks._recv_status_line(_FakeSocket([])) == b""


def test_check_tcp_success_and_failure(monkeypatch) -> None:
    health_checks = _health_checks_module()

    monkeypatch.setattr(
        health_checks.socket,
        "create_connection",
        lambda *_args, **_kwargs: _FakeSocket(),
    )
    assert health_checks.check_tcp("127.0.0.1", 3310) == {
        "ok": True,
        "detail": "tcp connect ok",
    }

    monkeypatch.setattr(
        health_checks.socket,
        "create_connection",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("refused")),
    )
    assert health_checks.check_tcp(
        "127.0.0.1", 3310, error_formatter=lambda exc: f"formatted {exc}"
    ) == {
        "ok": False,
        "detail": "formatted refused",
    }


def test_check_icap_service_and_clamd_protocol_helpers(monkeypatch) -> None:
    health_checks = _health_checks_module()

    icap_sock = _FakeSocket([b"ICAP/1.0 200 OK\r\n\r\n"])
    monkeypatch.setattr(
        health_checks.socket, "create_connection", lambda *_args, **_kwargs: icap_sock
    )
    assert (
        health_checks.check_icap_service("127.0.0.1", 14000, "adblockreq")["ok"] is True
    )
    assert b"OPTIONS icap://127.0.0.1:14000/adblockreq ICAP/1.0" in icap_sock.sent[0]

    icap_error_sock = _FakeSocket([b"ICAP/1.0 404 Not Found\r\n"])
    monkeypatch.setattr(
        health_checks.socket,
        "create_connection",
        lambda *_args, **_kwargs: icap_error_sock,
    )
    assert health_checks.check_icap_service("127.0.0.1", 14000, "/missing") == {
        "ok": False,
        "detail": "ICAP/1.0 404 Not Found",
    }

    clamd_sock = _FakeSocket([b"PONG\0"])
    monkeypatch.setattr(
        health_checks.socket, "create_connection", lambda *_args, **_kwargs: clamd_sock
    )
    clamd = health_checks.check_clamd("clamd", 3310)
    assert clamd["ok"] is True
    assert "PONG" in clamd["detail"]
    assert clamd_sock.sent == [b"PING\n"]

    sample_sock = _FakeSocket(
        [
            b"ICAP/1.0 204 No Content\r\n",
            b'ISTag: "clamav-respmod-instream-1"\r\n\r\n',
        ]
    )
    monkeypatch.setattr(
        health_checks.socket,
        "create_connection",
        lambda *_args, **_kwargs: sample_sock,
    )
    sample = health_checks.send_sample_respmod_to("127.0.0.1", 14001)
    assert sample["ok"] is True
    assert sample["status"] == "healthy"
    assert sample["transport_ok"] is True
    assert sample["protection_ready"] is True
    assert sample["backend_available"] is True
    assert sample["icap_status_code"] == 204
    assert sample["icap_istag"] == '"clamav-respmod-instream-1"'
    combined = health_checks.build_clamav_health(
        {"ok": True, "detail": "clamd ok"}, {"ok": False, "detail": "icap down"}
    )
    assert combined["ok"] is False
    assert combined["components"]["clamd"]["detail"] == "clamd ok"


def _run_check_icap_service_response(monkeypatch, chunks: list[bytes]):
    health_checks = _health_checks_module()
    sock = _FakeSocket(chunks)
    monkeypatch.setattr(
        health_checks.socket,
        "create_connection",
        lambda *_args, **_kwargs: sock,
    )

    result = health_checks.check_icap_service(
        "127.0.0.1",
        14000,
        "adblockreq",
        timeout=0.5,
    )

    assert b"OPTIONS icap://127.0.0.1:14000/adblockreq ICAP/1.0" in sock.sent[0]
    return result


def test_check_icap_service_accepts_only_complete_strict_icap_200(monkeypatch) -> None:
    result = _run_check_icap_service_response(
        monkeypatch,
        [
            b"ICAP/1.0 ",
            b"200 OK\r\nMeth",
            b"ods: REQMOD\r\nConnection: close\r\nEncapsulated: null-body=0\r\n\r\n",
        ],
    )

    assert result == {"ok": True, "detail": "ICAP/1.0 200 OK"}


def test_check_icap_service_preserves_success_detail_for_strict_200(
    monkeypatch,
) -> None:
    health_checks = _health_checks_module()
    sock = _FakeSocket([b"ICAP/1.0 200 OK\r\nMethods: REQMOD\r\n\r\n"])
    monkeypatch.setattr(
        health_checks.socket,
        "create_connection",
        lambda *_args, **_kwargs: sock,
    )

    result = health_checks.check_icap_service(
        "127.0.0.1",
        14000,
        "adblockreq",
        success_detail="adblock ICAP ready",
    )

    assert result == {"ok": True, "detail": "adblock ICAP ready"}


@pytest.mark.parametrize(
    ("response", "detail"),
    [
        (b"ICAP/1.0 2000 Weird\r\nMethods: REQMOD\r\n\r\n", "malformed"),
        (b"ICAP/1.0 200X Weird\r\nMethods: REQMOD\r\n\r\n", "malformed"),
        (b"ICAP/1.0 200OK\r\nMethods: REQMOD\r\n\r\n", "malformed"),
        (b"ICAP/1.0 200\r\nMethods: REQMOD\r\n\r\n", "malformed"),
        (b"ICAP/1.0 200\tOK\r\nMethods: REQMOD\r\n\r\n", "malformed"),
        (b"ICAP/1.0 200 O\x01K\r\nMethods: REQMOD\r\n\r\n", "control"),
        (b" ICAP/1.0 200 OK\r\nMethods: REQMOD\r\n\r\n", "malformed"),
        (b"ICAP/1.1 200 OK\r\nMethods: REQMOD\r\n\r\n", "malformed"),
        (b"ICAP/1.0 204 No Content\r\nMethods: REQMOD\r\n\r\n", "204"),
        (b"HTTP/1.1 200 OK\r\nMethods: REQMOD\r\n\r\n", "malformed"),
        (b"ICAP/1.0 200 OK", "incomplete"),
        (
            b"ICAP/1.0 200 OK\r\nMethods: REQMOD\r\n" + (b"X-Test: value\r\n" * 600),
            "incomplete",
        ),
        (b"ICAP/1.0 200 OK\nMethods: REQMOD\n\n", "terminator"),
        (b"ICAP/1.0 200 OK\r\nBad Header: value\r\n\r\n", "header name"),
        (
            b"ICAP/1.0 200 OK\r\nMethods: REQMOD\r\nMethods: RESPMOD\r\n\r\n",
            "duplicate",
        ),
        (b"ICAP/1.0 200 OK\r\nX-Test: bad\x01value\r\n\r\n", "control"),
        (
            (
                b"ICAP/1.0 100 Continue\r\n\r\n"
                b"ICAP/1.0 200 OK\r\nMethods: REQMOD\r\n\r\n"
            ),
            "100 Continue",
        ),
        (
            (
                b"ICAP/1.0 200 OK\r\nMethods: REQMOD\r\n\r\n"
                b"ICAP/1.0 204 No Content\r\n\r\n"
            ),
            "unexpected data",
        ),
    ],
)
def test_check_icap_service_rejects_confusable_or_incomplete_options_responses(
    monkeypatch,
    response: bytes,
    detail: str,
) -> None:
    result = _run_check_icap_service_response(monkeypatch, [response])

    assert result["ok"] is False
    assert detail in result["detail"]


@pytest.mark.parametrize(
    ("name", "chunks", "expected_ok", "detail_fragment"),
    [
        ("lf terminator", [b"PONG\n"], True, "PONG"),
        ("crlf terminator", [b"PONG\r\n"], True, "PONG"),
        ("nul terminator", [b"PONG\0"], True, "PONG"),
        ("fragmented reply", [b"PO", b"NG\n"], True, "PONG"),
        ("extra bytes after terminator", [b"PONG\nVERSION\n"], False, "VERSION"),
        ("pong prefix wrong command", [b"PONG-OLD\n"], False, "PONG-OLD"),
        ("leading whitespace", [b" PONG\n"], False, "PONG"),
        ("trailing whitespace", [b"PONG \n"], False, "PONG"),
        ("lowercase", [b"pong\n"], False, "pong"),
        ("unterminated eof", [b"PONG", b""], False, "PONG"),
        ("oversized unterminated", [b"PONG" + (b"X" * 128)], False, "PONG"),
        ("error reply", [b"UNKNOWN COMMAND\n"], False, "UNKNOWN COMMAND"),
        ("empty eof", [], False, "no data"),
    ],
)
def test_check_clamd_accepts_only_exact_bounded_ping_pong(
    monkeypatch,
    name: str,
    chunks: list[bytes],
    expected_ok: bool,
    detail_fragment: str,
) -> None:
    health_checks = _health_checks_module()

    clamd_sock = _FakeSocket(chunks)
    monkeypatch.setattr(
        health_checks.socket, "create_connection", lambda *_args, **_kwargs: clamd_sock
    )

    result = health_checks.check_clamd("clamd", 3310, timeout=0.5)

    assert result["ok"] is expected_ok, name
    assert detail_fragment in result["detail"], name
    assert clamd_sock.sent == [b"PING\n"], name


def test_check_clamd_reports_timeout_as_unhealthy(monkeypatch) -> None:
    health_checks = _health_checks_module()

    class _TimeoutSocket(_FakeSocket):
        def recv(self, size: int) -> bytes:
            message = "timed out"
            raise TimeoutError(message)

    clamd_sock = _TimeoutSocket()
    monkeypatch.setattr(
        health_checks.socket, "create_connection", lambda *_args, **_kwargs: clamd_sock
    )

    result = health_checks.check_clamd("clamd", 3310, timeout=0.5)

    assert result["ok"] is False
    assert "clamd:3310" in result["detail"]
    assert clamd_sock.sent == [b"PING\n"]


@pytest.mark.parametrize("icap_status", [b"204 No Content", b"200 OK"])
def test_sample_respmod_reports_fail_open_placeholder_as_degraded(
    monkeypatch,
    icap_status: bytes,
) -> None:
    health_checks = _health_checks_module()

    sample_sock = _FakeSocket(
        [
            b"ICAP/1.0 " + icap_status + b"\r\n",
            b'ISTag: "clamav-fail-open-unavailable"\r\n',
            b"Encapsulated: null-body=0\r\n\r\n",
        ]
    )
    monkeypatch.setattr(
        health_checks.socket,
        "create_connection",
        lambda *_args, **_kwargs: sample_sock,
    )

    result = health_checks.send_sample_respmod_to("127.0.0.1", 14001)

    assert result["ok"] is False
    assert result["status"] == "degraded"
    assert result["transport_ok"] is True
    assert result["icap_transaction_ok"] is True
    assert result["protection_ready"] is False
    assert result["fail_open"] is True
    assert result["fail_mode"] == "open"
    assert result["backend_available"] is False
    assert result["icap_status_code"] in {200, 204}
    assert "fail-open placeholder" in result["detail"]


def test_sample_respmod_reports_transport_failure_separately(monkeypatch) -> None:
    health_checks = _health_checks_module()

    monkeypatch.setattr(
        health_checks.socket,
        "create_connection",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("refused")),
    )

    result = health_checks.send_sample_respmod_to("127.0.0.1", 14001)

    assert result["ok"] is False
    assert result["status"] == "unavailable"
    assert result["transport_ok"] is False
    assert result["icap_transaction_ok"] is False
    assert result["protection_ready"] is False
    assert result["fail_open"] is False
    assert result["backend_available"] is False
    assert result["icap_status_code"] is None


def test_check_http_proxy_forwarding_uses_absolute_form_local_probe(
    monkeypatch,
) -> None:
    health_checks = _health_checks_module()

    sock = _FakeSocket([_http_response()])
    monkeypatch.setattr(
        health_checks.socket,
        "create_connection",
        lambda *_args, **_kwargs: sock,
    )

    result = health_checks.check_http_proxy_forwarding(
        proxy_port=3128,
        target_url="http://127.0.0.1:80/health",
        timeout=0.4,
    )

    assert result == {
        "ok": True,
        "detail": "HTTP/1.1 200 OK; local health ok",
        "status_code": 200,
        "probe_url": "http://127.0.0.1:80/health",
        "headers_complete": True,
        "body_complete": True,
        "local_health_ok": True,
        "canary_probe_ok": None,
    }
    assert sock.timeout == pytest.approx(0.4)
    assert b"GET http://127.0.0.1:80/health HTTP/1.1" in sock.sent[0]
    assert b"Host: 127.0.0.1:80" in sock.sent[0]
    assert b"User-Agent: squid-flask-proxy-forwarding-health" in sock.sent[0]


def test_check_http_proxy_forwarding_uses_dedicated_canary_and_requires_marker(
    monkeypatch,
) -> None:
    health_checks = _health_checks_module()

    sock = _FakeSocket([_forwarding_canary_response()])
    monkeypatch.setattr(
        health_checks.socket,
        "create_connection",
        lambda *_args, **_kwargs: sock,
    )

    result = health_checks.check_http_proxy_forwarding(
        proxy_port=3128,
        target_url="http://127.0.0.1:18080/__docker_proxy_forwarding_canary",
        timeout=0.4,
    )

    assert result == {
        "ok": True,
        "detail": "HTTP/1.1 200 OK; local health ok",
        "status_code": 200,
        "probe_url": "http://127.0.0.1:18080/__docker_proxy_forwarding_canary?probe=squid-respmod",
        "headers_complete": True,
        "body_complete": True,
        "local_health_ok": True,
        "canary_probe_ok": True,
    }
    assert (
        b"GET http://127.0.0.1:18080/__docker_proxy_forwarding_canary?probe=squid-respmod HTTP/1.1"
        in sock.sent[0]
    )
    assert b"Host: 127.0.0.1:18080" in sock.sent[0]

    sock = _FakeSocket([_http_response(body=b'{"ok":true}\n')])
    monkeypatch.setattr(
        health_checks.socket,
        "create_connection",
        lambda *_args, **_kwargs: sock,
    )
    malformed = health_checks.check_http_proxy_forwarding(
        proxy_port=3128,
        target_url="http://127.0.0.1:18080/__docker_proxy_forwarding_canary",
        timeout=0.4,
    )
    assert malformed["ok"] is False
    assert malformed["canary_probe_ok"] is False
    assert "local health body did not confirm ok" in malformed["detail"]


def test_check_http_proxy_forwarding_custom_canary_path_requires_probe_marker(
    monkeypatch,
) -> None:
    health_checks = _health_checks_module()
    monkeypatch.setenv("FORWARDING_CANARY_PATH", "/custom-canary")

    sock = _FakeSocket([_forwarding_canary_response()])
    monkeypatch.setattr(
        health_checks.socket,
        "create_connection",
        lambda *_args, **_kwargs: sock,
    )

    result = health_checks.check_http_proxy_forwarding(
        proxy_port=3128,
        target_url="http://127.0.0.1:18080/custom-canary",
        timeout=0.4,
    )

    assert result == {
        "ok": True,
        "detail": "HTTP/1.1 200 OK; local health ok",
        "status_code": 200,
        "probe_url": "http://127.0.0.1:18080/custom-canary?probe=squid-respmod",
        "headers_complete": True,
        "body_complete": True,
        "local_health_ok": True,
        "canary_probe_ok": True,
    }
    assert (
        b"GET http://127.0.0.1:18080/custom-canary?probe=squid-respmod HTTP/1.1"
        in sock.sent[0]
    )

    sock = _FakeSocket([_http_response(body=b'{"ok":true}\n')])
    monkeypatch.setattr(
        health_checks.socket,
        "create_connection",
        lambda *_args, **_kwargs: sock,
    )

    malformed = health_checks.check_http_proxy_forwarding(
        proxy_port=3128,
        target_url="http://127.0.0.1:18080/custom-canary",
        timeout=0.4,
    )

    assert malformed["ok"] is False
    assert malformed["local_health_ok"] is False
    assert malformed["canary_probe_ok"] is False
    assert "local health body did not confirm ok" in malformed["detail"]


def test_check_http_proxy_forwarding_accepts_complete_chunked_local_health(
    monkeypatch,
) -> None:
    health_checks = _health_checks_module()
    body = b'{"ok":true}\n'
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n"
        + f"{len(body):x}\r\n".encode("ascii")
        + body
        + b"\r\n0\r\n\r\n"
    )

    monkeypatch.setattr(
        health_checks.socket,
        "create_connection",
        lambda *_args, **_kwargs: _FakeSocket([response]),
    )

    result = health_checks.check_http_proxy_forwarding(
        proxy_port=3128,
        target_url="http://127.0.0.1:80/health",
        timeout=0.1,
    )

    assert result["ok"] is True
    assert result["body_complete"] is True
    assert result["local_health_ok"] is True
    assert "local health ok" in result["detail"]


def test_check_http_proxy_forwarding_rejects_conflicting_content_lengths(
    monkeypatch,
) -> None:
    health_checks = _health_checks_module()
    body = b'{"ok":true}\n'
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 999\r\n"
        + b"Content-Length: "
        + str(len(body)).encode("ascii")
        + b"\r\n\r\n"
        + body
    )

    monkeypatch.setattr(
        health_checks.socket,
        "create_connection",
        lambda *_args, **_kwargs: _FakeSocket([response]),
    )

    result = health_checks.check_http_proxy_forwarding(
        proxy_port=3128,
        target_url="http://127.0.0.1:80/health",
        timeout=0.1,
    )

    assert result["ok"] is False
    assert result["local_health_ok"] is False
    assert result["body_complete"] is False
    assert "conflicting Content-Length" in result["detail"]


@pytest.mark.parametrize(
    ("target_url", "body", "expected_canary_ok"),
    [
        ("http://127.0.0.1:80/health", b'{"ok":true}\n', None),
        (
            "http://127.0.0.1:18080/__docker_proxy_forwarding_canary",
            (
                b'{"ok":true,"probe":"squid-respmod",'
                b'"service":"docker-proxy-forwarding-canary"}\n'
            ),
            False,
        ),
    ],
)
def test_check_http_proxy_forwarding_rejects_unframed_local_json_eof(
    monkeypatch,
    target_url,
    body,
    expected_canary_ok,
) -> None:
    health_checks = _health_checks_module()
    response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + body

    monkeypatch.setattr(
        health_checks.socket,
        "create_connection",
        lambda *_args, **_kwargs: _FakeSocket([response]),
    )

    result = health_checks.check_http_proxy_forwarding(
        proxy_port=3128,
        target_url=target_url,
        timeout=0.1,
    )

    assert result["ok"] is False
    assert result["body_complete"] is False
    assert result["local_health_ok"] is False
    assert result["canary_probe_ok"] is expected_canary_ok
    assert "incomplete local health response body" in result["detail"]


def test_check_http_proxy_forwarding_reports_blocked_or_timed_out_path(
    monkeypatch,
) -> None:
    health_checks = _health_checks_module()

    monkeypatch.setattr(
        health_checks.socket,
        "create_connection",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(TimeoutError("wedged")),
    )

    result = health_checks.check_http_proxy_forwarding(
        proxy_port=3128,
        target_url="http://127.0.0.1:80/health",
        timeout=0.1,
        error_formatter=lambda exc: f"formatted {exc}",
    )

    assert result == {"ok": False, "detail": "formatted wedged"}


@pytest.mark.parametrize(
    ("chunks", "detail"),
    [
        (
            [b'HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n{"ok":true'],
            "incomplete local health response body",
        ),
        ([_http_response(body=b"not json")], "local health body did not confirm ok"),
        (
            [_http_response(status=b"HTTP/1.1 503 Service Unavailable")],
            "HTTP/1.1 503 Service Unavailable",
        ),
    ],
)
def test_check_http_proxy_forwarding_rejects_partial_malformed_and_non_2xx(
    monkeypatch,
    chunks,
    detail,
) -> None:
    health_checks = _health_checks_module()

    monkeypatch.setattr(
        health_checks.socket,
        "create_connection",
        lambda *_args, **_kwargs: _FakeSocket(chunks),
    )

    result = health_checks.check_http_proxy_forwarding(
        proxy_port=3128,
        target_url="http://127.0.0.1:80/health",
        timeout=0.1,
    )

    assert result["ok"] is False
    assert detail in result["detail"]


def test_check_http_proxy_forwarding_refuses_self_proxy_loop(monkeypatch) -> None:
    health_checks = _health_checks_module()

    def fail_connect(*_args, **_kwargs):
        msg = "self-loop guard should avoid opening a socket"
        raise AssertionError(msg)

    monkeypatch.setattr(health_checks.socket, "create_connection", fail_connect)

    result = health_checks.check_http_proxy_forwarding(
        proxy_port=3128,
        target_url="http://127.0.0.1:3128/health",
        timeout=0.1,
    )

    assert result["ok"] is False
    assert "points back at the explicit proxy listener" in result["detail"]


def test_check_http_proxy_forwarding_refuses_request_line_injection(monkeypatch) -> None:
    health_checks = _health_checks_module()

    def fail_connect(*_args, **_kwargs):
        msg = "unsafe forwarding probe target should not open a socket"
        raise AssertionError(msg)

    monkeypatch.setattr(health_checks.socket, "create_connection", fail_connect)

    result = health_checks.check_http_proxy_forwarding(
        proxy_port=3128,
        target_url=(
            "http://127.0.0.1:18080/health HTTP/1.1\r\n"
            "X-Injected: yes\r\n"
            "GET http://127.0.0.1:18080/health"
        ),
        timeout=0.1,
    )

    assert result["ok"] is False
    assert "unsafe forwarding probe target URL" in result["detail"]


def test_proxy_health_icap_uses_protocol_probe_for_local_targets(monkeypatch) -> None:
    proxy_health = _proxy_health_module()

    calls = []

    def fake_check_icap_service(**kwargs):
        calls.append(kwargs)
        return {"ok": False, "detail": "ICAP/1.0 404 Not Found"}

    monkeypatch.setattr(proxy_health, "check_icap_service", fake_check_icap_service)

    result = proxy_health.check_adblock_icap_health(
        host="127.0.0.1",
        port=14000,
        timeout=0.4,
    )

    assert calls == [
        {
            "host": "127.0.0.1",
            "port": 14000,
            "service": "/adblockreq",
            "timeout": 0.4,
            "user_agent": "squid-flask-proxy-ui",
            "success_detail": None,
            "error_formatter": None,
        }
    ]
    assert result == {
        "ok": False,
        "detail": "ICAP/1.0 404 Not Found",
        "host": "127.0.0.1",
        "port": 14000,
        "target": "127.0.0.1:14000",
        "service": "/adblockreq",
    }


def test_remote_clamav_view_surfaces_stale_cached_health_source() -> None:
    proxy_health = _proxy_health_module()

    view = proxy_health.build_remote_clamav_view(
        {
            "ok": True,
            "proxy_status": "ClamAV health checked via lightweight management endpoint.",
            "detail": "using recent cached ClamAV health after refresh failure",
            "_stale": True,
            "services": {
                "clamav": {"ok": True, "detail": "clamav ok"},
                "av_icap": {"ok": True, "detail": "icap ok"},
                "clamd": {"ok": True, "detail": "clamd ok"},
            },
        }
    )

    assert view["health_source"] == (
        "ClamAV health checked via lightweight management endpoint. "
        "(using recent cached ClamAV health after refresh failure)"
    )


def test_remote_clamav_view_surfaces_unavailable_cached_health_source() -> None:
    proxy_health = _proxy_health_module()

    view = proxy_health.build_remote_clamav_view(
        {
            "ok": False,
            "proxy_status": "offline",
            "detail": "Proxy management request timed out",
            "_unavailable_cached": True,
            "services": {},
        }
    )

    assert view["health_source"] == "offline (Proxy management request timed out)"


def test_remote_clamav_view_preserves_split_av_icap_components() -> None:
    proxy_health = _proxy_health_module()

    view = proxy_health.build_remote_clamav_view(
        {
            "ok": False,
            "proxy_status": "ClamAV health checked via lightweight management endpoint.",
            "services": {
                "clamav": {"ok": False, "detail": "upload=ok | download=down"},
                "av_icap": {
                    "ok": False,
                    "detail": "upload=ok | download=down",
                    "host": "127.0.0.1",
                    "port": 24002,
                    "target": "127.0.0.1:24002",
                    "service": "/avrespmod",
                    "components": {
                        "upload_av_icap": {
                            "ok": True,
                            "detail": "ICAP/1.0 200 OK",
                            "host": "127.0.0.1",
                            "port": 24001,
                            "target": "127.0.0.1:24001",
                            "service": "/avrespmod",
                        },
                        "download_av_icap": {
                            "ok": False,
                            "detail": "connection refused",
                            "host": "127.0.0.1",
                            "port": 24002,
                            "target": "127.0.0.1:24002",
                            "service": "/avrespmod",
                        },
                    },
                },
                "clamd": {
                    "ok": False,
                    "detail": "Name does not resolve",
                    "host": "clamav.edge-2.internal",
                    "port": 3311,
                    "target": "clamav.edge-2.internal:3311",
                },
            },
        }
    )

    av_icap = view["av_icap_health"]
    assert av_icap["target"] == "127.0.0.1:24002"
    assert av_icap["components"]["upload_av_icap"]["target"] == "127.0.0.1:24001"
    assert av_icap["components"]["download_av_icap"]["target"] == "127.0.0.1:24002"
    assert (
        view["health"]["components"]["av_icap"]["components"] == av_icap["components"]
    )


def test_local_runtime_services_uses_tcp_timeout_for_clamd(monkeypatch) -> None:
    proxy_health = _proxy_health_module()

    calls: dict[str, float] = {}

    def fake_check_adblock(*, timeout, **_kwargs):
        calls["adblock"] = timeout
        return {"ok": True, "detail": "adblock ok"}

    def fake_check_av(*, timeout, **_kwargs):
        calls["av_icap"] = timeout
        return {"ok": True, "detail": "av ok"}

    def fake_check_clamd(*, timeout, **_kwargs):
        calls["clamd"] = timeout
        return {"ok": True, "detail": "clamd ok"}

    monkeypatch.setattr(proxy_health, "check_adblock_icap_health", fake_check_adblock)
    monkeypatch.setattr(proxy_health, "check_av_icap_health", fake_check_av)
    monkeypatch.setattr(proxy_health, "check_clamd_health", fake_check_clamd)
    monkeypatch.setattr(
        proxy_health,
        "check_forwarding_path_health",
        lambda **_kwargs: {"ok": True, "detail": "forwarding ok"},
    )

    result = proxy_health.build_local_runtime_services(
        icap_timeout=0.9,
        tcp_timeout=0.2,
    )

    assert calls == {"adblock": 0.9, "av_icap": 0.9, "clamd": 0.2}
    assert result["clamd"] == {"ok": True, "detail": "clamd ok"}
    assert result["clamav"]["ok"] is True


def test_forwarding_path_health_is_local_bounded_and_attributed(monkeypatch) -> None:
    proxy_health = _proxy_health_module()
    captured: dict[str, object] = {}

    monkeypatch.setenv("SQUID_HTTP_PORT", "3128")
    monkeypatch.setenv("FORWARDING_CANARY_HOST", "0.0.0.0")  # noqa: S104 - wildcard bind env is normalized to loopback.
    monkeypatch.setenv("FORWARDING_CANARY_PORT", "18080")
    monkeypatch.delenv("CLAMAV_REQUIRED", raising=False)

    def fake_probe(**kwargs):
        captured.update(kwargs)
        return {"ok": False, "detail": "HTTP/1.1 503 Service Unavailable"}

    monkeypatch.setattr(proxy_health, "check_http_proxy_forwarding", fake_probe)

    result = proxy_health.check_forwarding_path_health(
        timeout=0.3,
        av_icap_health={"ok": False, "detail": "RESPMOD timeout"},
    )

    assert captured == {
        "proxy_host": "127.0.0.1",
        "proxy_port": 3128,
        "target_url": "http://127.0.0.1:18080/__docker_proxy_forwarding_canary",
        "timeout": 0.3,
        "error_formatter": None,
    }
    assert result["ok"] is False
    assert result["target"] == "127.0.0.1:3128"
    assert result["traffic_scope"] == "local-only"
    assert result["fail_mode"] == "open"
    assert "forwarding path is degraded" in result["detail"]


def test_forwarding_path_health_no_longer_targets_public_listener_self_dependency(
    monkeypatch,
) -> None:
    proxy_health = _proxy_health_module()
    captured: dict[str, object] = {}

    monkeypatch.setenv("SQUID_HTTP_PORT", "3128")
    monkeypatch.setenv("PAC_HTTP_HOST", "127.0.0.1")
    monkeypatch.setenv("PAC_HTTP_PORT", "80")
    monkeypatch.delenv("FORWARDING_CANARY_HOST", raising=False)
    monkeypatch.delenv("FORWARDING_CANARY_PORT", raising=False)
    monkeypatch.delenv("FORWARDING_CANARY_PATH", raising=False)

    def fake_probe(**kwargs):
        captured.update(kwargs)
        return {"ok": True, "detail": "HTTP/1.1 200 OK; local health ok"}

    monkeypatch.setattr(proxy_health, "check_http_proxy_forwarding", fake_probe)

    result = proxy_health.check_forwarding_path_health(timeout=0.3)

    assert result["ok"] is True
    assert captured["target_url"] == (
        "http://127.0.0.1:18080/__docker_proxy_forwarding_canary"
    )
    assert captured["target_url"] != "http://127.0.0.1:80/health"


def test_forwarding_path_health_rejects_dns_names_that_look_like_loopback(
    monkeypatch,
) -> None:
    proxy_health = _proxy_health_module()
    captured: dict[str, object] = {}

    monkeypatch.setenv("SQUID_HTTP_PORT", "3128")
    monkeypatch.setenv("FORWARDING_CANARY_HOST", "127.0.0.1.evil.test")
    monkeypatch.setenv("FORWARDING_CANARY_PORT", "18080")

    def fake_probe(**kwargs):
        captured.update(kwargs)
        return {"ok": True, "detail": "HTTP/1.1 200 OK; local health ok"}

    monkeypatch.setattr(proxy_health, "check_http_proxy_forwarding", fake_probe)

    result = proxy_health.check_forwarding_path_health(timeout=0.3)

    assert result["ok"] is True
    assert captured["target_url"] == (
        "http://127.0.0.1:18080/__docker_proxy_forwarding_canary"
    )


def test_forwarding_path_health_rejects_canary_paths_with_double_slash(
    monkeypatch,
) -> None:
    proxy_health = _proxy_health_module()
    captured: dict[str, object] = {}

    monkeypatch.setenv("SQUID_HTTP_PORT", "3128")
    monkeypatch.setenv("FORWARDING_CANARY_HOST", "127.0.0.1")
    monkeypatch.setenv("FORWARDING_CANARY_PORT", "18080")
    monkeypatch.setenv("FORWARDING_CANARY_PATH", "/bad//canary")

    def fake_probe(**kwargs):
        captured.update(kwargs)
        return {"ok": True, "detail": "HTTP/1.1 200 OK; local health ok"}

    monkeypatch.setattr(proxy_health, "check_http_proxy_forwarding", fake_probe)

    result = proxy_health.check_forwarding_path_health(timeout=0.3)

    assert result["ok"] is True
    assert captured["target_url"] == (
        "http://127.0.0.1:18080/__docker_proxy_forwarding_canary"
    )


def test_forwarding_path_success_contract_cannot_include_stale_error(
    monkeypatch,
) -> None:
    proxy_health = _proxy_health_module()

    monkeypatch.delenv("CLAMAV_REQUIRED", raising=False)

    def fake_probe(**_kwargs):
        return {
            "ok": True,
            "detail": "HTTP/1.1 200 OK; local health ok",
            "status_code": 200,
            "body_complete": True,
            "local_health_ok": True,
        }

    monkeypatch.setattr(proxy_health, "check_http_proxy_forwarding", fake_probe)

    result = proxy_health.check_forwarding_path_health(
        timeout=0.3,
        av_icap_health={"ok": True, "detail": "ICAP/1.0 200 OK"},
    )

    assert result["ok"] is True
    assert result["detail"] == "HTTP/1.1 200 OK; local health ok"
    assert result["contract"] == (
        "Squid explicit forwarding path returned a local health response."
    )
    assert "timed out" not in result["detail"]
    assert "degraded" not in result["contract"]


def test_forwarding_path_timeout_with_healthy_av_cannot_claim_local_health(
    monkeypatch,
) -> None:
    proxy_health = _proxy_health_module()

    monkeypatch.delenv("CLAMAV_REQUIRED", raising=False)

    def fake_probe(**_kwargs):
        return {"ok": False, "detail": "timed out"}

    monkeypatch.setattr(proxy_health, "check_http_proxy_forwarding", fake_probe)

    result = proxy_health.check_forwarding_path_health(
        timeout=0.3,
        av_icap_health={"ok": True, "detail": "ICAP/1.0 200 OK"},
    )

    assert result["ok"] is False
    assert result["av_icap_ok"] is True
    assert result["detail"].startswith(
        "timed out | Squid explicit forwarding path is degraded"
    )
    assert "returned a local health response" not in result["detail"]
    assert "returned a local health response" not in result["contract"]


def test_clamav_diagnostic_actions_include_resolved_targets(monkeypatch) -> None:
    proxy_health = _proxy_health_module()

    monkeypatch.setenv("CICAP_HOST", "av-proxy")
    monkeypatch.setenv("CICAP_AV_PORT", "15001")
    monkeypatch.setenv("CLAMD_HOST", "127.0.0.1")
    monkeypatch.setenv("CLAMD_PORT", "13310")

    def fake_sample(**kwargs):
        assert kwargs["host"] == "av-proxy"
        assert kwargs["port"] == 15001
        assert kwargs["service"] == "/avrespmod"
        return {"ok": True, "detail": "ICAP/1.0 204 No Content"}

    def fake_eicar(**kwargs):
        assert kwargs["host"] == "127.0.0.1"
        assert kwargs["port"] == 13310
        return {"ok": True, "detail": "stream: Eicar-Test-Signature FOUND"}

    monkeypatch.setattr(proxy_health, "send_sample_respmod_to", fake_sample)
    monkeypatch.setattr(proxy_health, "test_clamd_eicar", fake_eicar)

    assert proxy_health.send_sample_av_icap() == {
        "ok": True,
        "detail": "ICAP/1.0 204 No Content",
        "host": "av-proxy",
        "port": 15001,
        "target": "av-proxy:15001",
        "service": "/avrespmod",
    }
    assert proxy_health.test_eicar() == {
        "ok": True,
        "detail": "stream: Eicar-Test-Signature FOUND",
        "host": "127.0.0.1",
        "port": 13310,
        "target": "127.0.0.1:13310",
    }


def test_remote_clamd_av_health_checks_upload_and_download_icap_ports(
    monkeypatch,
) -> None:
    proxy_health = _proxy_health_module()
    calls: list[tuple[str, int, str]] = []

    monkeypatch.setenv("CICAP_HOST", "av-proxy")
    monkeypatch.setenv("CICAP_PORT", "24000")
    monkeypatch.setenv("CICAP_AV_PORT", "24001")
    monkeypatch.setenv("CLAMD_HOST", "clamd-proxy")
    monkeypatch.setenv("SQUID_WORKERS", "3")

    def fake_check(**kwargs):
        calls.append((kwargs["host"], kwargs["port"], kwargs["service"]))
        return {"ok": True, "detail": f"ICAP {kwargs['port']} OK"}

    monkeypatch.setattr(proxy_health, "check_icap_service", fake_check)

    result = proxy_health.check_av_icap_health(timeout=0.4)

    assert calls == [
        ("av-proxy", 24003, "/avrespmod"),
        ("av-proxy", 24006, "/avrespmod"),
    ]
    assert result["ok"] is True
    assert result["host"] == "av-proxy"
    assert result["port"] == 24006
    assert result["components"]["upload_av_icap"]["port"] == 24003
    assert result["components"]["download_av_icap"]["port"] == 24006


def test_remote_clamd_av_health_fails_when_download_respmod_is_down(
    monkeypatch,
) -> None:
    proxy_health = _proxy_health_module()

    monkeypatch.setenv("CICAP_AV_PORT", "15001")
    monkeypatch.setenv("CLAMD_HOST", "clamd-proxy")
    monkeypatch.setenv("SQUID_WORKERS", "1")

    def fake_check(**kwargs):
        if kwargs["port"] == 15002:
            return {"ok": False, "detail": "connection refused"}
        return {"ok": True, "detail": "ICAP/1.0 200 OK"}

    monkeypatch.setattr(proxy_health, "check_icap_service", fake_check)

    result = proxy_health.check_av_icap_health(timeout=0.4)

    assert result["ok"] is False
    assert result["components"]["upload_av_icap"]["ok"] is True
    assert result["components"]["download_av_icap"]["ok"] is False
    assert "download=connection refused" in result["detail"]


def test_remote_clamd_sample_av_icap_targets_download_respmod_port(monkeypatch) -> None:
    proxy_health = _proxy_health_module()
    captured: dict[str, object] = {}

    monkeypatch.setenv("CICAP_AV_PORT", "15001")
    monkeypatch.setenv("CICAP_AV_RESP_PORT", "16000")
    monkeypatch.setenv("CLAMD_HOST", "clamd-proxy")

    def fake_sample(**kwargs):
        captured.update(kwargs)
        return {"ok": True, "detail": "ICAP/1.0 204 No Content"}

    monkeypatch.setattr(proxy_health, "send_sample_respmod_to", fake_sample)

    result = proxy_health.send_sample_av_icap()

    assert captured["port"] == 16000
    assert result["port"] == 16000
    assert result["target"] == "127.0.0.1:16000"
