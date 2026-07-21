from __future__ import annotations

import importlib.util
import socket
import threading
from pathlib import Path


def _load_runner():
    path = Path(__file__).resolve().parents[2] / "docker" / "cicap_av_runner.py"
    spec = importlib.util.spec_from_file_location("cicap_av_runner", path)
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_optional_unavailable_clamd_serves_fail_open_placeholder(monkeypatch) -> None:
    runner = _load_runner()
    calls: list[tuple[str, str, int, bool]] = []

    monkeypatch.delenv("CLAMAV_REQUIRED", raising=False)
    monkeypatch.delenv("FILE_SECURITY_AV_REQUIRED", raising=False)
    monkeypatch.setattr(runner, "clamd_ready", lambda _host, _port: False)
    monkeypatch.setattr(
        runner,
        "run_unavailable_placeholder",
        lambda conf_path, *, host, port, fail_open: calls.append(
            (conf_path, host, port, fail_open),
        ),
    )

    assert runner.main(["cicap_av_runner.py", "/etc/c-icap/av.conf"]) == 0

    assert calls == [("/etc/c-icap/av.conf", "127.0.0.1", 3310, True)]


def test_required_unavailable_clamd_serves_fail_closed_placeholder(monkeypatch) -> None:
    runner = _load_runner()
    calls: list[tuple[str, str, int, bool]] = []

    monkeypatch.setenv("CLAMAV_REQUIRED", "1")
    monkeypatch.setattr(runner, "clamd_ready", lambda _host, _port: False)
    monkeypatch.setattr(
        runner,
        "run_unavailable_placeholder",
        lambda conf_path, *, host, port, fail_open: calls.append(
            (conf_path, host, port, fail_open),
        ),
    )

    assert runner.main(["cicap_av_runner.py", "/etc/c-icap/av.conf"]) == 0
    assert calls == [("/etc/c-icap/av.conf", "127.0.0.1", 3310, False)]


def test_ready_clamd_execs_c_icap(monkeypatch) -> None:
    runner = _load_runner()
    exec_calls: list[tuple[str, list[str]]] = []

    class ExecCalledError(Exception):
        pass

    def fake_execv(path, argv):
        exec_calls.append((path, argv))
        raise ExecCalledError

    monkeypatch.setattr(runner, "clamd_ready", lambda _host, _port: True)
    monkeypatch.setattr(runner.os, "execv", fake_execv)

    try:
        runner.main(["cicap_av_runner.py", "/etc/c-icap/av.conf"])
    except ExecCalledError:
        pass

    assert exec_calls == [
        ("/usr/bin/c-icap", ["/usr/bin/c-icap", "-N", "-f", "/etc/c-icap/av.conf"]),
    ]


def _placeholder_exchange(runner, *, fail_open: bool, method: str) -> bytes:
    with runner._FailOpenAvServer(
        ("127.0.0.1", 0), runner._FailOpenAvHandler
    ) as server:
        server.fail_open = fail_open
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        if method == "RESPMOD":
            http_header = b"HTTP/1.1 204 No Content\r\nCache-Control: no-store\r\n\r\n"
            request = (
                (
                    f"{method} icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
                    "Host: 127.0.0.1\r\n"
                    "Allow: 204\r\n"
                    f"Encapsulated: res-hdr=0, null-body={len(http_header)}\r\n\r\n"
                ).encode("ascii")
                + http_header
            )
        else:
            request = (
                f"{method} icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
                "Host: 127.0.0.1\r\n"
                "Allow: 204\r\n"
                "Encapsulated: null-body=0\r\n\r\n"
            ).encode("ascii")
        with socket.create_connection(("127.0.0.1", port), timeout=1) as sock:
            sock.settimeout(1)
            sock.sendall(request)
            response = sock.recv(4096)
        server.shutdown()
        thread.join(timeout=1)
    return response


def _placeholder_raw_exchange(
    runner, request: bytes, *, fail_open: bool = True, shutdown_write: bool = False
) -> bytes:
    with runner._FailOpenAvServer(
        ("127.0.0.1", 0), runner._FailOpenAvHandler
    ) as server:
        server.fail_open = fail_open
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        request = request.replace(b"{port}", str(port).encode("ascii"))
        with socket.create_connection(("127.0.0.1", port), timeout=1) as sock:
            sock.settimeout(1)
            sock.sendall(request)
            if shutdown_write:
                sock.shutdown(socket.SHUT_WR)
            response = bytearray()
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response.extend(chunk)
        server.shutdown()
        thread.join(timeout=1)
    return bytes(response)


def test_fail_open_placeholder_accepts_valid_icap_start_line_matrix() -> None:
    runner = _load_runner()
    response_header = b"HTTP/1.1 204 No Content\r\nCache-Control: no-store\r\n\r\n"
    cases = (
        (
            "OPTIONS",
            (
                b"OPTIONS icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Encapsulated: null-body=0\r\n\r\n"
            ),
            b"ICAP/1.0 200 OK\r\n",
        ),
        (
            "REQMOD",
            (
                b"REQMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Encapsulated: null-body=0\r\n\r\n"
            ),
            b"ICAP/1.0 204 No Content\r\n",
        ),
        (
            "RESPMOD",
            (
                b"RESPMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Allow: 204\r\n"
                b"Encapsulated: res-hdr=0, null-body="
                + str(len(response_header)).encode("ascii")
                + b"\r\n\r\n"
                + response_header
            ),
            b"ICAP/1.0 204 No Content\r\n",
        ),
        (
            "mixed-case REQMOD compatibility",
            (
                b"rEqMoD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Encapsulated: null-body=0\r\n\r\n"
            ),
            b"ICAP/1.0 204 No Content\r\n",
        ),
    )

    for name, request, expected_prefix in cases:
        response = _placeholder_raw_exchange(runner, request)

        assert response.startswith(expected_prefix), name
        assert b"HTTP/1.1 502 Bad Gateway" not in response, name


def test_fail_open_placeholder_rejects_ambiguous_icap_start_line_matrix() -> None:
    runner = _load_runner()
    cases = (
        (
            "missing target token",
            (
                b"REQMOD ICAP/1.0\r\nHost: 127.0.0.1\r\n"
                b"Encapsulated: null-body=0\r\n\r\n"
            ),
        ),
        (
            "extra token",
            (
                b"REQMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0 extra\r\n"
                b"Host: 127.0.0.1\r\nEncapsulated: null-body=0\r\n\r\n"
            ),
        ),
        (
            "extra spacing",
            (
                b"REQMOD  icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
                b"Host: 127.0.0.1\r\nEncapsulated: null-body=0\r\n\r\n"
            ),
        ),
        (
            "tab separator",
            (
                b"REQMOD\ticap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
                b"Host: 127.0.0.1\r\nEncapsulated: null-body=0\r\n\r\n"
            ),
        ),
        (
            "control in target",
            (
                b"REQMOD icap://127.0.0.1:{port}/av\x1frespmod ICAP/1.0\r\n"
                b"Host: 127.0.0.1\r\nEncapsulated: null-body=0\r\n\r\n"
            ),
        ),
        (
            "non-ASCII in target",
            (
                b"REQMOD icap://127.0.0.1:{port}/av\xffrespmod ICAP/1.0\r\n"
                b"Host: 127.0.0.1\r\nEncapsulated: null-body=0\r\n\r\n"
            ),
        ),
        (
            "invalid method token",
            (
                b"REQ/MOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
                b"Host: 127.0.0.1\r\nEncapsulated: null-body=0\r\n\r\n"
            ),
        ),
        (
            "unsupported ICAP version",
            (
                b"REQMOD icap://127.0.0.1:{port}/avrespmod ICAP/2.0\r\n"
                b"Host: 127.0.0.1\r\nEncapsulated: null-body=0\r\n\r\n"
            ),
        ),
        (
            "malformed ICAP version",
            (
                b"REQMOD icap://127.0.0.1:{port}/avrespmod HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\nEncapsulated: null-body=0\r\n\r\n"
            ),
        ),
        (
            "relative target",
            (
                b"REQMOD /avrespmod ICAP/1.0\r\nHost: 127.0.0.1\r\n"
                b"Encapsulated: null-body=0\r\n\r\n"
            ),
        ),
        (
            "empty service target",
            (
                b"REQMOD icap://127.0.0.1:{port} ICAP/1.0\r\n"
                b"Host: 127.0.0.1\r\nEncapsulated: null-body=0\r\n\r\n"
            ),
        ),
        (
            "response-line masquerade",
            (
                b"ICAP/1.0 200 OK\r\nHost: 127.0.0.1\r\n"
                b"Encapsulated: null-body=0\r\n\r\n"
            ),
        ),
        (
            "REQMOD LF injection",
            (
                b"REQMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\n"
                b"OPTIONS icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
                b"Host: 127.0.0.1\r\nEncapsulated: null-body=0\r\n\r\n"
            ),
        ),
        (
            "OPTIONS LF injection",
            (
                b"OPTIONS icap://127.0.0.1:{port}/avrespmod ICAP/1.0\n"
                b"REQMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
                b"Host: 127.0.0.1\r\nEncapsulated: null-body=0\r\n\r\n"
            ),
        ),
    )

    for name, request in cases:
        response = _placeholder_raw_exchange(runner, request)

        assert response.startswith(b"ICAP/1.0 200 OK\r\n"), name
        assert b"HTTP/1.1 502 Bad Gateway" in response, name
        assert b"ICAP/1.0 204 No Content\r\n" not in response, name
        assert b"Methods: REQMOD, RESPMOD" not in response, name


def test_fail_open_placeholder_keeps_405_for_well_formed_unsupported_method() -> None:
    runner = _load_runner()
    request = (
        b"PURGE icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Encapsulated: null-body=0\r\n\r\n"
    )

    response = _placeholder_raw_exchange(runner, request)

    assert response.startswith(b"ICAP/1.0 405 Method Not Allowed\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" not in response


class _MemorySocket:
    def __init__(self, incoming: bytes = b"") -> None:
        self.incoming = bytearray(incoming)
        self.sent = bytearray()

    def recv(self, size: int) -> bytes:
        chunk = bytes(self.incoming[:size])
        del self.incoming[:size]
        return chunk

    def sendall(self, data: bytes) -> None:
        self.sent.extend(data)


class _TimeoutSocket(_MemorySocket):
    def recv(self, size: int) -> bytes:
        if self.incoming:
            return super().recv(size)
        raise TimeoutError


class _ReadFailureSocket(_MemorySocket):
    def __init__(self, incoming: bytes, exc: OSError) -> None:
        super().__init__(incoming)
        self.exc = exc

    def recv(self, size: int) -> bytes:
        if self.incoming:
            return super().recv(size)
        raise self.exc


def test_read_failures_after_partial_encapsulated_headers_are_protocol_errors() -> None:
    runner = _load_runner()
    socket_timeout = vars(socket)["timeout"]
    req_header = b"POST /upload HTTP/1.1\r\nHost: example.test\r\n\r\n"
    resp_header = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"
    cases = (
        (
            "REQMOD",
            runner._drain_encapsulated_body,
            b"REQMOD icap://127.0.0.1/avrespmod ICAP/1.0\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Encapsulated: req-hdr=0, null-body="
            + str(len(req_header)).encode("ascii")
            + b"\r\n\r\n",
            req_header[:-1],
            "REQMOD encapsulated headers ended before declared offsets",
        ),
        (
            "RESPMOD",
            runner._read_respmod_payload,
            b"RESPMOD icap://127.0.0.1/avrespmod ICAP/1.0\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Encapsulated: res-hdr=0, null-body="
            + str(len(resp_header)).encode("ascii")
            + b"\r\n\r\n",
            resp_header[:-1],
            "RESPMOD encapsulated headers ended before declared offsets",
        ),
    )
    failures: tuple[tuple[str, OSError], ...] = (
        ("socket.timeout", socket_timeout("timed out")),
        ("TimeoutError", TimeoutError("timed out")),
        ("OSError", OSError("read failed")),
    )

    for name, read_payload, header, partial, expected in cases:
        for exc_name, exc in failures:
            sock = _ReadFailureSocket(partial, exc)

            try:
                read_payload(sock, header.split(runner.HEADER_END, 1)[0], b"")
            except runner.IcapProtocolError as protocol_exc:
                assert expected in str(protocol_exc), (name, exc_name)
            else:  # pragma: no cover - regression guard should always raise
                message = f"{name} partial encapsulated header read failure was accepted"
                raise AssertionError(message)


def test_read_failures_after_partial_chunk_paths_are_protocol_errors() -> None:
    runner = _load_runner()
    socket_timeout = vars(socket)["timeout"]
    cases = (
        (
            "chunk-size line",
            b"",
            b"5",
            False,
            b"",
            "truncated ICAP chunk-size line",
        ),
        (
            "chunk payload",
            b"5\r\nabc",
            b"",
            False,
            b"",
            "truncated ICAP chunk payload",
        ),
        (
            "trailer",
            b"0\r\nX-Trailer: partial",
            b"",
            False,
            b"",
            "truncated ICAP chunk trailers",
        ),
        (
            "preview continuation",
            b"4\r\ntest\r\n0\r\n\r\n",
            b"5",
            True,
            b"ICAP/1.0 100 Continue\r\n\r\n",
            "truncated ICAP chunk-size line",
        ),
    )
    failures: tuple[tuple[str, OSError], ...] = (
        ("socket.timeout", socket_timeout("timed out")),
        ("TimeoutError", TimeoutError("timed out")),
        ("OSError", OSError("read failed")),
    )

    for name, initial, incoming, preview, expected_sent, expected_error in cases:
        for exc_name, exc in failures:
            sock = _ReadFailureSocket(incoming, exc)

            try:
                runner._drain_chunked_body(sock, initial, preview=preview)
            except runner.IcapProtocolError as protocol_exc:
                assert expected_error in str(protocol_exc), (name, exc_name)
            else:  # pragma: no cover - regression guard should always raise
                message = f"{name} read failure was accepted"
                raise AssertionError(message)

            assert sock.sent == expected_sent, (name, exc_name)


def _reqmod_null_body_outer_header(runner, *, size: int | None = None) -> bytes:
    lines = [
        b"REQMOD icap://127.0.0.1/avrespmod ICAP/1.0",
        b"Host: 127.0.0.1",
        b"Allow: 204",
        b"Encapsulated: null-body=0",
    ]
    if size is None:
        return runner.CRLF.join(lines)

    prefix = b"X-Pad: "
    full_pad_len = min(8000, runner.MAX_ICAP_HEADER_LINE_BYTES)
    base_len = len(runner.CRLF.join(lines))
    for full_count in range(32):
        final_len = size - base_len - (full_count * (len(runner.CRLF) + full_pad_len))
        if full_count or final_len != 0:
            final_len -= len(runner.CRLF)
        if len(prefix) <= final_len <= runner.MAX_ICAP_HEADER_LINE_BYTES:
            lines.extend(
                prefix + (b"a" * (full_pad_len - len(prefix)))
                for _ in range(full_count)
            )
            lines.append(prefix + (b"b" * (final_len - len(prefix))))
            header = runner.CRLF.join(lines)
            assert len(header) == size
            return header
    message = f"could not construct {size}-byte ICAP header"
    raise AssertionError(message)


def test_read_icap_outer_header_allows_exact_boundary_and_preserves_remainder() -> None:
    runner = _load_runner()
    header = _reqmod_null_body_outer_header(
        runner, size=runner.DEFAULT_MAX_HEADER_BYTES
    )
    remainder = b"0\r\n\r\nPIPELINED"
    sock = _MemorySocket(header + runner.HEADER_END + remainder)

    parsed, parsed_remainder = runner._read_icap_outer_header(sock)

    assert parsed == header
    assert parsed_remainder == b""
    assert bytes(sock.incoming) == remainder

    small_header = _reqmod_null_body_outer_header(runner)
    sock = _MemorySocket(small_header + runner.HEADER_END + remainder)

    parsed, parsed_remainder = runner._read_icap_outer_header(sock)

    assert parsed == small_header
    assert parsed_remainder == remainder


def test_read_icap_outer_header_rejects_outer_header_read_matrix() -> None:
    runner = _load_runner()
    base_header = _reqmod_null_body_outer_header(runner)
    short_lines_over_limit = _reqmod_null_body_outer_header(
        runner, size=runner.DEFAULT_MAX_HEADER_BYTES + 1
    )
    cases = (
        (
            "header block over 64KiB",
            short_lines_over_limit + runner.HEADER_END,
            "ICAP header block exceeds",
            _MemorySocket,
        ),
        (
            "one huge unterminated line",
            base_header
            + runner.CRLF
            + b"X-Huge: "
            + (b"a" * runner.MAX_ICAP_HEADER_LINE_BYTES),
            "ICAP header line exceeds",
            _MemorySocket,
        ),
        (
            "EOF before CRLFCRLF",
            base_header + runner.CRLF + b"X-Partial: value",
            "truncated ICAP header",
            _MemorySocket,
        ),
        (
            "socket timeout after partial reads",
            base_header + runner.CRLF + b"X-Partial: value",
            "truncated ICAP header",
            _TimeoutSocket,
        ),
    )

    for name, incoming, expected, socket_factory in cases:
        sock = socket_factory(incoming)
        try:
            runner._read_icap_outer_header(sock)
        except runner.IcapProtocolError as exc:
            assert expected in str(exc), name
        else:  # pragma: no cover - regression guard should always raise
            message = f"{name} ICAP outer header was accepted"
            raise AssertionError(message)


def test_read_icap_outer_header_rejects_delimiter_beyond_aggregate_bound() -> None:
    runner = _load_runner()
    header = _reqmod_null_body_outer_header(
        runner, size=runner.DEFAULT_MAX_HEADER_BYTES
    )
    sock = _MemorySocket(header + b"X" + runner.HEADER_END)

    try:
        runner._read_icap_outer_header(sock)
    except runner.IcapProtocolError as exc:
        assert "ICAP header block exceeds" in str(exc)
    else:  # pragma: no cover - regression guard should always raise
        message = "delimiter beyond ICAP header bound was accepted"
        raise AssertionError(message)


def test_fail_open_placeholder_rejects_truncated_or_oversized_outer_header() -> None:
    runner = _load_runner()
    base = (
        b"REQMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Allow: 204\r\n"
        b"Encapsulated: null-body=0\r\n"
    )
    aggregate_padding = (b"X-Pad: " + (b"a" * 1024) + b"\r\n") * 70
    cases = (
        (
            "aggregate over 64KiB",
            base + aggregate_padding + b"\r\n",
            False,
            b"ICAP header block exceeds",
        ),
        (
            "huge line before delimiter",
            base
            + b"X-Huge: "
            + (b"a" * runner.MAX_ICAP_HEADER_LINE_BYTES)
            + b"\r\n\r\n",
            False,
            b"ICAP header line exceeds",
        ),
        (
            "EOF before CRLFCRLF",
            base,
            True,
            b"truncated ICAP header",
        ),
    )

    for name, request, shutdown_write, expected in cases:
        response = _placeholder_raw_exchange(
            runner, request, shutdown_write=shutdown_write
        )

        assert response.startswith(b"ICAP/1.0 200 OK\r\n"), name
        assert b"HTTP/1.1 502 Bad Gateway" in response, name
        assert expected in response, name
        assert not response.startswith(b"ICAP/1.0 204 No Content\r\n"), name


def test_drain_chunked_body_rejects_malformed_or_truncated_reqmod_chunks() -> None:
    runner = _load_runner()
    cases = (
        ("empty chunk-size line", b"\r\n"),
        ("non-hex chunk-size line", b"G\r\npayload\r\n0\r\n\r\n"),
        ("signed chunk-size line", b"+0\r\n\r\n"),
        ("prefixed chunk-size line", b"0x1\r\nx\r\n0\r\n\r\n"),
        ("short payload", b"5\r\nabc\r\n0\r\n\r\n"),
        ("missing payload CRLF", b"3\r\nabcXX0\r\n\r\n"),
        ("EOF before zero chunk", b"3\r\nabc\r\n"),
        ("malformed trailer", b"0\r\nBad Trailer: x\r\n\r\n"),
        ("unterminated trailer", b"0\r\nX-Trailer: x\r\n"),
    )

    for name, body in cases:
        sock = _MemorySocket()

        try:
            runner._drain_chunked_body(sock, body)
        except runner.IcapProtocolError:
            pass
        else:  # pragma: no cover - regression guard should always raise
            message = f"{name} was accepted as drained"
            raise AssertionError(message)

        assert sock.sent == b"", name


def test_drain_chunked_body_rejects_invalid_or_unsafe_trailers() -> None:
    runner = _load_runner()
    trailer_line_limit = getattr(runner, "MAX_ICAP_TRAILER_LINE_BYTES", 8192)
    long_line = b"X" * (trailer_line_limit + 1)
    aggregate_lines = (b"X-Trailer: " + (b"a" * 1024) + b"\r\n") * 70
    cases = (
        (
            "whitespace before colon",
            b"0\r\nBad : value\r\n\r\n",
            "invalid ICAP chunk trailer field name",
        ),
        (
            "empty field name",
            b"0\r\n: value\r\n\r\n",
            "invalid ICAP chunk trailer field name",
        ),
        (
            "invalid field token",
            b"0\r\nBad/Name: value\r\n\r\n",
            "invalid ICAP chunk trailer field name",
        ),
        (
            "non-ASCII field name",
            b"0\r\nX-\xff: value\r\n\r\n",
            "invalid ICAP chunk trailer field name",
        ),
        (
            "control field name",
            b"0\r\nBad\x1f: value\r\n\r\n",
            "invalid ICAP chunk trailer field name",
        ),
        (
            "obs-fold continuation",
            b"0\r\nX-Trailer: value\r\n folded\r\n\r\n",
            "invalid ICAP chunk trailer",
        ),
        (
            "missing colon",
            b"0\r\nMissing-Colon\r\n\r\n",
            "invalid ICAP chunk trailer",
        ),
        (
            "NUL value",
            b"0\r\nX-Trailer: ok\x00bad\r\n\r\n",
            "invalid ICAP chunk trailer value",
        ),
        (
            "control value",
            b"0\r\nX-Trailer: ok\x1fbad\r\n\r\n",
            "invalid ICAP chunk trailer value",
        ),
        (
            "very long individual line",
            b"0\r\n" + long_line + b": value\r\n\r\n",
            "ICAP chunk trailer line exceeds",
        ),
        (
            "many lines exceed aggregate bound",
            b"0\r\n" + aggregate_lines + b"\r\n",
            "ICAP chunk trailers exceed",
        ),
        (
            "duplicate sensitive framing names",
            b"0\r\nContent-Length: 1\r\ncontent-length: 2\r\n\r\n",
            "forbidden ICAP chunk trailer field",
        ),
        (
            "encapsulated control name",
            b"0\r\nEncapsulated: null-body=0\r\n\r\n",
            "forbidden ICAP chunk trailer field",
        ),
        (
            "allow control name",
            b"0\r\nAllow: 204\r\n\r\n",
            "forbidden ICAP chunk trailer field",
        ),
        (
            "preview control name",
            b"0\r\nPreview: 0\r\n\r\n",
            "forbidden ICAP chunk trailer field",
        ),
        (
            "transfer encoding framing name",
            b"0\r\nTransfer-Encoding: chunked\r\n\r\n",
            "forbidden ICAP chunk trailer field",
        ),
    )

    for name, body, expected in cases:
        sock = _MemorySocket()

        try:
            runner._drain_chunked_body(sock, body)
        except runner.IcapProtocolError as exc:
            assert expected in str(exc), name
        else:  # pragma: no cover - regression guard should always raise
            message = f"{name} trailer was accepted as drained"
            raise AssertionError(message)

        assert sock.sent == b"", name


def test_drain_chunked_body_preserves_valid_token_ows_and_unknown_trailers() -> None:
    runner = _load_runner()
    sock = _MemorySocket()

    remainder = runner._drain_chunked_body(
        sock,
        b"0\r\n"
        b"X_Token-Name!#$%&'*+-.^_`|~09AZaz: \t ok \t\r\n"
        b"X-Unknown-Extension: clean; meta=1\r\n"
        b"\r\nNEXT",
    )

    assert sock.sent == b""
    assert remainder == b"NEXT"


def test_drain_chunked_body_preserves_valid_trailers_remainder_and_preview_continue() -> None:
    runner = _load_runner()
    continuation = b"5\r\n-rest\r\n0; done=yes\r\nX-Trailer: ok\r\n\r\nNEXT"
    sock = _MemorySocket(continuation)

    remainder = runner._drain_chunked_body(
        sock,
        b"4; note=not-eof\r\ntest\r\n0\r\n\r\n",
        preview=True,
    )

    assert sock.sent == b"ICAP/1.0 100 Continue\r\n\r\n"
    assert remainder == b"NEXT"


def test_drain_chunked_body_preview_ieof_zero_does_not_continue() -> None:
    runner = _load_runner()
    sock = _MemorySocket()

    remainder = runner._drain_chunked_body(sock, b"0; ieof\r\n\r\n", preview=True)

    assert sock.sent == b""
    assert remainder == b""


def test_parse_chunk_size_rejects_unbounded_tokens_and_bad_extensions() -> None:
    runner = _load_runner()
    too_long = b"F" * (runner.MAX_ICAP_CHUNK_SIZE_DIGITS + 1)
    cases = (
        ("extremely long hex token", too_long),
        ("plus sign", b"+1"),
        ("minus sign", b"-1"),
        ("hex prefix", b"0x1"),
        ("underscore", b"1_0"),
        ("leading whitespace", b" 1"),
        ("trailing whitespace", b"1 "),
        ("empty extension", b"0;"),
        ("blank extension", b"0; \t"),
        ("internal extension whitespace", b"0;bad extension"),
        ("extension without name", b"0;=value"),
        ("extension without value", b"0;name="),
        ("unquoted whitespace in value", b"0;name=bad value"),
        ("control byte in extension name", b"0;bad\x01=x"),
        ("control byte in extension value", b"0;name=bad\x01"),
        ("unterminated quoted extension", b'0;name="bad'),
        ("duplicate ieof", b"0;ieof;IEOF"),
        ("valued ieof", b"0;ieof=0"),
        ("nonzero ieof", b"1;ieof"),
    )

    for name, line in cases:
        try:
            runner._parse_chunk_size(line)
        except runner.IcapProtocolError:
            pass
        else:  # pragma: no cover - regression guard should always raise
            message = f"{name} chunk-size line was accepted"
            raise AssertionError(message)


def test_parse_chunk_size_preserves_valid_extensions_and_ieof_case() -> None:
    runner = _load_runner()

    assert runner._parse_chunk_size(b"a; foo=bar; flag; quoted=\"a b;c\"") == 10
    assert runner._parse_chunk_size(b"0;IEOF") == 0
    size, extensions = runner._parse_chunk_line(b"0;IEOF")
    assert size == 0
    assert extensions == {b"ieof"}


def test_drain_chunked_body_preview_requires_ieof_extension_name() -> None:
    runner = _load_runner()
    sock = _MemorySocket(b"5\r\n-rest\r\n0;IEOF\r\n\r\nNEXT")

    remainder = runner._drain_chunked_body(
        sock,
        b"4; ordinary=yes\r\ntest\r\n0;not-ieof=1\r\n\r\n",
        preview=True,
    )

    assert sock.sent == b"ICAP/1.0 100 Continue\r\n\r\n"
    assert remainder == b"NEXT"


def test_drain_chunked_body_duplicate_preview_terminators_send_one_continue() -> None:
    runner = _load_runner()
    sock = _MemorySocket()

    remainder = runner._drain_chunked_body(
        sock,
        b"0\r\n\r\n0\r\n\r\nTAIL",
        preview=True,
    )

    assert sock.sent == b"ICAP/1.0 100 Continue\r\n\r\n"
    assert remainder == b"TAIL"


def test_parse_encapsulated_rejects_non_ascii_decimal_offsets_and_malformed_items() -> None:
    runner = _load_runner()
    enormous_offset = "9" * (runner.MAX_ENCAPSULATED_OFFSET_DIGITS + 1)
    cases = (
        ("plus sign", "req-hdr=+0, req-body=42", "invalid Encapsulated offset"),
        ("minus sign", "req-hdr=-0, req-body=42", "invalid Encapsulated offset"),
        ("underscore", "req-hdr=0, req-body=4_2", "invalid Encapsulated offset"),
        (
            "Unicode digits",
            "req-hdr=\N{ARABIC-INDIC DIGIT ZERO}, req-body=42",
            "invalid Encapsulated offset",
        ),
        ("internal whitespace", "req-hdr=0, req-body=4 2", "invalid Encapsulated offset"),
        ("empty offset", "req-hdr=, req-body=42", "invalid Encapsulated offset"),
        ("scientific", "req-hdr=0, req-body=1e2", "invalid Encapsulated offset"),
        ("hex", "req-hdr=0, req-body=0x2a", "invalid Encapsulated offset"),
        (
            "enormous decimal",
            f"req-hdr=0, req-body={enormous_offset}",
            "invalid Encapsulated offset",
        ),
        ("missing equals", "req-hdr=0, garbage, req-body=42", "malformed"),
        ("empty item", "req-hdr=0,, req-body=42", "malformed"),
    )

    for name, value, expected in cases:
        try:
            runner._parse_encapsulated(value)
        except runner.IcapProtocolError as exc:
            assert expected in str(exc), name
        else:  # pragma: no cover - regression guard should always raise
            message = f"{name} Encapsulated item was accepted"
            raise AssertionError(message)


def test_parse_encapsulated_preserves_ascii_decimals_leading_zeros_and_edge_whitespace() -> None:
    runner = _load_runner()

    offsets = runner._parse_encapsulated(
        " req-hdr = 000 , req-body = 00042 , null-body=43 "
    )

    assert offsets == {"req-hdr": 0, "req-body": 42, "null-body": 43}


def test_drain_encapsulated_body_rejects_truncated_reqmod_null_body_boundary() -> None:
    runner = _load_runner()
    sock = _MemorySocket()
    header = (
        b"REQMOD icap://127.0.0.1/avrespmod ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Allow: 204\r\n"
        b"Encapsulated: req-hdr=0, null-body=5"
    )

    try:
        runner._drain_encapsulated_body(sock, header, b"POST ")
    except runner.IcapProtocolError as exc:
        assert str(exc) == "invalid REQMOD encapsulated req-hdr boundary"
    else:  # pragma: no cover - regression guard should always raise
        message = "truncated REQMOD null-body boundary was accepted"
        raise AssertionError(message)


def test_drain_encapsulated_body_preserves_valid_reqmod_req_body_and_null_body() -> None:
    runner = _load_runner()
    request_header = b"POST /upload HTTP/1.1\r\nHost: example.test\r\n\r\n"
    body = b"5\r\nhello\r\n0\r\n\r\n"
    body_offset = len(request_header)

    req_body_header = (
        b"REQMOD icap://127.0.0.1/avrespmod ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Encapsulated: req-hdr=0, req-body="
        + str(body_offset).encode("ascii")
    )
    null_body_header = (
        b"REQMOD icap://127.0.0.1/avrespmod ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Encapsulated: req-hdr=0, null-body="
        + str(body_offset).encode("ascii")
    )

    for header, remainder in (
        (req_body_header, request_header + body),
        (null_body_header, request_header),
    ):
        sock = _MemorySocket()

        runner._drain_encapsulated_body(sock, header, remainder)

        assert sock.sent == b""


def test_split_headers_rejects_duplicate_consumed_singletons_case_insensitive() -> None:
    runner = _load_runner()
    cases = (
        ("Encapsulated", "eNcApSuLaTeD", "duplicate ICAP Encapsulated header"),
        ("Allow", "aLlOw", "duplicate ICAP Allow header"),
        ("Preview", "pReViEw", "duplicate ICAP Preview header"),
    )

    for first_name, second_name, expected in cases:
        header = (
            "RESPMOD icap://127.0.0.1/avrespmod ICAP/1.0\r\n"
            f"{first_name}: 204\r\n"
            f"{second_name}: 204\r\n"
            "X-Repeatable-Extension: one\r\n"
            "x-repeatable-extension: two\r\n"
        ).encode("ascii")
        try:
            runner._split_headers(header)
        except runner.IcapProtocolError as exc:
            assert str(exc) == expected
        else:  # pragma: no cover - regression guard should always raise
            message = f"duplicate {first_name} header was accepted"
            raise AssertionError(message)


def test_split_headers_accepts_repeated_unknown_extension_header() -> None:
    runner = _load_runner()

    start_line, headers = runner._split_headers(
        b"REQMOD icap://127.0.0.1/avrespmod ICAP/1.0\r\n"
        b"X-Repeatable-Extension: one\r\n"
        b"x-repeatable-extension: two\r\n"
        b"Allow: 204\r\n"
        b"Encapsulated: null-body=0"
    )

    assert start_line == "REQMOD icap://127.0.0.1/avrespmod ICAP/1.0"
    assert headers["x-repeatable-extension"] == "two"
    assert headers["allow"] == "204"
    assert headers["encapsulated"] == "null-body=0"


def test_split_headers_rejects_malformed_outer_field_lines() -> None:
    runner = _load_runner()
    cases = (
        ("missing colon", b"Missing-Colon", "malformed ICAP header field line"),
        ("empty name", b": value", "invalid ICAP header field name"),
        ("whitespace before colon", b"Allow : 204", "invalid ICAP header field name"),
        ("tab before colon", b"Preview\t: 0", "invalid ICAP header field name"),
        ("invalid token", b"Bad/Name: value", "invalid ICAP header field name"),
        ("non-ASCII name", b"X-\xff: value", "invalid ICAP header field name"),
        ("control name", b"Bad\x1f: value", "invalid ICAP header field name"),
        ("obs-fold without colon", b" folded", "obsolete folded ICAP header line"),
        ("obs-fold with colon", b"\tFolded: value", "obsolete folded ICAP header line"),
        ("NUL value", b"X-Value: ok\x00bad", "invalid ICAP header field value"),
        ("control value", b"X-Value: ok\x1fbad", "invalid ICAP header field value"),
        ("DEL value", b"X-Value: ok\x7fbad", "invalid ICAP header field value"),
        (
            "Encapsulated lookalike",
            b"Encapsulated : null-body=0",
            "invalid ICAP header field name",
        ),
        ("Allow lookalike", b"Allow : 204", "invalid ICAP header field name"),
        ("Preview lookalike", b"Preview : 0", "invalid ICAP header field name"),
    )

    for name, field_line, expected in cases:
        header = b"REQMOD icap://127.0.0.1/avrespmod ICAP/1.0\r\n" + field_line
        try:
            runner._split_headers(header)
        except runner.IcapProtocolError as exc:
            assert expected in str(exc), name
        else:  # pragma: no cover - regression guard should always raise
            message = f"{name} outer ICAP header line was accepted"
            raise AssertionError(message)


def test_split_headers_preserves_valid_outer_tokens_ows_and_extensions() -> None:
    runner = _load_runner()

    start_line, headers = runner._split_headers(
        b"REQMOD icap://127.0.0.1/avrespmod ICAP/1.0\r\n"
        b"X_Token-Name!#$%&'*+-.^_`|~09AZaz: \t ok \t\r\n"
        b"X-Unknown-Extension: clean; meta=1\r\n"
        b"x-unknown-extension: replacement\r\n"
        b"Allow:  204 \t\r\n"
        b"Encapsulated: null-body=0"
    )

    assert start_line == "REQMOD icap://127.0.0.1/avrespmod ICAP/1.0"
    assert headers["x_token-name!#$%&'*+-.^_`|~09azaz"] == "ok"
    assert headers["x-unknown-extension"] == "replacement"
    assert headers["allow"] == "204"
    assert headers["encapsulated"] == "null-body=0"


def test_fail_open_placeholder_returns_204_for_transactions() -> None:
    runner = _load_runner()

    reqmod = _placeholder_exchange(runner, fail_open=True, method="REQMOD")
    respmod = _placeholder_exchange(runner, fail_open=True, method="RESPMOD")

    assert reqmod.startswith(b"ICAP/1.0 204 No Content\r\n")
    assert respmod.startswith(b"ICAP/1.0 204 No Content\r\n")
    assert b"clamav-fail-open-unavailable" in reqmod
    assert b"clamav-fail-open-unavailable" in respmod


def test_fail_closed_placeholder_keeps_service_unavailable_transactions() -> None:
    runner = _load_runner()

    response = _placeholder_exchange(runner, fail_open=False, method="RESPMOD")

    assert response.startswith(b"ICAP/1.0 500 Service Unavailable\r\n")
    assert b"clamav-fail-closed-unavailable" in response


def _placeholder_exchange_with_body(
    runner, *, fail_open: bool, method: str, body: bytes
) -> tuple[bytes, float]:
    with runner._FailOpenAvServer(
        ("127.0.0.1", 0), runner._FailOpenAvHandler
    ) as server:
        server.fail_open = fail_open
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        if method == "RESPMOD":
            http_header = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/octet-stream\r\n"
                + f"Content-Length: {len(body)}\r\n".encode("ascii")
                + b"\r\n"
            )
        else:
            http_header = (
                b"POST /upload HTTP/1.1\r\n"
                b"Content-Type: application/octet-stream\r\n"
                + f"Content-Length: {len(body)}\r\n".encode("ascii")
                + b"\r\n"
            )
        chunked = f"{len(body):X}\r\n".encode("ascii") + body + b"\r\n0\r\n\r\n"
        header_section = "req-hdr" if method == "REQMOD" else "res-hdr"
        encapsulated = "req-body" if method == "REQMOD" else "res-body"
        request = (
            (
                f"{method} icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
                "Host: 127.0.0.1\r\n"
                "Allow: 204\r\n"
                f"Encapsulated: {header_section}=0, "
                f"{encapsulated}={len(http_header)}\r\n\r\n"
            ).encode("ascii")
            + http_header
            + chunked
        )
        with socket.create_connection(("127.0.0.1", port), timeout=1) as sock:
            sock.settimeout(1)
            started = __import__("time").monotonic()
            sock.sendall(request)
            response = bytearray()
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response.extend(chunk)
            elapsed = __import__("time").monotonic() - started
        server.shutdown()
        thread.join(timeout=1)
    return bytes(response), elapsed


def test_fail_open_placeholder_drains_large_reqmod_body_before_204() -> None:
    runner = _load_runner()

    response, elapsed = _placeholder_exchange_with_body(
        runner, fail_open=True, method="REQMOD", body=b"x" * (1024 * 1024)
    )

    assert response.startswith(b"ICAP/1.0 204 No Content\r\n")
    assert elapsed < 1


def test_fail_open_placeholder_rejects_malformed_reqmod_chunked_body_before_204() -> None:
    runner = _load_runner()
    request_header = b"POST /upload HTTP/1.1\r\nHost: example.test\r\n\r\n"
    body = b"G\r\nhello\r\n0\r\n\r\n"
    request = (
        b"REQMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Allow: 204\r\n"
        b"Encapsulated: req-hdr=0, req-body="
        + str(len(request_header)).encode("ascii")
        + b"\r\n\r\n"
        + request_header
        + body
    )

    response = _placeholder_raw_exchange(runner, request)

    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert not response.startswith(b"ICAP/1.0 204 No Content\r\n")
    assert b"hello" not in response


def test_fail_open_placeholder_rejects_bad_chunk_extension_before_204() -> None:
    runner = _load_runner()
    request_header = b"POST /upload HTTP/1.1\r\nHost: example.test\r\n\r\n"
    body = b"0;bad extension\r\n\r\n"
    request = (
        b"REQMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Allow: 204\r\n"
        b"Encapsulated: req-hdr=0, req-body="
        + str(len(request_header)).encode("ascii")
        + b"\r\n\r\n"
        + request_header
        + body
    )

    response = _placeholder_raw_exchange(runner, request)

    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"invalid ICAP chunk extension" in response
    assert not response.startswith(b"ICAP/1.0 204 No Content\r\n")


def test_fail_open_placeholder_rejects_bad_chunk_trailer_before_204() -> None:
    runner = _load_runner()
    request_header = b"POST /upload HTTP/1.1\r\nHost: example.test\r\n\r\n"
    body = b"0\r\nX-Trailer: ok\x00bad\r\n\r\n"
    request = (
        b"REQMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Allow: 204\r\n"
        b"Encapsulated: req-hdr=0, req-body="
        + str(len(request_header)).encode("ascii")
        + b"\r\n\r\n"
        + request_header
        + body
    )

    response = _placeholder_raw_exchange(runner, request)

    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"invalid ICAP chunk trailer value" in response
    assert not response.startswith(b"ICAP/1.0 204 No Content\r\n")


def test_fail_open_placeholder_preserves_unknown_chunk_trailer_before_204() -> None:
    runner = _load_runner()
    request_header = b"POST /upload HTTP/1.1\r\nHost: example.test\r\n\r\n"
    body = b"0\r\nX-Unknown-Extension: clean\r\n\r\n"
    request = (
        b"REQMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Allow: 204\r\n"
        b"Encapsulated: req-hdr=0, req-body="
        + str(len(request_header)).encode("ascii")
        + b"\r\n\r\n"
        + request_header
        + body
    )

    response = _placeholder_raw_exchange(runner, request)

    assert response.startswith(b"ICAP/1.0 204 No Content\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" not in response


def test_fail_open_placeholder_preview_not_ieof_substring_continues() -> None:
    runner = _load_runner()

    with runner._FailOpenAvServer(
        ("127.0.0.1", 0), runner._FailOpenAvHandler
    ) as server:
        server.fail_open = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        http_header = b"POST /upload HTTP/1.1\r\nHost: example.test\r\n\r\n"
        request_prefix = (
            (
                f"REQMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
                "Host: 127.0.0.1\r\n"
                "Allow: 204\r\n"
                "Preview: 4\r\n"
                f"Encapsulated: req-hdr=0, req-body={len(http_header)}\r\n\r\n"
            ).encode("ascii")
            + http_header
        )
        preview = b"4\r\ntest\r\n0;not-ieof=1\r\n\r\n"
        remainder = b"0;IEOF\r\n\r\n"
        with socket.create_connection(("127.0.0.1", port), timeout=1) as sock:
            sock.settimeout(1)
            sock.sendall(request_prefix + preview)
            interim = sock.recv(4096)
            sock.sendall(remainder)
            final = sock.recv(4096)
        server.shutdown()
        thread.join(timeout=1)

    assert interim == b"ICAP/1.0 100 Continue\r\n\r\n"
    assert final.startswith(b"ICAP/1.0 204 No Content\r\n")


def test_fail_open_placeholder_rejects_invalid_offset_instead_of_reinterpreting_layout() -> None:
    runner = _load_runner()
    request_header = b"POST /upload HTTP/1.1\r\nHost: example.test\r\n\r\n"
    request = (
        b"REQMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Allow: 204\r\n"
        b"Encapsulated: req-hdr=0, req-body=4_2, null-body="
        + str(len(request_header)).encode("ascii")
        + b"\r\n\r\n"
        + request_header
    )

    response = _placeholder_raw_exchange(runner, request)

    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"invalid Encapsulated offset: req-body=4_2" in response
    assert not response.startswith(b"ICAP/1.0 204 No Content\r\n")


def test_fail_open_placeholder_rejects_malformed_encapsulated_item_before_204() -> None:
    runner = _load_runner()
    request_header = b"POST /upload HTTP/1.1\r\nHost: example.test\r\n\r\n"
    body = b"5\r\nhello\r\n0\r\n\r\n"
    request = (
        b"REQMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Allow: 204\r\n"
        b"Encapsulated: garbage, req-hdr=0, req-body="
        + str(len(request_header)).encode("ascii")
        + b"\r\n\r\n"
        + request_header
        + body
    )

    response = _placeholder_raw_exchange(runner, request)

    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"malformed Encapsulated section item: garbage" in response
    assert not response.startswith(b"ICAP/1.0 204 No Content\r\n")
    assert b"hello" not in response


def test_fail_open_placeholder_replays_respmod_body_instead_of_late_204() -> None:
    runner = _load_runner()

    response, elapsed = _placeholder_exchange_with_body(
        runner, fail_open=True, method="RESPMOD", body=b"hello" * 1024
    )

    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 200 OK" in response
    assert b"Content-Length: 5120\r\n" in response
    assert b"1400\r\n" + (b"hello" * 1024) + b"\r\n0\r\n\r\n" in response
    assert elapsed < 1


def _respmod_request_for_response(
    http_header: bytes,
    *,
    allow_204: bool = False,
    body: bytes | None = None,
) -> bytes:
    body_section = b""
    terminal_name = "null-body"
    if body is not None:
        terminal_name = "res-body"
        body_section = f"{len(body):X}\r\n".encode("ascii") + body + b"\r\n0\r\n\r\n"
    allow_header = b"Allow: 204\r\n" if allow_204 else b""
    return (
        b"RESPMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        + allow_header
        + f"Encapsulated: res-hdr=0, {terminal_name}={len(http_header)}".encode(
            "ascii"
        )
        + b"\r\n\r\n"
        + http_header
        + body_section
    )


def test_fail_open_placeholder_rejects_malformed_respmod_status_line_before_204_or_replay() -> None:
    runner = _load_runner()
    cases = (
        (
            "missing status line",
            b"X-Header: value\r\n\r\n",
            True,
            None,
        ),
        (
            "request-line masquerade with body",
            b"GET /download HTTP/1.1\r\nHost: example.test\r\n\r\n",
            False,
            b"hello",
        ),
        (
            "unsupported HTTP version",
            b"HTTP/2 200 OK\r\nContent-Length: 5\r\n\r\n",
            False,
            b"hello",
        ),
        (
            "non-three-digit status",
            b"HTTP/1.1 20 OK\r\nContent-Length: 5\r\n\r\n",
            False,
            b"hello",
        ),
        (
            "out-of-range status",
            b"HTTP/1.1 700 No Such Status\r\nContent-Length: 5\r\n\r\n",
            False,
            b"hello",
        ),
        (
            "extra spacing",
            b"HTTP/1.1  200 OK\r\nContent-Length: 5\r\n\r\n",
            False,
            b"hello",
        ),
        (
            "extra pre-reason spacing",
            b"HTTP/1.1 200  OK\r\nContent-Length: 5\r\n\r\n",
            False,
            b"hello",
        ),
        (
            "control reason byte",
            b"HTTP/1.1 200 OK\x1f\r\nContent-Length: 5\r\n\r\n",
            False,
            b"hello",
        ),
        (
            "non-ASCII reason byte",
            b"HTTP/1.1 200 Caf\xe9\r\nContent-Length: 5\r\n\r\n",
            False,
            b"hello",
        ),
        (
            "1xx with body",
            b"HTTP/1.1 101 Switching Protocols\r\nContent-Length: 5\r\n\r\n",
            False,
            b"hello",
        ),
        (
            "204 with body",
            b"HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n",
            False,
            b"hello",
        ),
        (
            "304 with body",
            b"HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\n\r\n",
            False,
            b"hello",
        ),
    )

    for name, http_header, allow_204, body in cases:
        response = _placeholder_raw_exchange(
            runner,
            _respmod_request_for_response(
                http_header,
                allow_204=allow_204,
                body=body,
            ),
        )

        assert response.startswith(b"ICAP/1.0 200 OK\r\n"), name
        assert b"HTTP/1.1 502 Bad Gateway" in response, name
        assert not response.startswith(b"ICAP/1.0 204 No Content\r\n"), name
        assert b"5\r\nhello\r\n0\r\n\r\n" not in response, name
        assert b"GET /download HTTP/1.1" not in response, name


def test_fail_open_placeholder_preserves_valid_respmod_status_line_matrix() -> None:
    runner = _load_runner()
    cases = (
        (
            "HTTP/1.0 body replay",
            b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\n",
            False,
            b"hello",
            b"HTTP/1.0 200 OK",
        ),
        (
            "HTTP/1.1 body replay with reason phrase tokens",
            b"HTTP/1.1 404 Not Found Here\r\nContent-Length: 5\r\n\r\n",
            False,
            b"hello",
            b"HTTP/1.1 404 Not Found Here",
        ),
        (
            "HTTP/1.1 null-body 304 may become 204 when allowed",
            b"HTTP/1.1 304 Not Modified\r\nCache-Control: no-store\r\n\r\n",
            True,
            None,
            b"ICAP/1.0 204 No Content",
        ),
        (
            "HTTP/1.1 empty reason phrase",
            b"HTTP/1.1 500 \r\nConnection: close\r\n\r\n",
            False,
            None,
            b"HTTP/1.1 500 ",
        ),
    )

    for name, http_header, allow_204, body, expected in cases:
        response = _placeholder_raw_exchange(
            runner,
            _respmod_request_for_response(
                http_header,
                allow_204=allow_204,
                body=body,
            ),
        )

        assert b"HTTP/1.1 502 Bad Gateway" not in response, name
        assert expected in response, name
        if body:
            assert b"5\r\nhello\r\n0\r\n\r\n" in response, name


def test_fail_open_placeholder_rejects_malformed_respmod_http_field_lines_before_204_or_replay() -> None:
    runner = _load_runner()
    cases = (
        ("missing colon", b"Missing-Colon", b"malformed RESPMOD encapsulated HTTP header field line"),
        ("empty name", b": value", b"invalid RESPMOD encapsulated HTTP header field name"),
        ("whitespace before colon", b"Bad : value", b"invalid RESPMOD encapsulated HTTP header field name"),
        ("tab before colon", b"Bad\t: value", b"invalid RESPMOD encapsulated HTTP header field name"),
        ("invalid token", b"Bad/Name: value", b"invalid RESPMOD encapsulated HTTP header field name"),
        ("non-ASCII name", b"Bad-\xff: value", b"invalid RESPMOD encapsulated HTTP header field name"),
        ("obs-fold", b" folded: value", b"obsolete folded RESPMOD encapsulated HTTP header line"),
        ("NUL value", b"X-Value: ok\x00bad", b"invalid RESPMOD encapsulated HTTP header field value"),
        ("control value", b"X-Value: ok\x1fbad", b"invalid RESPMOD encapsulated HTTP header field value"),
        ("DEL value", b"X-Value: ok\x7fbad", b"invalid RESPMOD encapsulated HTTP header field value"),
    )

    for name, field_line, expected_error in cases:
        for path_name, allow_204, body in (
            ("204", True, None),
            ("replay", False, b"hello"),
        ):
            http_header = b"HTTP/1.1 200 OK\r\n" + field_line + b"\r\n\r\n"
            response = _placeholder_raw_exchange(
                runner,
                _respmod_request_for_response(
                    http_header,
                    allow_204=allow_204,
                    body=body,
                ),
            )

            label = f"{name} {path_name}"
            assert response.startswith(b"ICAP/1.0 200 OK\r\n"), label
            assert b"HTTP/1.1 502 Bad Gateway" in response, label
            assert expected_error in response, label
            assert not response.startswith(b"ICAP/1.0 204 No Content\r\n"), label
            assert b"5\r\nhello\r\n0\r\n\r\n" not in response, label


def test_fail_open_placeholder_rejects_ambiguous_respmod_http_framing_before_replay() -> None:
    runner = _load_runner()
    long_content_length = b"9" * (runner.MAX_HTTP_CONTENT_LENGTH_DIGITS + 1)
    cases = (
        (
            "conflicting duplicate content-length",
            b"Content-Length: 5\r\nContent-Length: 6",
            b"conflicting RESPMOD encapsulated HTTP Content-Length headers",
        ),
        (
            "signed content-length",
            b"Content-Length: +5",
            b"invalid RESPMOD encapsulated HTTP Content-Length header",
        ),
        (
            "unicode content-length",
            b"Content-Length: \xff",
            b"invalid RESPMOD encapsulated HTTP Content-Length header",
        ),
        (
            "huge content-length",
            b"Content-Length: " + long_content_length,
            b"invalid RESPMOD encapsulated HTTP Content-Length header",
        ),
        (
            "declared length mismatch",
            b"Content-Length: 6",
            b"RESPMOD encapsulated HTTP Content-Length mismatches decoded body",
        ),
        (
            "content-length plus transfer-encoding",
            b"Content-Length: 5\r\nTransfer-Encoding: chunked",
            b"ambiguous RESPMOD encapsulated HTTP Content-Length with Transfer-Encoding",
        ),
        (
            "duplicate transfer-encoding",
            b"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked",
            b"duplicate RESPMOD encapsulated HTTP Transfer-Encoding header",
        ),
        (
            "transfer-encoding chunked not final",
            b"Transfer-Encoding: chunked, gzip",
            b"unsupported RESPMOD encapsulated HTTP Transfer-Encoding header",
        ),
        (
            "duplicate chunked transfer-coding",
            b"Transfer-Encoding: chunked, chunked",
            b"duplicate RESPMOD encapsulated HTTP chunked transfer-coding",
        ),
        (
            "non-chunked transfer-encoding",
            b"Transfer-Encoding: gzip",
            b"unsupported RESPMOD encapsulated HTTP Transfer-Encoding header",
        ),
    )

    for name, fields, expected_error in cases:
        http_header = b"HTTP/1.1 200 OK\r\n" + fields + b"\r\n\r\n"
        response = _placeholder_raw_exchange(
            runner,
            _respmod_request_for_response(http_header, body=b"hello"),
        )

        assert response.startswith(b"ICAP/1.0 200 OK\r\n"), name
        assert b"HTTP/1.1 502 Bad Gateway" in response, name
        assert expected_error in response, name
        assert b"5\r\nhello\r\n0\r\n\r\n" not in response, name


def test_fail_open_placeholder_preserves_valid_respmod_http_fields_and_framing() -> None:
    runner = _load_runner()
    cases = (
        (
            "unknown fields with OWS and obs-text value",
            (
                b"HTTP/1.1 200 OK\r\n"
                b"X_Token-Name!#$%&'*+-.^_`|~09AZaz: \t ok \t\r\n"
                b"X-Obs-Text: caf\xe9\r\n"
                b"Content-Length: 5\r\n\r\n"
            ),
            False,
            b"hello",
            (
                b"X_Token-Name!#$%&'*+-.^_`|~09AZaz: \t ok \t",
                b"X-Obs-Text: caf\xe9",
            ),
        ),
        (
            "duplicate matching content-length is normalized",
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\ncontent-length: 5\r\n\r\n",
            False,
            b"hello",
            (b"Content-Length: 5\r\n",),
        ),
        (
            "valid chunked transfer-encoding is normalized to content-length",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
            False,
            b"hello",
            (b"Content-Length: 5\r\n",),
        ),
        (
            "304 content-length metadata is preserved without body inference",
            b"HTTP/1.1 304 Not Modified\r\nContent-Length: 12345\r\nETag: \"abc\"\r\n\r\n",
            False,
            None,
            (b"HTTP/1.1 304 Not Modified", b"Content-Length: 12345", b"ETag: \"abc\""),
        ),
        (
            "null-body 200 content-length may be HEAD without request metadata",
            b"HTTP/1.1 200 OK\r\nContent-Length: 12345\r\n\r\n",
            False,
            None,
            (b"HTTP/1.1 200 OK", b"Content-Length: 12345"),
        ),
    )

    for name, http_header, allow_204, body, expected_values in cases:
        response = _placeholder_raw_exchange(
            runner,
            _respmod_request_for_response(
                http_header,
                allow_204=allow_204,
                body=body,
            ),
        )

        assert b"HTTP/1.1 502 Bad Gateway" not in response, name
        for expected in expected_values:
            assert expected in response, name
        if body is not None:
            assert b"5\r\nhello\r\n0\r\n\r\n" in response, name


def test_fail_open_placeholder_rejects_duplicate_outer_encapsulated_header() -> None:
    response_header = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"
    request = (
        b"RESPMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Allow: 204\r\n"
        b"Encapsulated: res-hdr=999, null-body=999\r\n"
        + f"eNcApSuLaTeD: res-hdr=0, res-body={len(response_header)}".encode(
            "ascii"
        )
        + b"\r\n\r\n"
        + response_header
        + b"5\r\nhello\r\n0\r\n\r\n"
    )

    response = _placeholder_raw_exchange(_load_runner(), request)

    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"duplicate ICAP Encapsulated header" in response
    assert b"5\r\nhello\r\n0\r\n\r\n" not in response


def test_fail_open_placeholder_rejects_duplicate_outer_allow_header() -> None:
    response_header = b"HTTP/1.1 204 No Content\r\nCache-Control: no-store\r\n\r\n"
    request = (
        b"RESPMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Allow: 206\r\n"
        b"aLlOw: 204\r\n"
        + f"Encapsulated: res-hdr=0, null-body={len(response_header)}".encode(
            "ascii"
        )
        + b"\r\n\r\n"
        + response_header
    )

    response = _placeholder_raw_exchange(_load_runner(), request)

    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"duplicate ICAP Allow header" in response
    assert not response.startswith(b"ICAP/1.0 204 No Content\r\n")
    assert b"HTTP/1.1 204 No Content" not in response


def test_fail_open_placeholder_rejects_duplicate_outer_preview_header() -> None:
    http_header = (
        b"POST /upload HTTP/1.1\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
    )
    request = (
        b"REQMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Allow: 204\r\n"
        b"Preview: 0\r\n"
        b"pReViEw: 4\r\n"
        + f"Encapsulated: req-hdr=0, req-body={len(http_header)}".encode("ascii")
        + b"\r\n\r\n"
        + http_header
        + b"4\r\ntest\r\n0\r\n\r\n"
    )

    response = _placeholder_raw_exchange(_load_runner(), request)

    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"duplicate ICAP Preview header" in response
    assert not response.startswith(b"ICAP/1.0 100 Continue\r\n")
    assert b"test" not in response


def test_fail_open_placeholder_rejects_malformed_outer_header_metadata() -> None:
    runner = _load_runner()
    response_header = b"HTTP/1.1 204 No Content\r\nCache-Control: no-store\r\n\r\n"
    response_body_header = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"
    request_header = (
        b"POST /upload HTTP/1.1\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
    )
    cases = (
        (
            "malformed Allow lookalike cannot enable 204",
            b"RESPMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Allow : 204\r\n"
            + f"Encapsulated: res-hdr=0, null-body={len(response_header)}".encode(
                "ascii"
            )
            + b"\r\n\r\n"
            + response_header,
            b"invalid ICAP header field name",
            (b"ICAP/1.0 204 No Content\r\n",),
        ),
        (
            "malformed Encapsulated lookalike cannot reach clean replay",
            b"RESPMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Allow: 204\r\n"
            + f"Encapsulated : res-hdr=0, res-body={len(response_body_header)}".encode(
                "ascii"
            )
            + b"\r\n\r\n"
            + response_body_header
            + b"5\r\nhello\r\n0\r\n\r\n",
            b"invalid ICAP header field name",
            (b"5\r\nhello\r\n0\r\n\r\n",),
        ),
        (
            "malformed Preview lookalike cannot trigger preview continue",
            b"REQMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Allow: 204\r\n"
            b"Preview : 4\r\n"
            + f"Encapsulated: req-hdr=0, req-body={len(request_header)}".encode(
                "ascii"
            )
            + b"\r\n\r\n"
            + request_header
            + b"4\r\ntest\r\n0\r\n\r\n",
            b"invalid ICAP header field name",
            (b"ICAP/1.0 100 Continue\r\n", b"ICAP/1.0 204 No Content\r\n"),
        ),
    )

    for name, request, expected_error, forbidden in cases:
        response = _placeholder_raw_exchange(runner, request)

        assert response.startswith(b"ICAP/1.0 200 OK\r\n"), name
        assert b"HTTP/1.1 502 Bad Gateway" in response, name
        assert expected_error in response, name
        for forbidden_bytes in forbidden:
            assert forbidden_bytes not in response, name


def _placeholder_preview_exchange(
    runner, *, method: str
) -> tuple[bytes, bytes, bytes]:
    with runner._FailOpenAvServer(
        ("127.0.0.1", 0), runner._FailOpenAvHandler
    ) as server:
        server.fail_open = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        http_header = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
        )
        header_section = "req-hdr" if method == "REQMOD" else "res-hdr"
        encapsulated = "req-body" if method == "REQMOD" else "res-body"
        request_prefix = (
            (
                f"{method} icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
                "Host: 127.0.0.1\r\n"
                "Allow: 204\r\n"
                "Preview: 4\r\n"
                f"Encapsulated: {header_section}=0, "
                f"{encapsulated}={len(http_header)}\r\n\r\n"
            ).encode("ascii")
            + http_header
        )
        preview = b"4\r\ntest\r\n0\r\n\r\n"
        remainder = b"5\r\n-rest\r\n0\r\n\r\n"
        with socket.create_connection(("127.0.0.1", port), timeout=1) as sock:
            sock.settimeout(1)
            sock.sendall(request_prefix + preview)
            interim = sock.recv(4096)
            sock.sendall(remainder)
            final = sock.recv(4096)
            extra = sock.recv(4096)
        server.shutdown()
        thread.join(timeout=1)
    return interim, final, extra


def test_fail_open_placeholder_continues_reqmod_preview_before_204() -> None:
    runner = _load_runner()

    interim, final, extra = _placeholder_preview_exchange(runner, method="REQMOD")

    assert interim == b"ICAP/1.0 100 Continue\r\n\r\n"
    assert final.startswith(b"ICAP/1.0 204 No Content\r\n")
    assert extra == b""


def test_fail_open_placeholder_continues_respmod_preview_before_204() -> None:
    runner = _load_runner()

    interim, final, extra = _placeholder_preview_exchange(runner, method="RESPMOD")

    assert interim == b"ICAP/1.0 100 Continue\r\n\r\n"
    assert final.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"9\r\ntest-rest\r\n0\r\n\r\n" in final
    assert extra == b""


def test_fail_open_placeholder_respmod_null_body_with_req_hdr_is_valid() -> None:
    runner = _load_runner()

    with runner._FailOpenAvServer(
        ("127.0.0.1", 0), runner._FailOpenAvHandler
    ) as server:
        server.fail_open = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        request_header = b"GET /generate_204 HTTP/1.1\r\nHost: example.test\r\n\r\n"
        response_header = b"HTTP/1.1 204 No Content\r\nCache-Control: no-store\r\n\r\n"
        response_offset = len(request_header)
        null_offset = response_offset + len(response_header)
        request = (
            (
                f"RESPMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
                "Host: 127.0.0.1\r\n"
                "Encapsulated: "
                f"req-hdr=0, res-hdr={response_offset}, null-body={null_offset}"
                "\r\n\r\n"
            ).encode("ascii")
            + request_header
            + response_header
        )
        with socket.create_connection(("127.0.0.1", port), timeout=1) as sock:
            sock.settimeout(1)
            sock.sendall(request)
            response = sock.recv(4096)
        server.shutdown()
        thread.join(timeout=1)

    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"Encapsulated: res-hdr=0, null-body=" in response
    assert b"HTTP/1.1 204 No Content" in response
    assert b"GET /generate_204 HTTP/1.1" not in response


def test_fail_open_placeholder_rejects_duplicate_encapsulated_section() -> None:
    runner = _load_runner()

    with runner._FailOpenAvServer(
        ("127.0.0.1", 0), runner._FailOpenAvHandler
    ) as server:
        server.fail_open = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        response_header = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"
        request = (
            (
                f"RESPMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
                "Host: 127.0.0.1\r\n"
                "Allow: 204\r\n"
                "Encapsulated: res-hdr=999, res-hdr=0, "
                f"res-body={len(response_header)}"
                "\r\n\r\n"
            ).encode("ascii")
            + response_header
            + b"5\r\nhello\r\n0\r\n\r\n"
        )
        with socket.create_connection(("127.0.0.1", port), timeout=1) as sock:
            sock.settimeout(1)
            sock.sendall(request)
            response = sock.recv(4096)
        server.shutdown()
        thread.join(timeout=1)

    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" in response
    assert b"duplicate Encapsulated section name: res-hdr" in response
    assert b"hello" not in response


def test_fail_open_placeholder_rejects_invalid_respmod_encapsulated_matrix() -> None:
    runner = _load_runner()
    response_header = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"
    body = b"5\r\nhello\r\n0\r\n\r\n"
    valid_request_header = b"GET /download HTTP/1.1\r\nHost: example.test\r\n\r\n"
    valid_request_offset = len(valid_request_header)
    valid_body_offset = len(response_header)
    cases = (
        (
            "negative res-hdr",
            b"Encapsulated: res-hdr=-1, res-body="
            + str(valid_body_offset).encode("ascii")
            + b"\r\n\r\n"
            + response_header
            + body,
            False,
        ),
        (
            "decreasing req/res offsets",
            b"Encapsulated: req-hdr=0, res-hdr=1, res-body="
            + str(valid_body_offset).encode("ascii")
            + b"\r\n\r\n"
            + response_header
            + body,
            False,
        ),
        (
            "overlapping response body",
            b"Encapsulated: res-hdr=0, res-body=5\r\n\r\n"
            + response_header
            + body,
            False,
        ),
        (
            "equal response/body offsets",
            b"Encapsulated: res-hdr=0, res-body=0\r\n\r\n"
            + response_header
            + body,
            False,
        ),
        (
            "body before header",
            b"Encapsulated: res-body=0, res-hdr="
            + str(valid_body_offset).encode("ascii")
            + b"\r\n\r\n"
            + response_header
            + body,
            False,
        ),
        (
            "terminal offset past available bytes",
            b"Encapsulated: res-hdr=0, null-body="
            + str(valid_body_offset + 1).encode("ascii")
            + b"\r\n\r\n"
            + response_header,
            True,
        ),
        (
            "terminal offset past header bound",
            b"Encapsulated: res-hdr=0, res-body="
            + str(runner.DEFAULT_MAX_HEADER_BYTES + 1).encode("ascii")
            + b"\r\n\r\n",
            False,
        ),
        (
            "unknown section",
            b"Encapsulated: res-hdr=0, x-body=1, null-body="
            + str(valid_body_offset).encode("ascii")
            + b"\r\n\r\n"
            + response_header,
            False,
        ),
        (
            "unsupported req-body",
            b"Encapsulated: res-hdr=0, req-body="
            + str(valid_body_offset).encode("ascii")
            + b"\r\n\r\n"
            + response_header
            + body,
            False,
        ),
        (
            "res-body with null-body",
            b"Encapsulated: res-hdr=0, res-body="
            + str(valid_body_offset).encode("ascii")
            + b", null-body="
            + str(valid_body_offset).encode("ascii")
            + b"\r\n\r\n"
            + response_header
            + body,
            False,
        ),
        (
            "null-body before res-hdr",
            b"Encapsulated: req-hdr=0, res-hdr="
            + str(valid_request_offset).encode("ascii")
            + b", null-body=1\r\n\r\n"
            + valid_request_header
            + response_header,
            False,
        ),
    )

    for name, encapsulated_payload, shutdown_write in cases:
        request = (
            b"RESPMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Allow: 204\r\n"
            + encapsulated_payload
        )

        response = _placeholder_raw_exchange(
            runner, request, shutdown_write=shutdown_write
        )

        assert response.startswith(b"ICAP/1.0 200 OK\r\n"), name
        assert b"HTTP/1.1 502 Bad Gateway" in response, name
        assert b"hello" not in response, name


def test_fail_open_placeholder_rejects_invalid_reqmod_encapsulated_matrix() -> None:
    runner = _load_runner()
    request_header = b"POST /upload HTTP/1.1\r\nHost: example.test\r\n\r\n"
    body = b"5\r\nhello\r\n0\r\n\r\n"
    valid_body_offset = len(request_header)
    cases = (
        (
            "missing encapsulated",
            b"Allow: 204\r\n\r\n" + request_header + body,
            False,
        ),
        (
            "empty encapsulated",
            b"Encapsulated: \r\n\r\n" + request_header + body,
            False,
        ),
        (
            "negative req-hdr",
            b"Encapsulated: req-hdr=-1, req-body="
            + str(valid_body_offset).encode("ascii")
            + b"\r\n\r\n"
            + request_header
            + body,
            False,
        ),
        (
            "decreasing req-body",
            b"Encapsulated: req-hdr=0, req-body=1\r\n\r\n"
            + request_header
            + body,
            False,
        ),
        (
            "equal req offsets",
            b"Encapsulated: req-hdr=0, req-body=0\r\n\r\n"
            + request_header
            + body,
            False,
        ),
        (
            "oversized header offset",
            b"Encapsulated: req-hdr=0, req-body="
            + str(runner.DEFAULT_MAX_HEADER_BYTES + 1).encode("ascii")
            + b"\r\n\r\n",
            False,
        ),
        (
            "truncated req-hdr null-body",
            b"Encapsulated: req-hdr=0, null-body="
            + str(valid_body_offset).encode("ascii")
            + b"\r\n\r\n"
            + request_header[:-1],
            True,
        ),
        (
            "unsupported res-hdr",
            b"Encapsulated: req-hdr=0, res-hdr="
            + str(valid_body_offset).encode("ascii")
            + b"\r\n\r\n"
            + request_header,
            False,
        ),
        (
            "unsupported res-body",
            b"Encapsulated: req-hdr=0, res-body="
            + str(valid_body_offset).encode("ascii")
            + b"\r\n\r\n"
            + request_header
            + body,
            False,
        ),
        (
            "unknown section",
            b"Encapsulated: req-hdr=0, x-body=1, req-body="
            + str(valid_body_offset).encode("ascii")
            + b"\r\n\r\n"
            + request_header
            + body,
            False,
        ),
        (
            "req-body with null-body",
            b"Encapsulated: req-hdr=0, req-body="
            + str(valid_body_offset).encode("ascii")
            + b", null-body="
            + str(valid_body_offset).encode("ascii")
            + b"\r\n\r\n"
            + request_header
            + body,
            False,
        ),
        (
            "header boundary not ending crlfcrlf",
            b"Encapsulated: req-hdr=0, req-body="
            + str(valid_body_offset).encode("ascii")
            + b"\r\n\r\n"
            + request_header[:-1]
            + b"X"
            + body,
            False,
        ),
    )

    for name, encapsulated_payload, shutdown_write in cases:
        request = (
            b"REQMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Allow: 204\r\n"
            + encapsulated_payload
        )

        response = _placeholder_raw_exchange(
            runner, request, shutdown_write=shutdown_write
        )

        assert response.startswith(b"ICAP/1.0 200 OK\r\n"), name
        assert b"HTTP/1.1 502 Bad Gateway" in response, name
        assert b"hello" not in response, name
        assert not response.startswith(b"ICAP/1.0 204 No Content\r\n"), name


def test_fail_open_placeholder_preserves_valid_reqmod_offset_layouts() -> None:
    runner = _load_runner()
    request_header = b"POST /upload HTTP/1.1\r\nHost: example.test\r\n\r\n"
    body = b"5\r\nhello\r\n0\r\n\r\n"
    body_offset = len(request_header)

    req_body_request = (
        b"REQMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Allow: 204\r\n"
        b"Encapsulated: req-hdr=0, req-body="
        + str(body_offset).encode("ascii")
        + b"\r\n\r\n"
        + request_header
        + body
    )
    null_body_request = (
        b"REQMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Allow: 204\r\n"
        b"Encapsulated: req-hdr=0, null-body="
        + str(body_offset).encode("ascii")
        + b"\r\n\r\n"
        + request_header
    )

    for name, request in (
        ("req-hdr+req-body", req_body_request),
        ("req-hdr+null-body", null_body_request),
    ):
        response = _placeholder_raw_exchange(runner, request)

        assert response.startswith(b"ICAP/1.0 204 No Content\r\n"), name
        assert b"HTTP/1.1 502 Bad Gateway" not in response, name


def test_fail_open_placeholder_preserves_valid_respmod_offset_layouts() -> None:
    runner = _load_runner()
    request_header = b"GET /download HTTP/1.1\r\nHost: example.test\r\n\r\n"
    response_header = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"
    body = b"5\r\nhello\r\n0\r\n\r\n"
    response_offset = len(request_header)
    body_offset = response_offset + len(response_header)
    request = (
        b"RESPMOD icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Encapsulated: req-hdr=0, res-hdr="
        + str(response_offset).encode("ascii")
        + b", res-body="
        + str(body_offset).encode("ascii")
        + b"\r\n\r\n"
        + request_header
        + response_header
        + body
    )

    response = _placeholder_raw_exchange(runner, request)

    assert response.startswith(b"ICAP/1.0 200 OK\r\n")
    assert b"HTTP/1.1 502 Bad Gateway" not in response
    assert b"HTTP/1.1 200 OK" in response
    assert b"GET /download HTTP/1.1" not in response
    assert b"Content-Length: 5\r\n" in response
    assert b"5\r\nhello\r\n0\r\n\r\n" in response
