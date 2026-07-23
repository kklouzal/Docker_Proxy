from __future__ import annotations

import json
import socket
import socketserver
import threading
import time
from pathlib import Path

import pytest

ResponsePayload = bytes | list[bytes]


def _add_repo_paths() -> None:
    import sys

    repo_root = Path(__file__).resolve().parents[2]
    for path in (repo_root, repo_root / "docker"):
        path_str = str(path)
        if path_str not in sys.path:
            sys.path.insert(0, path_str)


class _IcapHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.server.calls += 1
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = self.request.recv(512)
            if not chunk:
                break
            data += chunk
        if self.server.responses:
            response = self.server.responses[min(self.server.calls, len(self.server.responses)) - 1]
        elif self.server.ready_after_calls and self.server.calls < self.server.ready_after_calls:
            response = b"ICAP/1.0 503 Service Unavailable\r\nConnection: close\r\n\r\n"
        else:
            response = (
                b"ICAP/1.0 200 OK\r\n"
                + f"Methods: {self.server.methods}\r\n".encode("ascii")
                + b"Connection: close\r\nEncapsulated: null-body=0\r\n\r\n"
            )
        if isinstance(response, list):
            for chunk in response:
                self.request.sendall(chunk)
                time.sleep(0.001)
        else:
            self.request.sendall(response)


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        methods: str = "REQMOD",
        ready_after_calls: int = 0,
        responses: list[ResponsePayload] | None = None,
    ) -> None:
        self.calls = 0
        self.methods = methods
        self.ready_after_calls = ready_after_calls
        self.responses = responses or []
        super().__init__(("127.0.0.1", 0), _IcapHandler)


def _start_server(
    methods: str = "REQMOD",
    ready_after_calls: int = 0,
    responses: list[ResponsePayload] | None = None,
):
    server = _Server(methods=methods, ready_after_calls=ready_after_calls, responses=responses)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _service(port: int):
    _add_repo_paths()
    import icap_readiness  # type: ignore

    return icap_readiness.IcapService(
        name="adblock_req",
        method="REQMOD",
        url=f"icap://127.0.0.1:{port}/adblockreq",
        host="127.0.0.1",
        port=port,
        path="/adblockreq",
        bypass=False,
    )


def _probe_response(response: ResponsePayload):
    _add_repo_paths()
    import icap_readiness  # type: ignore

    server = _start_server(responses=[response])
    try:
        return icap_readiness.probe_service(_service(server.server_address[1]), timeout=0.5)
    finally:
        server.shutdown()
        server.server_close()


def test_icap_readiness_requires_options_method_match(tmp_path) -> None:
    _add_repo_paths()
    import icap_readiness  # type: ignore

    server = _start_server(methods="RESPMOD")
    try:
        config = tmp_path / "20-icap.conf"
        config.write_text(
            f"icap_service adblock_req reqmod_precache icap://127.0.0.1:{server.server_address[1]}/adblockreq bypass=on\n",
            encoding="utf-8",
        )

        ok, detail, payload = icap_readiness.check_once([str(config)], probe_timeout=0.5)

        assert ok is False
        assert "does not include REQMOD" in detail
        assert payload["services"][0]["bypass"] is True
    finally:
        server.shutdown()
        server.server_close()


def test_icap_readiness_accepts_strict_options_200_status() -> None:
    result = _probe_response(
        b"ICAP/1.0 200 OK\r\n"
        b"Methods: REQMOD\r\n"
        b"Connection: close\r\n"
        b"Encapsulated: null-body=0\r\n\r\n",
    )

    assert result.ok is True
    assert result.status_line == "ICAP/1.0 200 OK"
    assert result.methods == "REQMOD"


def test_icap_readiness_accepts_fragmented_strict_options_200_status() -> None:
    result = _probe_response(
        [
            b"ICAP/1.0 ",
            b"200 OK\r\nMeth",
            b"ods: REQMOD\r\nConnection: close\r\n",
            b"Encapsulated: null-body=0\r\n\r\n",
        ],
    )

    assert result.ok is True
    assert result.status_line == "ICAP/1.0 200 OK"
    assert result.methods == "REQMOD"


def test_icap_readiness_rejects_status_prefix_confusion() -> None:
    for status_line in (b"ICAP/1.0 2000 Weird", b"ICAP/1.0 200X Weird", b"ICAP/1.0 200OK"):
        result = _probe_response(status_line + b"\r\nMethods: REQMOD\r\n\r\n")

        assert result.ok is False
        assert result.status_line == status_line.decode("ascii")
        assert "malformed ICAP status line" in result.detail


def test_icap_readiness_rejects_non_strict_status_lines() -> None:
    cases = (
        b"ICAP/1.0 200",
        b"ICAP/1.0 200\tOK",
        b" ICAP/1.0 200 OK",
        b"ICAP/1.1 200 OK",
    )
    for status_line in cases:
        result = _probe_response(status_line + b"\r\nMethods: REQMOD\r\n\r\n")

        assert result.ok is False
        assert "malformed ICAP status line" in result.detail


def test_icap_readiness_rejects_duplicate_interim_response() -> None:
    result = _probe_response(
        b"ICAP/1.0 100 Continue\r\n\r\n"
        b"ICAP/1.0 200 OK\r\nMethods: REQMOD\r\n\r\n",
    )

    assert result.ok is False
    assert result.status_line == "ICAP/1.0 100 Continue"


def test_icap_readiness_rejects_incomplete_or_oversized_headers() -> None:
    cases = (
        b"ICAP/1.0 200 OK",
        b"ICAP/1.0 200 OK\r\nMethods: REQMOD\r\n" + (b"X-Test: value\r\n" * 600),
    )
    for response in cases:
        result = _probe_response(response)

        assert result.ok is False
        assert result.detail == "incomplete ICAP response headers"


def test_icap_readiness_rejects_malformed_headers() -> None:
    cases = (
        b"ICAP/1.0 200 OK\nMethods: REQMOD\n\n",
        b"ICAP/1.0 200 OK\r\nBad Header: value\r\n\r\n",
        b"ICAP/1.0 200 OK\r\nMethods: REQMOD\r\nMethods: RESPMOD\r\n\r\n",
        b"ICAP/1.0 200 OK\r\nX-Test: bad\x01value\r\n\r\n",
    )
    for response in cases:
        result = _probe_response(response)

        assert result.ok is False


def test_icap_readiness_waits_until_options_ready(tmp_path, monkeypatch) -> None:
    _add_repo_paths()
    import icap_readiness  # type: ignore

    server = _start_server(methods="REQMOD", ready_after_calls=3)
    sleeps: list[float] = []
    monkeypatch.setattr(icap_readiness.time, "sleep", sleeps.append)
    try:
        config = tmp_path / "20-icap.conf"
        status_file = tmp_path / "status.json"
        config.write_text(
            f"icap_service adblock_req reqmod_precache icap://127.0.0.1:{server.server_address[1]}/adblockreq bypass=on\n",
            encoding="utf-8",
        )

        ok, detail = icap_readiness.wait_ready(
            [str(config)],
            timeout=3.0,
            probe_timeout=0.5,
            interval=0.1,
            status_file=str(status_file),
        )

        assert ok is True
        assert "All configured ICAP services" in detail
        assert server.calls == 3
        assert sleeps == [0.1, 0.1]
        assert '"ok": true' in status_file.read_text(encoding="utf-8")
    finally:
        server.shutdown()
        server.server_close()


def test_icap_readiness_cli_ignores_malformed_numeric_env_defaults(
    tmp_path, monkeypatch, capsys
) -> None:
    _add_repo_paths()
    import icap_readiness  # type: ignore

    config = tmp_path / "20-icap.conf"
    config.write_text("", encoding="utf-8")
    status_file = tmp_path / "status.json"
    monkeypatch.setenv("SQUID_ICAP_READY_PROBE_TIMEOUT_SECONDS", "bogus")
    monkeypatch.setenv("SQUID_ICAP_READY_TIMEOUT_SECONDS", "also-bogus")
    monkeypatch.setenv("SQUID_ICAP_READY_INTERVAL_SECONDS", "nan")

    assert (
        icap_readiness.main(
            [
                "wait",
                "--config",
                str(config),
                "--status-file",
                str(status_file),
                "--json",
            ]
        )
        == 0
    )

    assert json.loads(capsys.readouterr().out) == {
        "detail": "No ICAP services are configured.",
        "ok": True,
        "services": [],
    }
    assert json.loads(status_file.read_text(encoding="utf-8"))[
        "timeout_seconds"
    ] == pytest.approx(75.0)


def test_icap_readiness_cli_rejects_non_finite_numeric_flags(capsys) -> None:
    _add_repo_paths()
    import icap_readiness  # type: ignore

    try:
        icap_readiness.main(["check", "--probe-timeout", "inf"])
    except SystemExit as exc:
        assert exc.code == 2
    else:  # pragma: no cover - argparse should exit for invalid values
        msg = "expected argparse to reject non-finite timeout"
        raise AssertionError(msg)

    captured = capsys.readouterr()
    assert "argument --probe-timeout: must be a finite number" in captured.err


def test_cicap_av_runner_optional_fallback_answers_options(tmp_path, monkeypatch) -> None:
    _add_repo_paths()
    import docker.cicap_av_runner as runner  # type: ignore

    conf = tmp_path / "c-icap-av.conf"
    conf.write_text("Port 127.0.0.1:0\n", encoding="utf-8")
    # Bind a real ephemeral socket first so we can write the selected port into the c-icap config.
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    conf.write_text(f"Port 127.0.0.1:{port}\n", encoding="utf-8")

    thread = threading.Thread(
        target=runner.run_fail_open_placeholder,
        kwargs={"conf_path": str(conf), "host": "clamd", "port": 3310},
        daemon=True,
    )
    thread.start()
    deadline = time.time() + 2.0
    response = b""
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2) as client:
                client.sendall(
                    f"OPTIONS icap://127.0.0.1:{port}/avrespmod ICAP/1.0\r\nHost: 127.0.0.1\r\nEncapsulated: null-body=0\r\n\r\n".encode()
                )
                response = client.recv(512)
                break
        except OSError:
            time.sleep(0.01)

    assert response.startswith(b"ICAP/1.0 200 OK")
    assert b"Methods: REQMOD, RESPMOD" in response
