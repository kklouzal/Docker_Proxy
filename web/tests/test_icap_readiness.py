from __future__ import annotations

import json
import socket
import socketserver
import threading
import time
from pathlib import Path

import pytest

ResponsePayload = bytes | list[bytes]


class _IcapHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.server.calls += 1
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = self.request.recv(512)
            if not chunk:
                break
            data += chunk
        self.server.requests.append(data)
        if self.server.responses:
            response = self.server.responses[
                min(self.server.calls, len(self.server.responses)) - 1
            ]
        elif (
            self.server.ready_after_calls
            and self.server.calls < self.server.ready_after_calls
        ):
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
        self.requests: list[bytes] = []
        self.methods = methods
        self.ready_after_calls = ready_after_calls
        self.responses = responses or []
        super().__init__(("127.0.0.1", 0), _IcapHandler)


def _start_server(
    methods: str = "REQMOD",
    ready_after_calls: int = 0,
    responses: list[ResponsePayload] | None = None,
):
    server = _Server(
        methods=methods, ready_after_calls=ready_after_calls, responses=responses
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _service(port: int):
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
    import icap_readiness  # type: ignore

    server = _start_server(responses=[response])
    try:
        return icap_readiness.probe_service(
            _service(server.server_address[1]), timeout=0.5
        )
    finally:
        server.shutdown()
        server.server_close()


def test_icap_readiness_requires_options_method_match(tmp_path) -> None:
    import icap_readiness  # type: ignore

    server = _start_server(methods="RESPMOD")
    try:
        config = tmp_path / "20-icap.conf"
        config.write_text(
            f"icap_service adblock_req reqmod_precache icap://127.0.0.1:{server.server_address[1]}/adblockreq bypass=on\n",
            encoding="utf-8",
        )

        ok, detail, payload = icap_readiness.check_once(
            [str(config)], probe_timeout=0.5
        )

        assert ok is True
        assert "optional ICAP services are degraded (fail-open)" in detail
        assert payload["degraded"] is True
        assert payload["blocking_failure_count"] == 0
        assert payload["optional_failure_count"] == 1
        assert payload["services"][0]["bypass"] is True
        assert payload["services"][0]["required"] is False
        assert payload["services"][0]["ok"] is False
        assert "does not include REQMOD" in payload["services"][0]["detail"]
    finally:
        server.shutdown()
        server.server_close()


def test_icap_readiness_required_failure_blocks_with_optional_degradation(
    tmp_path,
) -> None:
    import icap_readiness  # type: ignore

    config = tmp_path / "20-icap.conf"
    config.write_text(
        "icap_service optional_req reqmod_precache icap://127.0.0.1:1/optional bypass=on\n"
        "icap_service required_resp respmod_precache icap://127.0.0.1:2/required bypass=off\n",
        encoding="utf-8",
    )

    ok, detail, payload = icap_readiness.check_once([str(config)], probe_timeout=0.1)

    assert ok is False
    assert payload["ok"] is False
    assert payload["degraded"] is True
    assert payload["blocking_failure_count"] == 1
    assert payload["optional_failure_count"] == 1
    assert "Required ICAP services are not OPTIONS-ready" in detail
    assert "optional ICAP services also degraded" in detail
    assert [service["required"] for service in payload["services"]] == [False, True]
    assert [service["ok"] for service in payload["services"]] == [False, False]


def test_icap_readiness_skips_malformed_icap_service_ports(tmp_path) -> None:
    import icap_readiness  # type: ignore

    config = tmp_path / "20-icap.conf"
    config.write_text(
        "icap_service good_req reqmod_precache icap://127.0.0.1:1344/adblockreq bypass=on\n"
        "icap_service bad_text reqmod_precache icap://127.0.0.1:notaport/adblockreq bypass=on\n"
        "icap_service bad_range reqmod_precache icap://127.0.0.1:70000/adblockreq bypass=on\n"
        "icap_service bad_empty reqmod_precache icap://127.0.0.1:/adblockreq bypass=on",
        encoding="utf-8",
    )

    services = icap_readiness.parse_services([str(config)])

    assert [(service.name, service.port, service.path) for service in services] == [
        ("good_req", 1344, "/adblockreq")
    ]


def test_icap_readiness_preserves_query_and_rejects_fragmented_service_url(
    tmp_path,
) -> None:
    import icap_readiness  # type: ignore

    config = tmp_path / "20-icap.conf"
    config.write_text(
        "icap_service query_req reqmod_precache "
        "icap://127.0.0.1:1344/adblockreq?profile=edge bypass=on\n"
        "icap_service fragment_req reqmod_precache "
        "icap://127.0.0.1:1345/adblockreq#ignored bypass=on\n",
        encoding="utf-8",
    )

    services = icap_readiness.parse_services([str(config)])

    assert [(service.name, service.path) for service in services] == [
        ("query_req", "/adblockreq?profile=edge")
    ]


def test_icap_readiness_options_request_uses_authority_host_header(tmp_path) -> None:
    import icap_readiness  # type: ignore

    server = _start_server(methods="REQMOD")
    try:
        config = tmp_path / "20-icap.conf"
        config.write_text(
            f"icap_service adblock_req reqmod_precache icap://127.0.0.1:{server.server_address[1]}/adblockreq bypass=off\n",
            encoding="utf-8",
        )

        ok, _detail, _payload = icap_readiness.check_once(
            [str(config)], probe_timeout=0.5
        )

        assert ok is True
        request = server.requests[0]
        authority = f"127.0.0.1:{server.server_address[1]}".encode("ascii")
        assert request.startswith(b"OPTIONS icap://" + authority + b"/adblockreq ")
        assert b"\r\nHost: " + authority + b"\r\n" in request
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
    for status_line in (
        b"ICAP/1.0 2000 Weird",
        b"ICAP/1.0 200X Weird",
        b"ICAP/1.0 200OK",
    ):
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
        b"ICAP/1.0 100 Continue\r\n\r\nICAP/1.0 200 OK\r\nMethods: REQMOD\r\n\r\n",
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
    import icap_readiness  # type: ignore

    server = _start_server(methods="REQMOD", ready_after_calls=3)
    sleeps: list[float] = []
    monkeypatch.setattr(icap_readiness.time, "sleep", sleeps.append)
    try:
        config = tmp_path / "20-icap.conf"
        status_file = tmp_path / "status.json"
        config.write_text(
            f"icap_service adblock_req reqmod_precache icap://127.0.0.1:{server.server_address[1]}/adblockreq bypass=off\n",
            encoding="utf-8",
        )

        ok, detail, payload = icap_readiness.wait_ready(
            [str(config)],
            timeout=3.0,
            probe_timeout=0.5,
            interval=0.1,
            status_file=str(status_file),
        )

        assert ok is True
        assert "All configured ICAP services" in detail
        assert payload["ok"] is True
        assert server.calls == 3
        assert sleeps == [0.1, 0.1]
        assert json.loads(status_file.read_text(encoding="utf-8")) == payload
    finally:
        server.shutdown()
        server.server_close()


def test_icap_readiness_wait_json_uses_success_payload_without_extra_probe(
    tmp_path, monkeypatch, capsys
) -> None:
    import icap_readiness  # type: ignore

    server = _start_server(
        responses=[
            b"ICAP/1.0 200 OK\r\nMethods: REQMOD\r\nConnection: close\r\nEncapsulated: null-body=0\r\n\r\n",
            b"ICAP/1.0 503 Service Unavailable\r\nConnection: close\r\n\r\n",
        ]
    )
    monkeypatch.setattr(icap_readiness.time, "sleep", lambda _seconds: None)
    try:
        config = tmp_path / "20-icap.conf"
        status_file = tmp_path / "status.json"
        config.write_text(
            f"icap_service adblock_req reqmod_precache icap://127.0.0.1:{server.server_address[1]}/adblockreq bypass=on\n",
            encoding="utf-8",
        )

        exit_code = icap_readiness.main(
            [
                "wait",
                "--config",
                str(config),
                "--status-file",
                str(status_file),
                "--timeout",
                "1",
                "--probe-timeout",
                "0.5",
                "--interval",
                "0.1",
                "--json",
            ]
        )

        stdout_payload = json.loads(capsys.readouterr().out)
        status_payload = json.loads(status_file.read_text(encoding="utf-8"))
        assert exit_code == 0
        assert stdout_payload == status_payload
        assert stdout_payload["ok"] is True
        assert "timed_out" not in stdout_payload
        assert server.calls == 1
    finally:
        server.shutdown()
        server.server_close()


def test_icap_readiness_wait_json_reports_timeout_payload_without_recheck(
    tmp_path, monkeypatch, capsys
) -> None:
    import icap_readiness  # type: ignore

    server = _start_server(
        responses=[
            b"ICAP/1.0 503 Service Unavailable\r\nConnection: close\r\n\r\n",
            b"ICAP/1.0 200 OK\r\nMethods: REQMOD\r\nConnection: close\r\nEncapsulated: null-body=0\r\n\r\n",
        ]
    )
    monkeypatch.setattr(icap_readiness.time, "sleep", lambda _seconds: None)
    monotonic_values = iter([0.0, 0.1])
    monkeypatch.setattr(
        icap_readiness.time, "monotonic", lambda: next(monotonic_values)
    )
    try:
        config = tmp_path / "20-icap.conf"
        status_file = tmp_path / "status.json"
        config.write_text(
            f"icap_service adblock_req reqmod_precache icap://127.0.0.1:{server.server_address[1]}/adblockreq bypass=off\n",
            encoding="utf-8",
        )

        exit_code = icap_readiness.main(
            [
                "wait",
                "--config",
                str(config),
                "--status-file",
                str(status_file),
                "--timeout",
                "0.1",
                "--probe-timeout",
                "0.5",
                "--interval",
                "0.1",
                "--json",
            ]
        )

        stdout_payload = json.loads(capsys.readouterr().out)
        status_payload = json.loads(status_file.read_text(encoding="utf-8"))
        assert exit_code == 1
        assert stdout_payload == status_payload
        assert stdout_payload["ok"] is False
        assert stdout_payload["timed_out"] is True
        assert (
            stdout_payload["services"][0]["status_line"]
            == "ICAP/1.0 503 Service Unavailable"
        )
        assert server.calls == 1
    finally:
        server.shutdown()
        server.server_close()


def test_icap_readiness_cli_ignores_malformed_numeric_env_defaults(
    tmp_path, monkeypatch, capsys
) -> None:
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

    stdout_payload = json.loads(capsys.readouterr().out)
    status_payload = json.loads(status_file.read_text(encoding="utf-8"))
    assert stdout_payload == status_payload
    assert stdout_payload["detail"] == "No ICAP services are configured."
    assert stdout_payload["ok"] is True
    assert stdout_payload["services"] == []
    assert stdout_payload["timeout_seconds"] == pytest.approx(75.0)


def test_icap_readiness_cli_rejects_non_finite_numeric_flags(capsys) -> None:
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


def test_icap_readiness_probe_does_not_swallow_programming_errors(monkeypatch) -> None:
    import icap_readiness  # type: ignore

    def raise_runtime_error(*_args, **_kwargs):
        msg = "synthetic non-socket bug"
        raise RuntimeError(msg)

    monkeypatch.setattr(icap_readiness.socket, "create_connection", raise_runtime_error)

    with pytest.raises(RuntimeError, match="synthetic non-socket bug"):
        icap_readiness.probe_service(_service(1344), timeout=0.1)


def test_icap_readiness_reports_status_file_write_failures(tmp_path) -> None:
    import icap_readiness  # type: ignore

    config = tmp_path / "20-icap.conf"
    config.write_text("", encoding="utf-8")
    blocked_parent = tmp_path / "not-a-directory"
    blocked_parent.write_text("already a file", encoding="utf-8")

    ok, detail, payload = icap_readiness.wait_ready(
        [str(config)],
        timeout=0.1,
        probe_timeout=0.1,
        interval=0.05,
        status_file=str(blocked_parent / "status.json"),
    )

    assert ok is True
    assert detail == "No ICAP services are configured."
    assert payload["ok"] is True
    assert "failed to write ICAP readiness status file" in payload["status_file_error"]


def test_icap_readiness_status_write_ignores_hostile_predictable_temp_symlink(
    tmp_path,
) -> None:
    import icap_readiness  # type: ignore

    status_file = tmp_path / "status.json"
    victim = tmp_path / "victim.json"
    victim.write_text("do not overwrite\n", encoding="utf-8")
    stale_tmp = tmp_path / f".{status_file.name}.{icap_readiness.os.getpid()}.tmp"
    stale_tmp.symlink_to(victim)

    assert icap_readiness._write_status(str(status_file), {"ok": True}) is None

    assert victim.read_text(encoding="utf-8") == "do not overwrite\n"
    assert stale_tmp.is_symlink()
    assert json.loads(status_file.read_text(encoding="utf-8")) == {"ok": True}


def test_icap_readiness_status_write_uses_private_permissions(tmp_path) -> None:
    import icap_readiness  # type: ignore

    status_file = tmp_path / "status.json"
    previous_umask = icap_readiness.os.umask(0)
    try:
        assert icap_readiness._write_status(str(status_file), {"ok": True}) is None
    finally:
        icap_readiness.os.umask(previous_umask)

    assert status_file.stat().st_mode & 0o777 == 0o600


def test_icap_readiness_status_write_cleans_temp_after_replace_failure(
    tmp_path, monkeypatch
) -> None:
    import icap_readiness  # type: ignore

    status_file = tmp_path / "status.json"

    def fail_replace(_source, _target) -> None:
        message = "synthetic replace failure"
        raise OSError(message)

    monkeypatch.setattr(icap_readiness.Path, "replace", fail_replace)

    error = icap_readiness._write_status(str(status_file), {"ok": True})

    assert error is not None
    assert "synthetic replace failure" in error
    assert list(tmp_path.iterdir()) == []


def test_squid_ready_start_delegates_numeric_env_parsing_to_readiness() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    script = (repo_root / "docker" / "squid_ready_start.sh").read_text(encoding="utf-8")

    assert '--timeout "$TIMEOUT"' not in script
    assert '--probe-timeout "$PROBE_TIMEOUT"' not in script
    assert '--interval "$INTERVAL"' not in script
    assert '--status-file "$STATUS_FILE"' in script


def test_cicap_av_runner_optional_fallback_answers_options(
    tmp_path, monkeypatch
) -> None:
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
