from __future__ import annotations

import socket
import sys
import threading
from pathlib import Path

from .test_adblock_lookup import _add_web_to_path, _build_lookup_db


def test_sqlite_decision_engine_applies_full_abp_semantics(tmp_path: Path) -> None:
    db_path = _build_lookup_db(
        tmp_path,
        [
            "||ads.example^",
            "@@||ads.example/allowed.js$script",
            "||cdn.example.com/assets/ad.js^$script",
            "||cdn.example.com/assets/ad.css^$~stylesheet",
            "wss://loader.*.com/ws^$websocket,third-party",
            "/tracker[.]example/$third-party",
            "plain-ad-token$domain=source.example",
            "||api.example.com/path$method=POST,denyallow=allowed.example",
            "CaseSensitive$match-case",
            "modifier-token$redirect=noopjs",
            "||ads.example.co.uk^$third-party",
        ],
    )

    _add_web_to_path()
    from services.adblock_decision import AdblockDecisionEngine

    engine = AdblockDecisionEngine(db_path, cache_ttl_seconds=0, cache_max=0)

    assert engine.decide("https://sub.ads.example/banner.js").blocked is True
    assert engine.decide("https://user:pass@sub.ads.example/banner.js").blocked is True
    exception = engine.decide(
        "https://ads.example/allowed.js",
        headers={"accept": "application/javascript"},
    )
    assert exception.blocked is False
    assert exception.reason == "exception"

    assert (
        engine.decide(
            "https://cdn.example.com/assets/ad.js?slot=1",
            headers={"accept": "application/javascript"},
        ).blocked
        is True
    )
    assert (
        engine.decide(
            "https://cdn.example.com/assets/ad.css",
            headers={"accept": "text/css"},
        ).blocked
        is False
    )
    assert (
        engine.decide(
            "wss://loader.foo.com/ws",
            headers={"upgrade": "websocket", "referer": "https://source.example/"},
        ).blocked
        is True
    )
    assert (
        engine.decide(
            "https://static.example/plain-ad-token.js",
            headers={"referer": "https://source.example/page"},
        ).blocked
        is True
    )
    assert (
        engine.decide(
            "https://static.example/plain-ad-token.js",
            headers={"referer": "https://other.example/page"},
        ).blocked
        is False
    )
    assert (
        engine.decide(
            "https://api.example.com/path",
            method="POST",
        ).blocked
        is True
    )
    assert (
        engine.decide(
            "https://allowed.example/path",
            method="POST",
        ).blocked
        is False
    )
    assert engine.decide("https://static.example/CaseSensitive.js").blocked is True
    assert engine.decide("https://static.example/casesensitive.js").blocked is False
    assert engine.decide("https://static.example/modifier-token.js").blocked is False
    assert (
        engine.decide(
            "https://ads.example.co.uk/banner.js",
            headers={"referer": "https://shop.other.co.uk/"},
        ).blocked
        is True
    )
    assert (
        engine.decide(
            "https://ads.example.co.uk/banner.js",
            headers={"referer": "https://shop.example.co.uk/"},
        ).blocked
        is False
    )


def _send_icap(port: int, payload: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
        sock.settimeout(2.0)
        sock.sendall(payload)
        chunks: list[bytes] = []
        while True:
            try:
                chunk = sock.recv(65536)
            except TimeoutError:
                break
            if not chunk:
                break
            chunks.append(chunk)
            if b"\r\n\r\n" in b"".join(chunks):
                break
        return b"".join(chunks)


def test_adblock_icap_server_uses_sqlite_decisions_and_logs_blocks(
    tmp_path: Path,
) -> None:
    db_path = _build_lookup_db(tmp_path, ["||ads.example^"])
    log_path = tmp_path / "cicap-access.log"

    _add_web_to_path()
    from services.adblock_decision import AdblockDecisionEngine
    from tools.adblock_icap_server import _AdblockIcapServer

    engine = AdblockDecisionEngine(db_path, cache_ttl_seconds=0, cache_max=0)
    server = _AdblockIcapServer(
        ("127.0.0.1", 0),
        engine=engine,
        access_log_path=str(log_path),
        max_request_bytes=65536,
    )
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        options = _send_icap(
            port,
            (
                b"OPTIONS icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Encapsulated: null-body=0\r\n\r\n"
            ),
        )
        assert options.startswith(b"ICAP/1.0 200")
        assert b"Methods: REQMOD" in options

        http = (
            b"GET http://ads.example/banner.js HTTP/1.1\r\n"
            b"Host: ads.example\r\n"
            b"Accept: application/javascript\r\n\r\n"
        )
        req = (
            b"REQMOD icap://127.0.0.1/adblockreq ICAP/1.0\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Encapsulated: req-hdr=0, null-body="
            + str(len(http)).encode("ascii")
            + b"\r\n\r\n"
            + http
        )
        response = _send_icap(port, req)
        assert response.startswith(b"ICAP/1.0 200")
        assert b"HTTP/1.1 403 Forbidden" in response
        assert "ads.example/banner.js" in log_path.read_text(encoding="utf-8")
    finally:
        server.shutdown()
        server.server_close()


def test_proxy_payload_includes_sqlite_adblock_runtime() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    dockerfile = (repo_root / "docker/Dockerfile.proxy").read_text(encoding="utf-8")
    entrypoint = (repo_root / "docker/entrypoint.sh").read_text(encoding="utf-8")

    assert "web/services/adblock_decision.py" in dockerfile
    assert "web/services/adblock_lookup.py" in dockerfile
    assert "web/tools/adblock_icap_server.py" in dockerfile
    assert "python3 /app/tools/adblock_icap_server.py" in entrypoint
    assert "request_lookup.sqlite" in entrypoint
    assert "srv_url_check.so" not in entrypoint


if str(Path(__file__).resolve().parents[1]) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
