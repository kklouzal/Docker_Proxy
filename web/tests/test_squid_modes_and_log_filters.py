import os
import sys
from pathlib import Path

from .mysql_test_utils import configure_test_mysql_env


def _add_web_to_path() -> None:
    web_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if web_dir not in sys.path:
        sys.path.insert(0, web_dir)


def test_socks_store_ignores_accept_noise_and_keeps_connect_events(tmp_path):
    _add_web_to_path()
    configure_test_mysql_env(tmp_path)

    from services.socks_store import SocksStore  # type: ignore

    store = SocksStore(log_path=str(tmp_path / "sockd.log"))
    store.init_db()

    store.ingest_line(
        "Apr 18 04:11:14 (1776485474.616347) sockd[948]: info: pass(1): tcp/accept [: 127.0.0.1.36422 127.0.0.1.1080"
    )
    store.ingest_line(
        "Apr 18 03:27:21 (1776482841.123456) sockd[104]: info: pass(1): tcp/connect [: 172.18.0.1.50000 140.82.114.26.443"
    )

    recent = store.recent(limit=10)

    assert len(recent) == 1
    assert recent[0].action == "connect"
    assert recent[0].src_ip == "172.18.0.1"
    assert recent[0].dst == "140.82.114.26"


def test_ssl_errors_store_seed_from_recent_log_skips_already_counted_rows(tmp_path):
    _add_web_to_path()
    configure_test_mysql_env(tmp_path / "ssl-errors-seed")

    from services.ssl_errors_store import SslErrorsStore  # type: ignore

    cache_log = tmp_path / "cache.log"
    cache_log.write_text(
        "\n".join(
            [
                "2026/04/18 04:04:09 kid1| Processing Configuration File: /etc/squid/conf.d/10-sslfilter.conf (depth 1)",
                "2026/04/18 04:04:40 kid1| error detail: SQUID_TLS_ERR_ACCEPT+TLS_LIB_ERR=A000119+TLS_IO_ERR=1",
            ]
        ),
        encoding="utf-8",
    )

    store = SslErrorsStore(cache_log_path=str(cache_log))
    store.init_db()
    store.seed_from_recent_log()
    store.seed_from_recent_log()

    rows = store.list_errors(limit=10)

    assert len(rows) == 1
    assert rows[0]["count"] == 1


def test_ssl_errors_store_ignores_startup_noise(tmp_path):
    _add_web_to_path()
    configure_test_mysql_env(tmp_path / "ssl-errors")

    from services.ssl_errors_store import SslErrorsStore  # type: ignore

    store = SslErrorsStore(cache_log_path=str(tmp_path / "cache.log"))
    store.init_db()
    store.ingest_line("2026/04/18 04:04:09| Processing Configuration File: /etc/squid/conf.d/10-sslfilter.conf (depth 1)")
    store.ingest_line("2026/04/18 04:04:39| helperOpenServers: Starting 5/12 'ssl_crtd' processes")
    store.ingest_line("2026/04/18 04:04:40| error detail: SQUID_TLS_ERR_ACCEPT+TLS_LIB_ERR=A000119+TLS_IO_ERR=1")

    rows = store.list_errors(limit=10)

    assert len(rows) == 1
    assert rows[0]["category"] == "TLS_OTHER"
    assert "SQUID_TLS_ERR_ACCEPT" in rows[0]["reason"]


def test_render_icap_include_uses_single_endpoint_services_and_identity_rules(monkeypatch):
    _add_web_to_path()

    from services.squidctl import SquidController  # type: ignore

    monkeypatch.setenv("CICAP_PORT", "24000")
    monkeypatch.setenv("CICAP_AV_PORT", "24001")

    ctl = SquidController()
    out = ctl._render_icap_include()

    assert out.count("icap_service adblock_req ") == 1
    assert out.count("icap_service av_resp ") == 1
    assert "icap_service adblock_req_0" not in out
    assert "icap_service av_resp_0" not in out
    assert "icap://127.0.0.1:24000/adblockreq" in out
    assert "icap://127.0.0.1:24001/avrespmod" in out
    assert "request_header_access Accept-Encoding deny icap_identity_methods" in out
    assert "request_header_add Accept-Encoding identity icap_identity_methods" in out


def test_repo_template_includes_cache_first_defaults():
    repo_root = Path(__file__).resolve().parents[2]
    text = (repo_root / "squid" / "squid.conf.template").read_text(encoding="utf-8")

    assert "pconn_timeout 120 seconds" in text
    assert "client_lifetime 3600 seconds" in text
    assert "pipeline_prefetch 1" in text
    assert "quick_abort_min 0 KB" in text
    assert "quick_abort_max 0 KB" in text
    assert "quick_abort_pct 100" in text