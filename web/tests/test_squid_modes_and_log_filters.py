import os
import sys
from pathlib import Path
from types import SimpleNamespace

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
    assert rows[0]["category"] == "TLS_CLIENT_ACCEPT"
    assert "SQUID_TLS_ERR_ACCEPT" in rows[0]["reason"]


def test_ssl_errors_store_merges_followup_connection_context_without_double_count(tmp_path):
    _add_web_to_path()
    configure_test_mysql_env(tmp_path / "ssl-errors-context")

    from services.ssl_errors_store import SslErrorsStore  # type: ignore

    store = SslErrorsStore(cache_log_path=str(tmp_path / "cache.log"))
    store.init_db()
    store.ingest_line("2026/04/18 04:04:40| error detail: SQUID_TLS_ERR_ACCEPT+TLS_LIB_ERR=A000119+TLS_IO_ERR=1")
    store.ingest_line("    connection: conn23 local=10.0.0.5:3128 remote=192.0.2.10:54432 FD 12 flags=1")

    rows = store.list_errors(limit=10)

    assert len(rows) == 1
    assert rows[0]["count"] == 1
    assert "connection: conn23" in rows[0]["sample"]
    assert "remote=192.0.2.10:54432" in rows[0]["sample"]


def test_ssl_errors_store_merges_tls_accept_header_detail_and_context_into_one_bucket(tmp_path):
    _add_web_to_path()
    configure_test_mysql_env(tmp_path / "ssl-errors-block")

    from services.ssl_errors_store import SslErrorsStore  # type: ignore

    store = SslErrorsStore(cache_log_path=str(tmp_path / "cache.log"))
    store.init_db()
    store.ingest_line("2026/04/21 23:37:04 kid1| ERROR: Cannot accept a TLS connection")
    store.ingest_line("2026/04/21 23:37:04 kid1| error detail: SQUID_TLS_ERR_ACCEPT+TLS_LIB_ERR=A000119+TLS_IO_ERR=1")
    store.ingest_line("    connection: conn23 local=10.0.0.5:3128 remote=192.0.2.10:54432 FD 12 flags=1")

    rows = store.list_errors(limit=10)

    assert len(rows) == 1
    assert rows[0]["category"] == "TLS_CLIENT_ACCEPT"
    assert rows[0]["reason"] == "SQUID_TLS_ERR_ACCEPT+TLS_LIB_ERR=A000119+TLS_IO_ERR=1"
    assert rows[0]["count"] == 1
    assert "Cannot accept a TLS connection" in rows[0]["sample"]
    assert "error detail: SQUID_TLS_ERR_ACCEPT+TLS_LIB_ERR=A000119+TLS_IO_ERR=1" in rows[0]["sample"]
    assert "connection: conn23" in rows[0]["sample"]


def test_render_icap_include_uses_single_endpoint_services_without_identity_rewrite(monkeypatch):
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
    assert "Accept-Encoding identity" not in out


def test_repo_template_includes_cache_first_defaults():
    repo_root = Path(__file__).resolve().parents[2]
    text = (repo_root / "squid" / "squid.conf.template").read_text(encoding="utf-8")

    assert "cache_dir rock /var/spool/squid 10000 slot-size=32768" in text
    assert "cache_mem 256 MB" in text
    assert "memory_cache_mode always" in text
    assert "memory_cache_shared on" in text
    assert "shared_transient_entries_limit 32768" in text
    assert "cache_replacement_policy heap GDSF" in text
    assert "memory_replacement_policy heap GDSF" in text
    assert "cache_miss_revalidate on" in text
    assert "client_idle_pconn_timeout 120 seconds" in text
    assert "server_idle_pconn_timeout 120 seconds" in text
    assert "client_lifetime 3600 seconds" in text
    assert "pipeline_prefetch 1" in text
    assert "quick_abort_min 0 KB" in text
    assert "quick_abort_max 0 KB" in text
    assert "quick_abort_pct 100" in text
    assert "icap_preview_enable on" in text
    assert "sslproxy_session_ttl 600 seconds" in text
    assert "icap_service_failure_limit 10 in 30 seconds" in text


def test_squid_controller_normalize_config_text_adds_default_observability_lines():
    _add_web_to_path()

    from services.squidctl import SquidController  # type: ignore

    ctl = SquidController()
    text = ctl.normalize_config_text(
        """
acl steam_sites ssl::server_name .steamserver.net
acl has_auth req_header Authorization .
acl has_cookie req_header Cookie .
logformat liveui %ts\t%tr\t%>a\t%rm\t%ru\t%Ss/%>Hs\t%st
access_log stdio:/var/log/squid/access.log liveui
cache_log stdio:/var/log/squid/cache.log
cache_store_log none
http_access allow all
""".strip()
    )

    assert "logformat diagnostic" in text
    assert "logformat icapobserve" in text
    assert "access_log stdio:/var/log/squid/access-observe.log diagnostic" in text
    assert "/var/log/squid/access.log" not in text
    assert "icap_log stdio:/var/log/squid/icap.log icapobserve" in text
    assert "note ssl_exception steam steam_sites" in text
    assert "note cache_bypass auth has_auth" in text
    assert "note cache_bypass cookie has_cookie" in text


def test_squid_controller_parses_new_perf_tunables():
    _add_web_to_path()

    from services.squidctl import SquidController  # type: ignore

    ctl = SquidController()
    options = ctl.get_tunable_options(
        """
cache_dir rock /var/spool/squid 10000 slot-size=32768 swap-timeout=250 max-swap-rate=1500
memory_cache_mode disk
memory_cache_shared off
shared_transient_entries_limit 65536
cache_miss_revalidate off
server_idle_pconn_timeout 150 seconds
client_idle_pconn_timeout 75 seconds
connect_retries 2
forward_max_tries 12
dns_retransmit_interval 7 seconds
ipcache_low 80
ipcache_high 92
sslcrtd_children 12 startup=3 idle=2 queue-size=96
http_port 0.0.0.0:3128 ssl-bump dynamic_cert_mem_cache_size=256MB
dns_packet_max 1232
sslproxy_session_ttl 900
sslproxy_session_cache_size 16 MB
icap_persistent_connections off
icap_default_options_ttl 120
icap_service_failure_limit 5 in 45 seconds
icap_service_revival_delay 90 seconds
shared_memory_locking on
cpu_affinity_map process_numbers=1,2 cores=1,3
max_open_disk_fds 512
""".strip()
    )

    assert options["cache_dir_type"] == "rock"
    assert options["cache_dir_rock_slot_size_kb"] == 32
    assert options["cache_dir_rock_swap_timeout_ms"] == 250
    assert options["cache_dir_rock_max_swap_rate"] == 1500
    assert options["memory_cache_mode"] == "disk"
    assert options["memory_cache_shared"] is False
    assert options["shared_transient_entries_limit"] == 65536
    assert options["cache_miss_revalidate"] is False
    assert options["server_idle_pconn_timeout_seconds"] == 150
    assert options["client_idle_pconn_timeout_seconds"] == 75
    assert options["connect_retries"] == 2
    assert options["forward_max_tries"] == 12
    assert options["dns_retransmit_interval_seconds"] == 7
    assert options["ipcache_low"] == 80
    assert options["ipcache_high"] == 92
    assert options["sslcrtd_children"] == 12
    assert options["sslcrtd_children_startup"] == 3
    assert options["sslcrtd_children_idle"] == 2
    assert options["sslcrtd_children_queue_size"] == 96
    assert options["dynamic_cert_mem_cache_size_mb"] == 256
    assert options["dns_packet_max"] == 1232
    assert options["sslproxy_session_ttl_seconds"] == 900
    assert options["sslproxy_session_cache_size_mb"] == 16
    assert options["icap_persistent_connections"] is False
    assert options["icap_default_options_ttl_seconds"] == 120
    assert options["icap_service_failure_limit"] == 5
    assert options["icap_service_failure_limit_window_seconds"] == 45
    assert options["icap_service_revival_delay_seconds"] == 90
    assert options["shared_memory_locking"] is True
    assert options["cpu_affinity_map"] == "process_numbers=1,2 cores=1,3"
    assert options["max_open_disk_fds"] == 512


def test_squid_controller_generate_config_applies_new_perf_tunables(tmp_path):
    _add_web_to_path()

    from services.squidctl import SquidController  # type: ignore

    repo_root = Path(__file__).resolve().parents[2]
    template_path = tmp_path / "squid.conf.template"
    template_path.write_text((repo_root / "squid" / "squid.conf.template").read_text(encoding="utf-8"), encoding="utf-8")

    ctl = SquidController(squid_conf_path=str(tmp_path / "squid.conf"))
    ctl.squid_conf_template_path = str(template_path)

    rendered = ctl.generate_config_from_template(
        {
            "cache_dir_type": "ufs",
            "cache_dir_ufs_l1": 32,
            "cache_dir_ufs_l2": 512,
            "memory_cache_mode": "disk",
            "memory_cache_shared_on": False,
            "shared_transient_entries_limit": 65536,
            "server_idle_pconn_timeout_seconds": 150,
            "client_idle_pconn_timeout_seconds": 75,
            "connect_retries": 2,
            "forward_max_tries": 12,
            "dns_retransmit_interval_seconds": 7,
            "ipcache_low": 80,
            "ipcache_high": 92,
            "sslcrtd_children": 12,
            "sslcrtd_children_startup": 3,
            "sslcrtd_children_idle": 2,
            "sslcrtd_children_queue_size": 96,
            "dynamic_cert_mem_cache_size_mb": 256,
            "dns_packet_max": "none",
            "sslproxy_session_ttl_seconds": 900,
            "sslproxy_session_cache_size_mb": 16,
            "icap_persistent_connections_on": False,
            "icap_default_options_ttl_seconds": 120,
            "icap_service_failure_limit": 5,
            "icap_service_failure_limit_window_seconds": 45,
            "icap_service_revival_delay_seconds": 90,
            "memory_pools_limit_mb": "none",
            "shared_memory_locking_on": True,
            "cpu_affinity_map": "process_numbers=1,2 cores=1,3",
            "max_open_disk_fds": 512,
            "cache_miss_revalidate_on": False,
            "icap_preview_enable_on": True,
        }
    )

    assert "cache_dir ufs /var/spool/squid 10000 32 512" in rendered
    assert "memory_cache_mode disk" in rendered
    assert "memory_cache_shared off" in rendered
    assert "shared_transient_entries_limit 65536" in rendered
    assert "server_idle_pconn_timeout 150 seconds" in rendered
    assert "client_idle_pconn_timeout 75 seconds" in rendered
    assert "connect_retries 2" in rendered
    assert "forward_max_tries 12" in rendered
    assert "dns_retransmit_interval 7 seconds" in rendered
    assert "ipcache_low 80" in rendered
    assert "ipcache_high 92" in rendered
    assert "sslcrtd_children 12 startup=3 idle=2 queue-size=96" in rendered
    assert "dynamic_cert_mem_cache_size=256MB" in rendered
    assert "dns_packet_max none" in rendered
    assert "sslproxy_session_ttl 900 seconds" in rendered
    assert "sslproxy_session_cache_size 16 MB" in rendered
    assert "icap_persistent_connections off" in rendered
    assert "icap_default_options_ttl 120" in rendered
    assert "icap_service_failure_limit 5 in 45 seconds" in rendered
    assert "icap_service_revival_delay 90 seconds" in rendered
    assert "memory_pools_limit none" in rendered
    assert "shared_memory_locking on" in rendered
    assert "cpu_affinity_map process_numbers=1,2 cores=1,3" in rendered
    assert "max_open_disk_fds 512" in rendered
    assert "cache_miss_revalidate off" in rendered
    assert "icap_preview_enable on" in rendered


def test_generate_config_with_exclusions_uses_sni_acl_for_tls_splice(tmp_path):
    _add_web_to_path()

    from services.exclusions_store import Exclusions  # type: ignore
    from services.squidctl import SquidController  # type: ignore

    repo_root = Path(__file__).resolve().parents[2]
    template_path = tmp_path / "squid.conf.template"
    template_path.write_text((repo_root / "squid" / "squid.conf.template").read_text(encoding="utf-8"), encoding="utf-8")

    ctl = SquidController(squid_conf_path=str(tmp_path / "squid.conf"))
    ctl.squid_conf_template_path = str(template_path)

    rendered = ctl.generate_config_from_template_with_exclusions(
        {},
        Exclusions(
            domains=["*.windowsupdate.com", "login.live.com"],
            dst_nets=[],
            src_nets=[],
            exclude_private_nets=False,
        ),
    )

    assert "acl excluded_domains dstdomain *.windowsupdate.com login.live.com" in rendered
    assert "acl excluded_domains_ssl ssl::server_name *.windowsupdate.com login.live.com" in rendered
    assert "note exclusion_rule domain excluded_domains_ssl" in rendered
    assert "ssl_bump splice excluded_domains_ssl" in rendered
    assert "cache deny excluded_domains" in rendered


def test_apply_config_text_restarts_under_supervisor_when_reconfigure_lacks_pidfile(tmp_path):
    _add_web_to_path()

    from services.squidctl import SquidController  # type: ignore

    squid_conf = tmp_path / "squid.conf"
    squid_conf.write_text("http_port 3128\n", encoding="utf-8")
    persisted_conf = tmp_path / "persisted.conf"
    os.environ["PERSISTED_SQUID_CONF_PATH"] = str(persisted_conf)

    commands: list[tuple[str, ...]] = []

    def fake_run(args, **kwargs):
        commands.append(tuple(args))
        if tuple(args[:3]) == ("squid", "-k", "parse"):
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        if tuple(args[:3]) == ("squid", "-k", "reconfigure"):
            return SimpleNamespace(
                returncode=1,
                stdout=b"",
                stderr=b"FATAL: failed to open /var/run/squid.pid: (2) No such file or directory\n",
            )
        if tuple(args[:4]) == ("supervisorctl", "-c", "/etc/supervisord.conf", "restart"):
            return SimpleNamespace(returncode=0, stdout=b"squid: started\n", stderr=b"")
        raise AssertionError(f"Unexpected command: {args}")

    ctl = SquidController(squid_conf_path=str(squid_conf), cmd_run=fake_run)

    ok, detail = ctl.apply_config_text("http_port 3128\ncache_mem 128 MB\n")

    assert ok is True
    assert "started" in detail
    assert persisted_conf.read_text(encoding="utf-8") == ctl.normalize_config_text("http_port 3128\ncache_mem 128 MB\n")