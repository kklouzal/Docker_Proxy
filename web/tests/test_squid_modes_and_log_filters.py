import os
import sys
from pathlib import Path

from .mysql_test_utils import configure_test_mysql_env


def _add_web_to_path() -> None:
    web_dir = Path(os.path.join(Path(__file__).parent, "..")).resolve()
    repo_dir = Path(os.path.join(web_dir, "..")).resolve()
    if web_dir not in sys.path:
        sys.path.insert(0, web_dir)
    if repo_dir not in sys.path:
        sys.path.insert(0, repo_dir)


def test_ssl_errors_store_seed_from_recent_log_skips_already_counted_rows(
    tmp_path,
) -> None:
    _add_web_to_path()
    configure_test_mysql_env(tmp_path / "ssl-errors-seed")

    from services.ssl_errors_store import SslErrorsStore  # type: ignore

    cache_log = tmp_path / "cache.log"
    cache_log.write_text(
        "2026/04/18 04:04:09 kid1| Processing Configuration File: /etc/squid/conf.d/10-sslfilter.conf (depth 1)\n2026/04/18 04:04:40 kid1| error detail: SQUID_TLS_ERR_ACCEPT+TLS_LIB_ERR=A000119+TLS_IO_ERR=1",
        encoding="utf-8",
    )

    store = SslErrorsStore(cache_log_path=str(cache_log))
    store.init_db()
    store.seed_from_recent_log()
    store.seed_from_recent_log()

    rows = store.list_errors(limit=10)

    assert len(rows) == 1
    assert rows[0]["count"] == 1


def test_ssl_errors_store_ignores_startup_noise(tmp_path) -> None:
    _add_web_to_path()
    configure_test_mysql_env(tmp_path / "ssl-errors")

    from services.ssl_errors_store import SslErrorsStore  # type: ignore

    store = SslErrorsStore(cache_log_path=str(tmp_path / "cache.log"))
    store.init_db()
    store.ingest_line(
        "2026/04/18 04:04:09| Processing Configuration File: /etc/squid/conf.d/10-sslfilter.conf (depth 1)"
    )
    store.ingest_line(
        "2026/04/18 04:04:39| helperOpenServers: Starting 5/12 'ssl_crtd' processes"
    )
    store.ingest_line(
        "2026/04/18 04:04:40| error detail: SQUID_TLS_ERR_ACCEPT+TLS_LIB_ERR=A000119+TLS_IO_ERR=1"
    )

    rows = store.list_errors(limit=10)

    assert len(rows) == 1
    assert rows[0]["category"] == "TLS_CLIENT_ACCEPT"
    assert "SQUID_TLS_ERR_ACCEPT" in rows[0]["reason"]


def test_ssl_errors_store_merges_followup_connection_context_without_double_count(
    tmp_path,
) -> None:
    _add_web_to_path()
    configure_test_mysql_env(tmp_path / "ssl-errors-context")

    from services.ssl_errors_store import SslErrorsStore  # type: ignore

    store = SslErrorsStore(cache_log_path=str(tmp_path / "cache.log"))
    store.init_db()
    store.ingest_line(
        "2026/04/18 04:04:40| error detail: SQUID_TLS_ERR_ACCEPT+TLS_LIB_ERR=A000119+TLS_IO_ERR=1"
    )
    store.ingest_line(
        "    connection: conn23 local=10.0.0.5:3128 remote=192.0.2.10:54432 FD 12 flags=1"
    )

    rows = store.list_errors(limit=10)

    assert len(rows) == 1
    assert rows[0]["count"] == 1
    assert "connection: conn23" in rows[0]["sample"]
    assert "remote=192.0.2.10:54432" in rows[0]["sample"]


def test_ssl_errors_store_merges_tls_accept_header_detail_and_context_into_one_bucket(
    tmp_path,
) -> None:
    _add_web_to_path()
    configure_test_mysql_env(tmp_path / "ssl-errors-block")

    from services.ssl_errors_store import SslErrorsStore  # type: ignore

    store = SslErrorsStore(cache_log_path=str(tmp_path / "cache.log"))
    store.init_db()
    store.ingest_line("2026/04/21 23:37:04 kid1| ERROR: Cannot accept a TLS connection")
    store.ingest_line(
        "2026/04/21 23:37:04 kid1| error detail: SQUID_TLS_ERR_ACCEPT+TLS_LIB_ERR=A000119+TLS_IO_ERR=1"
    )
    store.ingest_line(
        "    connection: conn23 local=10.0.0.5:3128 remote=192.0.2.10:54432 FD 12 flags=1"
    )

    rows = store.list_errors(limit=10)

    assert len(rows) == 1
    assert rows[0]["category"] == "TLS_CLIENT_ACCEPT"
    assert rows[0]["reason"] == "SQUID_TLS_ERR_ACCEPT+TLS_LIB_ERR=A000119+TLS_IO_ERR=1"
    assert rows[0]["count"] == 1
    assert "Cannot accept a TLS connection" in rows[0]["sample"]
    assert (
        "error detail: SQUID_TLS_ERR_ACCEPT+TLS_LIB_ERR=A000119+TLS_IO_ERR=1"
        in rows[0]["sample"]
    )
    assert "connection: conn23" in rows[0]["sample"]


def test_ssl_errors_store_enriches_tls_accept_domain_from_master_xaction(
    tmp_path,
) -> None:
    _add_web_to_path()
    configure_test_mysql_env(tmp_path / "ssl-errors-master-context")

    from services.ssl_errors_store import SslErrorsStore  # type: ignore

    store = SslErrorsStore(cache_log_path=str(tmp_path / "cache.log"))
    store.init_db()
    with store._connect() as conn:
        conn.execute(
            """
            CREATE TABLE diagnostic_requests (
                id BIGINT PRIMARY KEY AUTO_INCREMENT,
                proxy_id VARCHAR(64) NOT NULL DEFAULT 'default',
                ts BIGINT NOT NULL,
                domain VARCHAR(255) NOT NULL,
                sni VARCHAR(255) NOT NULL,
                host VARCHAR(255) NOT NULL,
                url TEXT NOT NULL,
                master_xaction VARCHAR(128) NOT NULL,
                KEY idx_diag_proxy_master_ts (proxy_id, master_xaction, ts)
            )
            """,
        )
        conn.execute(
            """
            INSERT INTO diagnostic_requests(proxy_id, ts, domain, sni, host, url, master_xaction)
            VALUES('default', UNIX_TIMESTAMP('2026-04-21 23:37:04'), 'gateway.discord.gg', 'gateway.discord.gg', 'gateway.discord.gg:443', 'gateway.discord.gg:443', '55')
            """,
        )

    store.ingest_line("2026/04/21 23:37:04 kid1| ERROR: Cannot accept a TLS connection")
    store.ingest_line(
        "2026/04/21 23:37:04 kid1| error detail: SQUID_TLS_ERR_ACCEPT+TLS_LIB_ERR=A000119+TLS_IO_ERR=1"
    )
    store.ingest_line("    current master transaction: master55")

    rows = store.list_errors(limit=10)

    assert len(rows) == 1
    assert rows[0]["domain"] == "gateway.discord.gg"
    assert rows[0]["count"] == 1
    assert "current master transaction: master55" in rows[0]["sample"]


def test_ssl_errors_store_search_queries_escape_like_patterns_for_mysql(
    tmp_path,
) -> None:
    _add_web_to_path()
    configure_test_mysql_env(tmp_path / "ssl-errors-search")

    from services.ssl_errors_store import SslErrorsStore  # type: ignore

    store = SslErrorsStore(cache_log_path=str(tmp_path / "cache.log"))
    store.init_db()
    store.ingest_line(
        "2026/04/21 23:37:04 kid1| error detail: SQUID_TLS_ERR_ACCEPT+TLS_LIB_ERR=A000119+TLS_IO_ERR=1 CONNECT tls.example:443"
    )

    recent = store.list_recent(search="tls.example", limit=10)
    top = store.top_domains(search="tls.example", limit=10)

    assert len(recent) == 1
    assert recent[0].domain == "tls.example"
    assert top[0]["domain"] == "tls.example"


def test_render_icap_include_scales_services_by_squid_workers_without_duplicate_uris(
    monkeypatch,
) -> None:
    _add_web_to_path()

    from services.squidctl import SquidController  # type: ignore

    monkeypatch.setenv("CICAP_PORT", "24000")
    monkeypatch.setenv("CICAP_AV_PORT", "24001")
    monkeypatch.setenv("SQUID_WORKERS", "3")

    ctl = SquidController()
    out = ctl._render_icap_include()

    assert out.count("icap_service adblock_req ") == 1
    assert out.count("icap_service adblock_req_2 ") == 1
    assert out.count("icap_service adblock_req_3 ") == 1
    assert out.count("icap://127.0.0.1:24000/adblockreq") == 1
    assert out.count("icap://127.0.0.1:24001/adblockreq") == 1
    assert out.count("icap://127.0.0.1:24002/adblockreq") == 1
    assert "icap://127.0.0.1:24003/avrespmod" in out
    assert "icap://127.0.0.1:24004/avrespmod" in out
    assert "icap://127.0.0.1:24005/avrespmod" in out
    assert "adaptation_service_set adblock_req_set adblock_req adblock_req_2 adblock_req_3" in out
    assert "adaptation_service_set av_resp_set av_resp av_resp_2 av_resp_3" in out
    assert (
        "acl icap_adblockable method GET HEAD CONNECT POST OPTIONS PUT PATCH DELETE"
        in out
    )


def test_render_icap_include_preserves_non_overlapping_explicit_av_base(
    monkeypatch,
) -> None:
    _add_web_to_path()

    from services.squid_core import SquidController  # type: ignore

    monkeypatch.setenv("CICAP_PORT", "24000")
    monkeypatch.setenv("CICAP_AV_PORT", "25000")
    monkeypatch.setenv("SQUID_WORKERS", "3")

    out = SquidController()._render_icap_include()

    assert "icap://127.0.0.1:24002/adblockreq" in out
    assert "icap://127.0.0.1:25000/avrespmod" in out
    assert "icap://127.0.0.1:25002/avrespmod" in out


def test_generate_icap_include_uses_supplied_workers_over_environment(
    monkeypatch, tmp_path
) -> None:
    _add_web_to_path()

    from services.squid_core import (  # type: ignore
        SquidController,
        _cached_icap_include_path,
    )

    include_path = tmp_path / "20-icap.conf"
    monkeypatch.setenv("SQUID_ICAP_INCLUDE_PATH", str(include_path))
    monkeypatch.setenv("CICAP_PORT", "26000")
    monkeypatch.setenv("CICAP_AV_PORT", "26001")
    monkeypatch.setenv("SQUID_WORKERS", "1")
    _cached_icap_include_path.cache_clear()

    ok, message = SquidController().apply_icap_scaling(3, "")

    assert ok, message
    out = include_path.read_text(encoding="utf-8")
    assert "icap_service adblock_req_3 " in out
    assert "icap://127.0.0.1:26002/adblockreq" in out
    assert "icap://127.0.0.1:26003/avrespmod" in out
    assert "adaptation_access adblock_req_set allow icap_adblockable" in out
    assert "adaptation_access adblock_req_set deny all" in out
    assert "adaptation_access adblock_req_set allow all" not in out
    assert "Accept-Encoding identity" not in out


def test_render_icap_include_makes_required_clamav_fail_closed(monkeypatch) -> None:
    _add_web_to_path()

    from services.squidctl import SquidController  # type: ignore

    monkeypatch.setenv("SQUID_WORKERS", "2")
    ctl = SquidController()
    out = ctl._render_icap_include("# BEGIN SQUID-UI CLAMAV SETTINGS\n# clamav_fail_mode: closed\n# END SQUID-UI CLAMAV SETTINGS\n")

    assert "icap_service av_req reqmod_precache icap://127.0.0.1:14002/avrespmod bypass=off" in out
    assert "icap_service av_req_2 reqmod_precache icap://127.0.0.1:14003/avrespmod bypass=off" in out
    assert "icap_service av_resp respmod_precache icap://127.0.0.1:14002/avrespmod bypass=off" in out
    assert "adaptation_service_set av_req_set av_req av_req_2" in out


def test_render_icap_include_keeps_body_methods_when_preview_is_disabled() -> None:
    _add_web_to_path()

    from services.squidctl import SquidController  # type: ignore

    ctl = SquidController()
    out = ctl._render_icap_include("icap_preview_enable off\n")

    adblock_acl = next(
        line
        for line in out.splitlines()
        if line.startswith("acl icap_adblockable method ")
    )
    assert (
        adblock_acl
        == "acl icap_adblockable method GET HEAD CONNECT POST OPTIONS PUT PATCH DELETE"
    )


def test_repo_template_includes_cache_first_defaults() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    text = (repo_root / "squid" / "squid.conf.template").read_text(encoding="utf-8")

    assert "# BEGIN SQUID-UI MANAGED SETTINGS" in text
    assert "# END SQUID-UI MANAGED SETTINGS" in text
    assert (
        "acl icap_adblockable method GET HEAD CONNECT POST OPTIONS PUT PATCH DELETE"
        in text
    )
    assert "acl icap_adblockable method GET HEAD CONNECT\n" not in text
    assert "hopeless_kid_revival_delay 3600 seconds" in text
    assert "cache_dir rock /var/spool/squid 10000 slot-size=32768" in text
    assert "store_dir_select_algorithm least-load" in text
    assert "cache_mem 256 MB" in text
    assert "memory_cache_mode always" in text
    assert "memory_cache_shared on" in text
    assert "shared_transient_entries_limit 16384" in text
    assert "cache_replacement_policy heap GDSF" in text
    assert "memory_replacement_policy heap GDSF" in text
    assert "cache_miss_revalidate on" in text
    assert "reload_into_ims off" in text
    assert "client_idle_pconn_timeout 120 seconds" in text
    assert "server_idle_pconn_timeout 60 seconds" in text
    assert "client_lifetime 86400 seconds" in text
    assert "pipeline_prefetch 0" in text
    assert "quick_abort_min 16 KB" in text
    assert "quick_abort_max 16 KB" in text
    assert "quick_abort_pct 95" in text
    assert "dns_packet_max 1232 bytes" in text
    assert "positive_dns_ttl 21600 seconds" in text
    assert "tls_outgoing_options min-version=1.2 options=NO_SSLv3" in text
    assert "request_header_max_size 64 KB" in text
    assert "client_db on" in text
    assert "buffered_logs off" in text
    assert "icap_206_enable on" in text
    assert "acl icap_range_request req_header Range .+" in text
    assert "acl icap_partial_response http_status 206" in text
    assert (
        "Antivirus scanning policy is materialized into /etc/squid/conf.d/20-icap.conf"
        in text
    )
    assert (
        "upload/download coverage, file blocking, size limits, and fail-open/closed"
        in text
    )
    assert "adaptation_send_client_ip on" in text
    assert "adaptation_send_username off" in text
    assert "icap_client_username_header X-Client-Username" in text
    assert "icap_client_username_encode off" in text
    assert "icap_preview_enable on" in text
    assert "sslproxy_session_ttl 600 seconds" in text
    assert "icap_service_failure_limit 10 in 30 seconds" in text
    assert "adaptation_service_iteration_limit 16" in text
    assert "icap_retry_limit 0" in text
    assert "store_avg_object_size 13 KB" in text
    assert "store_objects_per_bucket 20" in text
    assert "access_log stdio:/var/log/squid/access-observe.log diagnostic" in text
    assert "%{Content-Type}<h" in text
    assert "%{Server}<h" in text
    assert "%{Cf-Mitigated}<h" in text
    assert "%{Alt-Svc}<h" in text


def test_squid_controller_normalize_config_text_adds_default_observability_lines() -> (
    None
):
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
""".strip(),
    )

    assert "logformat diagnostic" in text
    assert "%{Content-Type}<h" in text
    assert "%{Server}<h" in text
    assert "%{Cf-Mitigated}<h" in text
    assert "%{Alt-Svc}<h" in text
    assert "logformat icapobserve" in text
    assert "access_log stdio:/var/log/squid/access-observe.log diagnostic" in text
    assert "/var/log/squid/access.log" not in text
    assert "include /etc/squid/conf.d/20-icap.conf" in text
    assert "include /etc/squid/conf.d/30-webfilter.conf" in text
    assert text.index("include /etc/squid/conf.d/30-webfilter.conf") < text.index(
        "http_access allow all"
    )
    assert "icap_log stdio:/var/log/squid/icap.log icapobserve" in text
    assert "note ssl_exception steam steam_sites" in text
    assert "note cache_bypass auth has_auth" in text
    assert "note cache_bypass cookie has_cookie" in text


def test_squid_controller_normalize_config_text_repositions_legacy_webfilter_include() -> (
    None
):
    _add_web_to_path()

    from services.squidctl import SquidController  # type: ignore

    ctl = SquidController()
    text = ctl.normalize_config_text(
        """
http_access allow all
include /etc/squid/conf.d/30-webfilter.conf
""".strip(),
    )

    assert text.count("include /etc/squid/conf.d/30-webfilter.conf") == 1
    assert text.index("include /etc/squid/conf.d/30-webfilter.conf") < text.index(
        "http_access allow all"
    )


def test_squid_controller_normalize_config_text_migrates_legacy_inline_icap_services_to_include() -> (
    None
):
    _add_web_to_path()

    from services.squidctl import SquidController  # type: ignore

    ctl = SquidController()
    text = ctl.normalize_config_text(
        """
icap_service adblock_req reqmod_precache icap://127.0.0.1:14000/adblockreq bypass=on
acl icap_adblockable method GET HEAD CONNECT POST OPTIONS PUT PATCH DELETE
adaptation_access adblock_req_set allow icap_adblockable
adaptation_access adblock_req_set deny all
http_access allow all
""".strip(),
    )

    assert "include /etc/squid/conf.d/20-icap.conf" in text
    assert "icap_service adblock_req" not in text
    assert "acl icap_adblockable method" not in text
    assert "adaptation_access adblock_req_set allow icap_adblockable" not in text
    assert "adaptation_access adblock_req_set allow all" not in text


def test_squid_controller_parses_new_perf_tunables() -> None:
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
reload_into_ims on
hopeless_kid_revival_delay 7200 seconds
server_idle_pconn_timeout 150 seconds
client_idle_pconn_timeout 75 seconds
connect_retries 2
forward_max_tries 12
dns_retransmit_interval 7 seconds
ipcache_low 80
ipcache_high 92
sslcrtd_children 12 startup=3 idle=2 queue-size=96
http_port 0.0.0.0:3128 ssl-bump dynamic_cert_mem_cache_size=256MB
http_port 0.0.0.0:3129 intercept
https_port 0.0.0.0:3130 intercept ssl-bump name=https_intercept dynamic_cert_mem_cache_size=256MB
acl https_intercept_listener myportname https_intercept
ssl_bump splice https_intercept_listener
dns_packet_max 1232 bytes
sslproxy_session_ttl 900
sslproxy_session_cache_size 16 MB
high_response_time_warning 2500
high_page_fault_warning 100
icap_206_enable off
adaptation_send_client_ip off
adaptation_send_username on
icap_client_username_header X-Auth-User
icap_client_username_encode on
icap_persistent_connections off
icap_default_options_ttl 120
icap_service_failure_limit 5 in 45 seconds
icap_service_revival_delay 90 seconds
adaptation_service_iteration_limit 8
force_request_body_continuation allow all
icap_retry allow all
icap_retry_limit 2
shared_memory_locking on
cpu_affinity_map process_numbers=1,2 cores=1,3
max_open_disk_fds 512
""".strip(),
    )

    assert options["cache_dir_type"] == "rock"
    assert options["cache_dir_rock_slot_size_kb"] == 32
    assert options["cache_dir_rock_swap_timeout_ms"] == 250
    assert options["cache_dir_rock_max_swap_rate"] == 1500
    assert options["memory_cache_mode"] == "disk"
    assert options["memory_cache_shared"] is False
    assert options["shared_transient_entries_limit"] == 65536
    assert options["cache_miss_revalidate"] is False
    assert options["reload_into_ims"] is True
    assert options["hopeless_kid_revival_delay_seconds"] == 7200
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
    assert options["explicit_proxy_port"] == 3128
    assert options["intercept_enabled"] is True
    assert options["intercept_port"] == 3129
    assert options["https_intercept_enabled"] is True
    assert options["https_intercept_port"] == 3130
    assert options["https_intercept_splice_only"] is True
    assert options["dns_packet_max"] == 1232
    assert options["sslproxy_session_ttl_seconds"] == 900
    assert options["sslproxy_session_cache_size_mb"] == 16
    assert options["high_response_time_warning_ms"] == 2500
    assert options["high_page_fault_warning"] == 100
    assert options["icap_206_enable"] is False
    assert options["icap_send_client_ip"] is False
    assert options["icap_send_client_username"] is True
    assert options["icap_client_username_header"] == "X-Auth-User"
    assert options["icap_client_username_encode"] is True
    assert options["icap_persistent_connections"] is False
    assert options["icap_default_options_ttl_seconds"] == 120
    assert options["icap_service_failure_limit"] == 5
    assert options["icap_service_failure_limit_window_seconds"] == 45
    assert options["icap_service_revival_delay_seconds"] == 90
    assert options["adaptation_service_iteration_limit"] == 8
    assert (
        options["force_request_body_continuation_rules_text"]
        == "force_request_body_continuation allow all"
    )
    assert options["icap_retry_rules_text"] == "icap_retry allow all"
    assert options["icap_retry_limit"] == 2
    assert options["shared_memory_locking"] is True
    assert options["cpu_affinity_map"] == "process_numbers=1,2 cores=1,3"
    assert options["max_open_disk_fds"] == 512


def test_squid_controller_network_lines_include_https_intercept_ports() -> None:
    _add_web_to_path()

    from services.squidctl import SquidController  # type: ignore

    ctl = SquidController()

    lines = ctl.get_network_lines(
        """
# listener directives
http_port 0.0.0.0:3128 ssl-bump dynamic_cert_mem_cache_size=256MB
http_port 0.0.0.0:3129 intercept
https_port 0.0.0.0:3130 intercept ssl-bump name=https_intercept dynamic_cert_mem_cache_size=256MB
acl https_intercept_listener myportname https_intercept
client_lifetime 1 day
""".strip(),
    )

    assert lines == [
        "http_port 0.0.0.0:3128 ssl-bump dynamic_cert_mem_cache_size=256MB",
        "http_port 0.0.0.0:3129 intercept",
        "https_port 0.0.0.0:3130 intercept ssl-bump name=https_intercept dynamic_cert_mem_cache_size=256MB",
        "client_lifetime 1 day",
    ]


def test_squid_controller_generate_config_applies_new_perf_tunables(tmp_path) -> None:
    _add_web_to_path()

    from services.squidctl import SquidController  # type: ignore

    repo_root = Path(__file__).resolve().parents[2]
    template_path = tmp_path / "squid.conf.template"
    template_path.write_text(
        (repo_root / "squid" / "squid.conf.template").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

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
            "reload_into_ims_on": True,
            "hopeless_kid_revival_delay_seconds": 7200,
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
            "high_response_time_warning_ms": 2500,
            "high_page_fault_warning": 100,
            "icap_206_enable_on": False,
            "icap_send_client_ip_on": False,
            "icap_send_client_username_on": True,
            "icap_client_username_header": "X-Auth-User",
            "icap_client_username_encode_on": True,
            "icap_persistent_connections_on": False,
            "icap_default_options_ttl_seconds": 120,
            "icap_service_failure_limit": 5,
            "icap_service_failure_limit_window_seconds": 45,
            "icap_service_revival_delay_seconds": 90,
            "adaptation_service_iteration_limit": 8,
            "force_request_body_continuation_rules_text": "force_request_body_continuation allow all",
            "icap_retry_rules_text": "icap_retry allow all",
            "icap_retry_limit": 2,
            "memory_pools_limit_mb": "none",
            "shared_memory_locking_on": True,
            "cpu_affinity_map": "process_numbers=1,2 cores=1,3",
            "max_open_disk_fds": 512,
            "cache_miss_revalidate_on": False,
            "icap_preview_enable_on": True,
        },
    )

    assert "# BEGIN SQUID-UI MANAGED SETTINGS" in rendered
    assert "# END SQUID-UI MANAGED SETTINGS" in rendered
    assert "cache_dir ufs /var/spool/squid 10000 32 512" in rendered
    assert "memory_cache_mode disk" in rendered
    assert "memory_cache_shared off" in rendered
    assert "shared_transient_entries_limit 65536" in rendered
    assert "reload_into_ims on" in rendered
    assert "hopeless_kid_revival_delay 7200 seconds" in rendered
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
    assert "high_response_time_warning 2500" in rendered
    assert "high_page_fault_warning 100" in rendered
    assert "icap_206_enable off" in rendered
    assert "adaptation_send_client_ip off" in rendered
    assert "adaptation_send_username on" in rendered
    assert "icap_client_username_header X-Auth-User" in rendered
    assert "icap_client_username_encode on" in rendered
    assert "icap_persistent_connections off" in rendered
    assert "icap_default_options_ttl 120" in rendered
    assert "icap_service_failure_limit 5 in 45 seconds" in rendered
    assert "icap_service_revival_delay 90 seconds" in rendered
    assert "adaptation_service_iteration_limit 8" in rendered
    assert "force_request_body_continuation allow all" in rendered
    assert "icap_retry allow all" in rendered
    assert "icap_retry_limit 2" in rendered
    assert "memory_pools_limit none" in rendered
    assert "shared_memory_locking on" in rendered
    assert "cpu_affinity_map process_numbers=1,2 cores=1,3" in rendered
    assert "max_open_disk_fds 512" in rendered
    assert "cache_miss_revalidate off" in rendered
    assert "icap_preview_enable on" in rendered
    assert "icap_preview_size 128 KB" in rendered
    assert "http_upgrade_request_protocols websocket deny all" in rendered
    assert "http_upgrade_request_protocols OTHER deny all" in rendered
    assert "access_log stdio:/var/log/squid/access-observe.log diagnostic" in rendered
    assert "cache_log stdio:/var/log/squid/cache.log" in rendered


def test_squid_controller_generate_config_adds_optional_intercept_listener(
    tmp_path,
) -> None:
    _add_web_to_path()

    from services.squid_config_forms import build_template_options  # type: ignore
    from services.squidctl import SquidController  # type: ignore

    repo_root = Path(__file__).resolve().parents[2]
    template_path = tmp_path / "squid.conf.template"
    template_path.write_text(
        (repo_root / "squid" / "squid.conf.template").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    ctl = SquidController(squid_conf_path=str(tmp_path / "squid.conf"))
    ctl.squid_conf_template_path = str(template_path)
    options = build_template_options(
        {
            "explicit_proxy_port": 8080,
            "intercept_enabled": True,
            "intercept_port": 8081,
        },
        max_workers=4,
    )

    rendered = ctl.generate_config_from_template(options)

    assert "http_port 0.0.0.0:8080 ssl-bump" in rendered
    assert "# BEGIN SQUID-UI INTERCEPT LISTENER" in rendered
    assert "http_port 0.0.0.0:8081 intercept" in rendered
    assert "SOCKS" not in rendered


def test_squid_controller_generate_config_parses_string_false_booleans(
    tmp_path,
) -> None:
    _add_web_to_path()

    from services.squidctl import SquidController  # type: ignore

    repo_root = Path(__file__).resolve().parents[2]
    template_path = tmp_path / "squid.conf.template"
    template_path.write_text(
        (repo_root / "squid" / "squid.conf.template").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    ctl = SquidController(squid_conf_path=str(tmp_path / "squid.conf"))
    ctl.squid_conf_template_path = str(template_path)

    rendered = ctl.generate_config_from_template(
        {
            "intercept_enabled_on": "false",
            "https_intercept_enabled_on": "0",
            "https_intercept_splice_only_on": "true",
            "pipeline_prefetch_on": "off",
            "pipeline_prefetch_count": 9,
            "memory_pools_on": "no",
            "icap_enable_on": "false",
        },
    )

    assert "# BEGIN SQUID-UI INTERCEPT LISTENER" not in rendered
    assert "# BEGIN SQUID-UI HTTPS INTERCEPT LISTENER" not in rendered
    assert "ssl_bump splice https_intercept_listener" not in rendered
    assert "pipeline_prefetch 0" in rendered
    assert "memory_pools off" in rendered
    assert "icap_enable off" in rendered


def test_squid_controller_generate_config_adds_optional_https_intercept_listener(
    tmp_path,
) -> None:
    _add_web_to_path()

    from services.squid_config_forms import build_template_options  # type: ignore
    from services.squidctl import SquidController  # type: ignore

    repo_root = Path(__file__).resolve().parents[2]
    template_path = tmp_path / "squid.conf.template"
    template_path.write_text(
        (repo_root / "squid" / "squid.conf.template").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    ctl = SquidController(squid_conf_path=str(tmp_path / "squid.conf"))
    ctl.squid_conf_template_path = str(template_path)
    options = build_template_options(
        {
            "explicit_proxy_port": 8080,
            "intercept_enabled": True,
            "intercept_port": 8081,
            "https_intercept_enabled": True,
            "https_intercept_port": 8082,
            "https_intercept_splice_only": True,
            "dynamic_cert_mem_cache_size_mb": 256,
        },
        max_workers=4,
    )

    rendered = ctl.generate_config_from_template(options)

    assert "http_port 0.0.0.0:8080 ssl-bump" in rendered
    assert "http_port 0.0.0.0:8081 intercept" in rendered
    assert "# BEGIN SQUID-UI HTTPS INTERCEPT LISTENER" in rendered
    assert "https_port 0.0.0.0:8082 intercept ssl-bump" in rendered
    assert "name=https_intercept" in rendered
    assert "dynamic_cert_mem_cache_size=256MB" in rendered
    assert "acl https_intercept_listener myportname https_intercept" in rendered
    assert "ssl_bump splice https_intercept_listener" in rendered
    assert (
        rendered.index("ssl_bump peek step1")
        < rendered.index("ssl_bump splice https_intercept_listener")
        < rendered.index("ssl_bump stare step2")
    )


def test_squid_controller_resolves_three_way_listener_port_collision(tmp_path) -> None:
    _add_web_to_path()

    from services.squid_config_forms import build_template_options  # type: ignore
    from services.squidctl import SquidController  # type: ignore

    repo_root = Path(__file__).resolve().parents[2]
    template_path = tmp_path / "squid.conf.template"
    template_path.write_text(
        (repo_root / "squid" / "squid.conf.template").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    ctl = SquidController(squid_conf_path=str(tmp_path / "squid.conf"))
    ctl.squid_conf_template_path = str(template_path)
    options = build_template_options(
        {
            "explicit_proxy_port": 3130,
            "intercept_enabled": True,
            "intercept_port": 3131,
            "https_intercept_enabled": True,
            "https_intercept_port": 3131,
        },
        max_workers=4,
    )

    rendered = ctl.generate_config_from_template(options)

    assert "http_port 0.0.0.0:3130 ssl-bump" in rendered
    assert "http_port 0.0.0.0:3131 intercept" in rendered
    assert "https_port 0.0.0.0:3132 intercept ssl-bump" in rendered


def test_squid_controller_avoids_unmanaged_listener_port_collision(tmp_path) -> None:
    _add_web_to_path()

    from services.squid_config_forms import build_template_options  # type: ignore
    from services.squidctl import SquidController  # type: ignore

    repo_root = Path(__file__).resolve().parents[2]
    template_text = (repo_root / "squid" / "squid.conf.template").read_text(
        encoding="utf-8",
    )
    template_path = tmp_path / "squid.conf.template"
    template_path.write_text(
        template_text.replace(
            "# Allow cache manager access from localhost",
            "http_port 127.0.0.1:8082\n\n# Allow cache manager access from localhost",
        ),
        encoding="utf-8",
    )

    ctl = SquidController(squid_conf_path=str(tmp_path / "squid.conf"))
    ctl.squid_conf_template_path = str(template_path)
    options = build_template_options(
        {
            "explicit_proxy_port": 8080,
            "intercept_enabled": True,
            "intercept_port": 8081,
            "https_intercept_enabled": True,
            "https_intercept_port": 8082,
        },
        max_workers=4,
    )

    rendered = ctl.generate_config_from_template(options)

    assert "http_port 127.0.0.1:8082" in rendered
    assert "https_port 0.0.0.0:8082 intercept ssl-bump" not in rendered
    assert "https_port 0.0.0.0:8083 intercept ssl-bump" in rendered


def test_squid_controller_https_intercept_listener_does_not_splice_by_default(
    tmp_path,
) -> None:
    _add_web_to_path()

    from services.squid_config_forms import build_template_options  # type: ignore
    from services.squidctl import SquidController  # type: ignore

    repo_root = Path(__file__).resolve().parents[2]
    template_path = tmp_path / "squid.conf.template"
    template_path.write_text(
        (repo_root / "squid" / "squid.conf.template").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    ctl = SquidController(squid_conf_path=str(tmp_path / "squid.conf"))
    ctl.squid_conf_template_path = str(template_path)
    options = build_template_options(
        {
            "https_intercept_enabled": True,
            "https_intercept_port": 8082,
        },
        max_workers=4,
    )

    rendered = ctl.generate_config_from_template(options)

    assert "https_port 0.0.0.0:8082 intercept ssl-bump" in rendered
    assert "name=https_intercept" in rendered
    assert "ssl_bump splice https_intercept_listener" not in rendered


def test_squid_controller_health_details_include_https_intercept_listener() -> None:
    _add_web_to_path()

    from services.squid_core import SquidController  # type: ignore

    config_text = """
http_port 0.0.0.0:3128 ssl-bump \\
    cert=/etc/squid/ssl/certs/ca.crt \\
    key=/etc/squid/ssl/certs/ca.key
# BEGIN SQUID-UI HTTPS INTERCEPT LISTENER
https_port 0.0.0.0:3130 intercept ssl-bump \\
    name=https_intercept \\
    cert=/etc/squid/ssl/certs/ca.crt \\
    key=/etc/squid/ssl/certs/ca.key
# END SQUID-UI HTTPS INTERCEPT LISTENER
"""

    controller = SquidController.__new__(SquidController)

    listeners = controller._http_listener_details(config_text)

    assert listeners == (
        {"port": 3128, "mode": "explicit"},
        {"port": 3130, "mode": "https-intercept"},
    )


def test_ssl_errors_store_suggests_review_only_exclusion_candidates(tmp_path) -> None:
    _add_web_to_path()
    configure_test_mysql_env(tmp_path / "ssl-errors-candidates")

    from services.ssl_errors_store import SslErrorsStore  # type: ignore

    store = SslErrorsStore(cache_log_path=str(tmp_path / "cache.log"))
    store.init_db()
    store.ingest_line(
        "2026/04/18 04:04:40| CONNECT gateway.discord.gg:443 error detail: SQUID_TLS_ERR_ACCEPT+TLS_LIB_ERR=A000119+TLS_IO_ERR=1"
    )
    store.ingest_line(
        "2026/04/18 04:04:41| CONNECT gateway.discord.gg:443 error detail: SQUID_TLS_ERR_ACCEPT+TLS_LIB_ERR=A000119+TLS_IO_ERR=1"
    )
    store.ingest_line(
        "2026/04/18 04:04:42| CONNECT gateway.discord.gg:443 error detail: SQUID_TLS_ERR_ACCEPT+TLS_LIB_ERR=A000119+TLS_IO_ERR=1"
    )

    candidates = store.suggest_exclusion_candidates(min_events=3)

    assert candidates
    assert candidates[0]["domain"] == "gateway.discord.gg"
    assert candidates[0]["total"] >= 3
    assert "TLS_CLIENT_ACCEPT" in candidates[0]["categories"]

    searched_candidates = store.suggest_exclusion_candidates(
        search="discord", min_events=3
    )

    assert searched_candidates
    assert searched_candidates[0]["domain"] == "gateway.discord.gg"


def test_sslfilter_materialized_config_deduplicates_domains_covered_by_wildcards(
    tmp_path,
) -> None:
    _add_web_to_path()
    configure_test_mysql_env(tmp_path / "sslfilter-domain-dedupe")

    from services.sslfilter_store import SslFilterStore  # type: ignore

    store = SslFilterStore(
        squid_include_path=str(tmp_path / "10-sslfilter.conf"),
        nobump_list_path=str(tmp_path / "nobump.txt"),
        nocache_src_list_path=str(tmp_path / "nocache-src.txt"),
    )
    store.init_db()
    for domain in [
        "example.com",
        "*.example.com",
        "api.example.net",
        "api.example.net",
    ]:
        assert store.add_domain("nobump", domain)[0] is True
    for domain in [
        "cache.example",
        "*.cache.example",
        "cdn.example.net",
        "cdn.example.net",
    ]:
        assert store.add_domain("nocache", domain)[0] is True

    rendered = store.render_materialized_state().include_text

    ssl_acl_line = next(
        line
        for line in rendered.splitlines()
        if line.startswith("acl sslfilter_nobump_domains ssl::server_name")
    )
    cache_acl_line = next(
        line
        for line in rendered.splitlines()
        if line.startswith("acl sslfilter_nocache_domains dstdomain")
    )
    ssl_values = ssl_acl_line.split()[3:]
    cache_values = cache_acl_line.split()[3:]
    assert ".example.com" in ssl_values
    assert "example.com" not in ssl_values
    assert ssl_values.count("api.example.net") == 1
    assert ".cache.example" in cache_values
    assert "cache.example" not in cache_values
    assert cache_values.count("cdn.example.net") == 1
    assert (
        "note ssl_exception sslfilter_nobump_domain sslfilter_nobump_domains"
        in rendered
    )
    assert (
        "note cache_bypass sslfilter_nocache_domain sslfilter_nocache_domains"
        in rendered
    )
    assert (
        "note ssl_exception sslfilter_nobump_domains sslfilter_nobump_domain"
        not in rendered
    )
    assert (
        "note cache_bypass sslfilter_nocache_domains sslfilter_nocache_domain"
        not in rendered
    )
    assert "ssl_bump splice sslfilter_nobump_domains" in rendered
    assert "cache deny sslfilter_nocache_domains" in rendered


def test_compatibility_presets_include_source_backed_collaboration_sslfilter_domains(
    tmp_path,
) -> None:
    _add_web_to_path()
    configure_test_mysql_env(tmp_path / "compatibility-presets")

    from services.ssl_compatibility_presets import COMPATIBILITY_PRESETS  # type: ignore
    from services.sslfilter_store import get_sslfilter_store  # type: ignore

    presets = {preset.id: preset for preset in COMPATIBILITY_PRESETS}

    assert "microsoft-cloud" in presets
    assert "webex" in presets
    assert "zoom" in presets
    assert "google-meet" in presets
    assert "adobe-cloud" in presets
    assert "apple-cloud" in presets
    assert "developer-collaboration" in presets
    assert "identity-mfa" in presets
    assert "steam" in presets
    assert "*.steampowered.com" in presets["steam"].domains
    assert "cdn.cloudflare.steamstatic.com" in presets["steam"].domains
    assert "*.teams.microsoft.com" in presets["microsoft-cloud"].domains
    assert "*.download.windowsupdate.com" in presets["microsoft-cloud"].domains
    assert "*.githubassets.com" in presets["microsoft-cloud"].domains
    assert "*.webex.com" in presets["webex"].domains
    assert "*.zoom.us" in presets["zoom"].domains
    assert "workspace.turns.goog" in presets["google-meet"].domains
    assert "*.googleapis.com" in presets["google-meet"].domains
    assert "*.adobe.com" in presets["adobe-cloud"].domains
    assert "ims-na1.adobelogin.com" in presets["adobe-cloud"].domains
    assert "updates.cdn-apple.com" in presets["apple-cloud"].domains
    assert "*.push.apple.com" in presets["apple-cloud"].domains
    assert (
        "copilot-proxy.githubusercontent.com"
        in presets["developer-collaboration"].domains
    )
    assert "*.githubassets.com" in presets["developer-collaboration"].domains
    assert "wss-primary.slack.com" in presets["developer-collaboration"].domains
    assert "*.atl-paas.net" in presets["developer-collaboration"].domains
    assert "*.okta.com" in presets["identity-mfa"].domains

    store = get_sslfilter_store()
    added, attempted, error = store.install_compatibility_preset("all")

    assert attempted == sum(len(preset.domains) for preset in COMPATIBILITY_PRESETS)
    assert added > 200
    assert error == ""


def test_github_compatibility_presets_cover_githubassets_domain() -> None:
    _add_web_to_path()
    from services.ssl_compatibility_presets import COMPATIBILITY_PRESETS  # type: ignore

    presets = {preset.id: preset for preset in COMPATIBILITY_PRESETS}

    for preset_id in ("microsoft-cloud", "developer-collaboration"):
        domains = presets[preset_id].domains
        assert "githubassets.com" in domains
        assert "*.githubassets.com" in domains


def test_squid_controller_default_ssl_bump_uses_peek_stare_then_bump(tmp_path) -> None:
    _add_web_to_path()

    from services.squid_config_forms import build_template_options  # type: ignore
    from services.squidctl import SquidController  # type: ignore

    repo_root = Path(__file__).resolve().parents[2]
    template = tmp_path / "squid.conf.template"
    template.write_text(
        (repo_root / "squid" / "squid.conf.template").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    controller = SquidController(squid_conf_path=str(tmp_path / "squid.conf"))
    controller.squid_conf_template_path = str(template)

    rendered = controller.generate_config_from_template(
        build_template_options({}, max_workers=4)
    )

    assert "acl step2 at_step SslBump2" in rendered
    assert "acl step3 at_step SslBump3" in rendered
    assert (
        rendered.index("ssl_bump peek step1")
        < rendered.index("ssl_bump stare step2")
        < rendered.index("ssl_bump bump step3")
    )
    assert "ssl_bump bump all" not in rendered
    assert "steam_sites" not in rendered


def test_webfilter_materialized_helper_name_tracks_webcat_revision(tmp_path) -> None:
    _add_web_to_path()
    configure_test_mysql_env(tmp_path / "webfilter-helper-version")

    from services.db import connect  # type: ignore
    from services.webfilter_store import WebFilterStore  # type: ignore

    store = WebFilterStore(
        squid_include_path=str(tmp_path / "30-webfilter.conf"),
        whitelist_path=str(tmp_path / "webfilter_whitelist.txt"),
    )
    store.init_db()
    store.set_settings(enabled=True, source_url="", blocked_categories=["adult"])

    with connect() as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS webcat_meta (k VARCHAR(64) PRIMARY KEY, v LONGTEXT NOT NULL)"
        )
        conn.execute(
            "INSERT INTO webcat_meta(k,v) VALUES('built_ts','100') ON DUPLICATE KEY UPDATE v=VALUES(v)"
        )

    first = store.render_materialized_state().include_text
    assert "external_acl_type webcat_" in first
    assert "acl webfilter_block_adult external webcat_" in first

    with connect() as conn:
        conn.execute(
            "INSERT INTO webcat_meta(k,v) VALUES('built_ts','200') ON DUPLICATE KEY UPDATE v=VALUES(v)"
        )

    second = store.render_materialized_state().include_text
    assert second != first
    assert "acl webfilter_block_adult external webcat_" in second


def test_adblock_reqmod_runtime_uses_sqlite_service_not_c_icap_url_check() -> None:
    dockerfile = Path("docker/Dockerfile.proxy").read_text(encoding="utf-8")
    entrypoint = Path("docker/entrypoint.sh").read_text(encoding="utf-8")

    assert "web/tools/adblock_icap_server.py" in dockerfile
    assert "COPY docker/adblock_req.conf /etc/adblock_req.conf" not in dockerfile
    assert "python3 /app/tools/adblock_icap_server.py" in entrypoint
    assert "request_lookup.sqlite" in entrypoint
    assert "c-icap-adblock.conf" not in entrypoint
    assert "srv_url_check.so" not in entrypoint


def test_repo_template_orders_generated_policy_includes_before_enforcement_hooks() -> (
    None
):
    template = Path("squid/squid.conf.template").read_text(encoding="utf-8")

    assert template.count("include /etc/squid/conf.d/20-icap.conf") == 1
    assert template.count("include /etc/squid/conf.d/30-webfilter.conf") == 1
    assert (
        "acl icap_adblockable method GET HEAD CONNECT POST OPTIONS PUT PATCH DELETE"
        in template
    )
    assert template.index("include /etc/squid/conf.d/20-icap.conf") < template.index(
        "adaptation_access adblock_req_set allow icap_adblockable"
    )
    assert template.index(
        "include /etc/squid/conf.d/30-webfilter.conf"
    ) < template.index("http_access allow all")


def test_squid_normalize_migrates_stale_inline_policy_plumbing_to_generated_includes() -> (
    None
):
    _add_web_to_path()
    from services.squid_core import SquidController  # type: ignore

    controller = SquidController.__new__(SquidController)
    legacy = "http_port 3128\nicap_service adblock_req_old reqmod_precache icap://127.0.0.1:14000/adblockreq bypass=on\nicap_service av_req reqmod_precache icap://127.0.0.1:14001/avrespmod bypass=on\nicap_service av_resp respmod_precache icap://127.0.0.1:14001/avrespmod bypass=on\nadaptation_service_set adblock_req_set adblock_req_old\nadaptation_service_set av_req_set av_req\nadaptation_service_set av_resp_set av_resp\nacl file_security_upload_methods method POST PUT PATCH\nacl file_security_download_methods method GET HEAD\nacl file_security_risky_path urlpath_regex -i \\.(exe|dll)($|[?#])\nadaptation_access adblock_req_set allow all\nadaptation_access adblock_req_set allow icap_adblockable\nadaptation_access adblock_req_set deny all\nadaptation_access av_req_set allow file_security_upload_methods\nadaptation_access av_req_set deny all\nadaptation_access av_resp_set allow file_security_download_methods\nadaptation_access av_resp_set deny all\nhttp_access allow manager localhost\nhttp_access deny manager\nhttp_access deny file_security_risky_path\nhttp_access allow all\ninclude /etc/squid/conf.d/30-webfilter.conf\n"

    normalized = controller.normalize_config_text(legacy)

    assert normalized.count("include /etc/squid/conf.d/20-icap.conf") == 1
    assert normalized.count("include /etc/squid/conf.d/30-webfilter.conf") == 1
    assert "icap_service adblock_req_old" not in normalized
    assert "adaptation_service_set adblock_req_set adblock_req_old" not in normalized
    assert "adaptation_service_set av_req_set av_req" not in normalized
    assert "adaptation_service_set av_resp_set av_resp" not in normalized
    assert "acl icap_adblockable method" not in normalized
    assert "acl file_security_upload_methods" not in normalized
    assert "acl file_security_download_methods" not in normalized
    assert "acl file_security_risky_path" not in normalized
    assert "adaptation_access adblock_req_set allow icap_adblockable" not in normalized
    assert "adaptation_access adblock_req_set allow all" not in normalized
    assert "adaptation_access adblock_req_set deny all" not in normalized
    assert (
        "adaptation_access av_req_set allow file_security_upload_methods"
        not in normalized
    )
    assert "adaptation_access av_req_set deny all" not in normalized
    assert (
        "adaptation_access av_resp_set allow file_security_download_methods"
        not in normalized
    )
    assert "adaptation_access av_resp_set deny all" not in normalized
    assert "http_access deny file_security_risky_path" not in normalized
    assert normalized.index(
        "include /etc/squid/conf.d/20-icap.conf"
    ) < normalized.index("http_access allow manager localhost")
    assert normalized.index(
        "include /etc/squid/conf.d/30-webfilter.conf"
    ) < normalized.index("http_access allow manager localhost")
    assert normalized.index(
        "include /etc/squid/conf.d/30-webfilter.conf"
    ) < normalized.index("http_access allow all")


def test_squid_normalize_migrates_hyphenated_versioned_adblock_service() -> None:
    _add_web_to_path()
    from services.squid_core import SquidController  # type: ignore

    controller = SquidController.__new__(SquidController)
    legacy = (
        "http_port 3128\n"
        "icap_service adblock_req_rev-2026.06 reqmod_precache "
        "icap://127.0.0.1:14000/adblockreq bypass=on\n"
        "adaptation_service_set adblock_req_set adblock_req_rev-2026.06\n"
        "adaptation_access adblock_req_set allow icap_adblockable\n"
        "adaptation_access adblock_req_set deny all\n"
        "http_access allow all\n"
    )

    normalized = controller.normalize_config_text(legacy)

    assert normalized.count("include /etc/squid/conf.d/20-icap.conf") == 1
    assert "icap_service adblock_req_rev-2026.06" not in normalized
    assert "adaptation_service_set adblock_req_set adblock_req_rev-2026.06" not in normalized
    assert "adaptation_access adblock_req_set allow icap_adblockable" not in normalized
    assert "adaptation_access adblock_req_set deny all" not in normalized
    assert normalized.index(
        "include /etc/squid/conf.d/20-icap.conf"
    ) < normalized.index("http_access allow all")


def test_squid_icap_include_versions_adblock_service_name_not_uri() -> None:
    _add_web_to_path()
    from services.squid_core import SquidController  # type: ignore

    controller = SquidController.__new__(SquidController)
    controller._adblock_icap_revision_token = ""
    unversioned = controller._render_icap_include("")
    assert (
        "icap_service adblock_req reqmod_precache icap://127.0.0.1:14000/adblockreq bypass=on"
        in unversioned
    )
    assert "adaptation_service_set adblock_req_set adblock_req" in unversioned

    controller.set_adblock_icap_revision_token("abc123:unsafe value")
    versioned = controller._render_icap_include("")
    assert (
        "icap_service adblock_req_abc123unsafevalue reqmod_precache icap://127.0.0.1:14000/adblockreq bypass=on"
        in versioned
    )
    assert (
        "adaptation_service_set adblock_req_set adblock_req_abc123unsafevalue"
        in versioned
    )
    assert "adblockreq?rev=" not in versioned
    assert (
        "acl icap_adblockable method GET HEAD CONNECT POST OPTIONS PUT PATCH DELETE"
        in versioned
    )
    assert "acl adblock_regex_allow url_regex -i" not in versioned
    assert "acl adblock_regex_block url_regex -i" not in versioned
    assert "http_access deny adblock_regex_block" not in versioned


def test_squid_icap_include_never_renders_legacy_regex_shortcut() -> None:
    _add_web_to_path()
    from services.squid_core import SquidController  # type: ignore

    controller = SquidController.__new__(SquidController)
    controller._adblock_icap_revision_token = ""
    rendered = controller._render_icap_include("")

    assert "adblock_regex_allow" not in rendered
    assert "adblock_regex_block" not in rendered
    assert "http_access deny adblock_regex_block" not in rendered
