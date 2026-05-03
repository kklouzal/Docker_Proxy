from __future__ import annotations

import os
import re
from typing import Any, Dict, Optional

import logging

from services.logutil import log_exception_throttled
from services.squid_core import SquidController as _CoreSquidController
from services.squid_config_forms import DEFAULT_CACHE_POLICY_RULES, DEFAULT_REFRESH_PATTERNS


logger = logging.getLogger(__name__)

try:
    from services.exclusions_store import Exclusions, PRIVATE_NETS_V4
except Exception:  # pragma: no cover
    Exclusions = None  # type: ignore[assignment]
    PRIVATE_NETS_V4 = []  # type: ignore[assignment]


class SquidController(_CoreSquidController):
    # -------------------------------------------------------------------------
    # Input validation helpers for config injection prevention
    # -------------------------------------------------------------------------
    _MANAGED_SETTINGS_START = "# BEGIN SQUID-UI MANAGED SETTINGS"
    _MANAGED_SETTINGS_END = "# END SQUID-UI MANAGED SETTINGS"
    _HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$")
    _IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    _IPV6_SIMPLE_RE = re.compile(r"^[a-fA-F0-9:]+$")
    _CPU_AFFINITY_RE = re.compile(r"^[A-Za-z0-9_,= ]+$")

    def __init__(self, squid_conf_path: str = "/etc/squid/squid.conf", *, cmd_run=None):
        super().__init__(squid_conf_path=squid_conf_path, cmd_run=cmd_run or __import__("subprocess").run)
        self.squid_conf_template_path = "/etc/squid/squid.conf.template"
        if (not os.path.exists(self.squid_conf_template_path)) and os.path.exists("/squid/squid.conf.template"):
            self.squid_conf_template_path = "/squid/squid.conf.template"

    def _sanitize_single_line(self, value: str, field_name: str) -> str:
        if not value:
            return ""
        clean = value.strip()
        if "\n" in clean or "\r" in clean:
            raise ValueError(f"{field_name} must not contain newlines")
        return clean

    def _validate_hostname(self, value: str, field_name: str = "hostname") -> str:
        clean = self._sanitize_single_line(value, field_name)
        if not clean:
            return ""
        if len(clean) > 253:
            raise ValueError(f"{field_name} too long (max 253 characters)")
        if not self._HOSTNAME_RE.match(clean):
            raise ValueError(f"{field_name} contains invalid characters")
        return clean

    def _validate_hosts_file_path(self, value: str, field_name: str = "hosts_file") -> str:
        clean = self._sanitize_single_line(value, field_name)
        if not clean:
            return ""
        if clean.lower() == "none":
            return "none"
        forbidden = set('|;&$`"\'\\<>(){}[]!#~')
        if any(char in clean for char in forbidden):
            raise ValueError(f"{field_name} contains forbidden characters")
        if not clean.startswith("/"):
            raise ValueError(f"{field_name} must be an absolute path")
        return clean

    def _validate_append_domain(self, value: str, field_name: str = "append_domain") -> str:
        clean = self._sanitize_single_line(value, field_name)
        if not clean:
            return ""
        if not clean.startswith("."):
            raise ValueError(f"{field_name} must begin with a dot")
        return clean

    def _validate_dns_nameservers(self, value: str, field_name: str = "dns_nameservers") -> str:
        clean = self._sanitize_single_line(value, field_name)
        if not clean:
            return ""
        for part in clean.split():
            if self._IP_RE.match(part):
                for octet in part.split("."):
                    if int(octet) > 255:
                        raise ValueError(f"{field_name} contains invalid IP address: {part}")
            elif self._IPV6_SIMPLE_RE.match(part):
                pass
            elif self._HOSTNAME_RE.match(part):
                pass
            else:
                raise ValueError(f"{field_name} contains invalid entry: {part}")
        return clean

    def _validate_choice(self, value: str, allowed: tuple[str, ...], field_name: str) -> str:
        clean = self._sanitize_single_line(value, field_name).lower()
        if clean not in allowed:
            raise ValueError(f"{field_name} must be one of: {', '.join(allowed)}")
        return clean

    def _validate_cpu_affinity_map(self, value: str, field_name: str = "cpu_affinity_map") -> str:
        clean = self._sanitize_single_line(value, field_name)
        if not clean:
            return ""
        if not self._CPU_AFFINITY_RE.match(clean):
            raise ValueError(f"{field_name} contains invalid characters")
        return clean

    def _validate_single_line_value(self, value: str, field_name: str) -> str:
        return self._sanitize_single_line(value, field_name)

    def _extract_managed_subblock(self, text: str, block_name: str) -> Optional[str]:
        pattern = re.compile(
            rf"^\s*# BEGIN SQUID-UI BLOCK: {re.escape(block_name)}\s*$\n?(.*?)^\s*# END SQUID-UI BLOCK: {re.escape(block_name)}\s*$",
            re.M | re.S,
        )
        match = pattern.search(text or "")
        if not match:
            return None
        return (match.group(1) or "").strip("\n")

    def _render_managed_subblock(self, block_name: str, content: str) -> str:
        body = (content or "").replace("\r\n", "\n").replace("\r", "\n").strip("\n")
        parts = [f"# BEGIN SQUID-UI BLOCK: {block_name}"]
        if body:
            parts.append(body)
        parts.append(f"# END SQUID-UI BLOCK: {block_name}")
        return "\n".join(parts)

    def _replace_managed_settings_block(self, text: str, rendered_block: str) -> str:
        pattern = re.compile(
            rf"^\s*{re.escape(self._MANAGED_SETTINGS_START)}\s*$.*?^\s*{re.escape(self._MANAGED_SETTINGS_END)}\s*$\n?",
            re.M | re.S,
        )
        rendered = rendered_block.rstrip() + "\n"
        if pattern.search(text):
            return pattern.sub(rendered, text, count=1)
        marker = "# Log settings"
        if marker in text:
            return text.replace(marker, rendered + "\n" + marker, 1)
        return text.rstrip() + "\n\n" + rendered

    def _normalize_multiline_text(self, value: Any) -> str:
        return str(value or "").replace("\r\n", "\n").replace("\r", "\n").strip("\n")

    def _render_managed_settings(self, options: Dict[str, Any]) -> str:
        def int_value(name: str, default: int, *, minimum: int | None = None, maximum: int | None = None) -> int:
            raw = options.get(name)
            try:
                value = int(str(raw).strip()) if raw is not None and str(raw).strip() != "" else int(default)
            except Exception:
                value = int(default)
            if minimum is not None:
                value = max(minimum, value)
            if maximum is not None:
                value = min(maximum, value)
            return value

        def optional_int_value(name: str) -> Optional[int]:
            raw = options.get(name)
            if raw is None:
                return None
            text = str(raw).strip()
            if text == "":
                return None
            try:
                return int(text)
            except Exception:
                return None

        def bool_value(name: str, default: bool) -> bool:
            raw = options.get(name)
            return bool(raw) if raw is not None else default

        def append_section(lines: list[str], title: str, description: str = "") -> None:
            if lines and lines[-1] != "":
                lines.append("")
            lines.append(f"# {title}")
            if description:
                lines.append(f"# {description}")

        def append_block(lines: list[str], block_name: str, content: str) -> None:
            rendered = self._render_managed_subblock(block_name, self._normalize_multiline_text(content))
            lines.extend(rendered.splitlines())

        cache_dir_type = self._validate_choice(str(options.get("cache_dir_type") or "rock"), ("rock", "ufs"), "cache_dir_type")
        cache_dir_size_mb = int_value("cache_dir_size_mb", 10000, minimum=100)
        cache_dir_ufs_l1 = int_value("cache_dir_ufs_l1", 16, minimum=1)
        cache_dir_ufs_l2 = int_value("cache_dir_ufs_l2", 256, minimum=1)
        cache_dir_rock_slot_size_kb = int_value("cache_dir_rock_slot_size_kb", 32, minimum=4)
        cache_dir_rock_swap_timeout_ms = optional_int_value("cache_dir_rock_swap_timeout_ms")
        cache_dir_rock_max_swap_rate = optional_int_value("cache_dir_rock_max_swap_rate")
        store_dir_select_algorithm = self._validate_choice(
            str(options.get("store_dir_select_algorithm") or "least-load"),
            ("least-load", "round-robin"),
            "store_dir_select_algorithm",
        )

        cache_mem_mb = int_value("cache_mem_mb", 256, minimum=16)
        maximum_object_size_mb = int_value("maximum_object_size_mb", 128, minimum=1)
        maximum_object_size_in_memory_kb = int_value("maximum_object_size_in_memory_kb", 2048, minimum=0)
        minimum_object_size_kb = int_value("minimum_object_size_kb", 0, minimum=0)
        memory_cache_mode = self._validate_choice(
            str(options.get("memory_cache_mode") or "always"),
            ("always", "disk", "network"),
            "memory_cache_mode",
        )
        memory_cache_shared_on = bool_value("memory_cache_shared_on", True)

        replacement_policies = ("heap GDSF", "heap LFUDA", "heap LRU", "lru")
        cache_replacement_policy = self._sanitize_single_line(
            str(options.get("cache_replacement_policy") or "heap GDSF"),
            "cache_replacement_policy",
        )
        if cache_replacement_policy not in replacement_policies:
            cache_replacement_policy = "heap GDSF"
        memory_replacement_policy = self._sanitize_single_line(
            str(options.get("memory_replacement_policy") or "heap GDSF"),
            "memory_replacement_policy",
        )
        if memory_replacement_policy not in replacement_policies:
            memory_replacement_policy = "heap GDSF"

        shared_transient_entries_limit = int_value("shared_transient_entries_limit", 16384, minimum=0)
        cache_swap_low = int_value("cache_swap_low", 90, minimum=0, maximum=100)
        cache_swap_high = int_value("cache_swap_high", 95, minimum=0, maximum=100)
        collapsed_forwarding_on = bool_value("collapsed_forwarding_on", True)
        collapsed_forwarding_access_rules_text = self._normalize_multiline_text(options.get("collapsed_forwarding_access_rules_text") or "")
        range_cache_on = bool_value("range_cache_on", True)
        range_offset_limit_value = self._sanitize_single_line(
            str(options.get("range_offset_limit_value") or "128 MB"),
            "range_offset_limit_value",
        )
        if not range_cache_on:
            range_offset_limit_value = "0"
        else:
            normalized_range = range_offset_limit_value.strip().lower()
            if normalized_range in ("", "0", "0 b", "0 byte", "0 bytes", "0 kb", "0 mb", "off", "false"):
                range_offset_limit_value = "128 MB"
            elif normalized_range == "-1":
                range_offset_limit_value = "none"
        cache_miss_revalidate_on = bool_value("cache_miss_revalidate_on", True)
        reload_into_ims_on = bool_value("reload_into_ims_on", False)
        pipeline_prefetch_on = bool_value("pipeline_prefetch_on", False)
        pipeline_prefetch_count = int_value("pipeline_prefetch_count", 0, minimum=0)
        if not pipeline_prefetch_on:
            pipeline_prefetch_count = 0
        elif pipeline_prefetch_count <= 0:
            pipeline_prefetch_count = 1
        read_ahead_gap_kb = int_value("read_ahead_gap_kb", 16, minimum=0)
        quick_abort_min_kb = int_value("quick_abort_min_kb", 16)
        quick_abort_max_kb = int_value("quick_abort_max_kb", 16, minimum=0)
        quick_abort_pct = int_value("quick_abort_pct", 95, minimum=0, maximum=100)
        negative_ttl_seconds = int_value("negative_ttl_seconds", 0, minimum=0)
        minimum_expiry_time_seconds = int_value("minimum_expiry_time_seconds", 60, minimum=0)
        max_stale_seconds = int_value("max_stale_seconds", 7 * 24 * 3600, minimum=0)
        refresh_all_ims_on = bool_value("refresh_all_ims_on", False)
        cache_policy_rules_text = self._normalize_multiline_text(options.get("cache_policy_rules_text") or DEFAULT_CACHE_POLICY_RULES)
        refresh_patterns_text = self._normalize_multiline_text(options.get("refresh_patterns_text") or DEFAULT_REFRESH_PATTERNS)

        client_persistent_connections_on = bool_value("client_persistent_connections_on", True)
        server_persistent_connections_on = bool_value("server_persistent_connections_on", True)
        buffered_logs_on = bool_value("buffered_logs_on", False)
        log_mime_hdrs_on = bool_value("log_mime_hdrs_on", False)
        logfile_rotate = int_value("logfile_rotate", 10, minimum=0)
        stats_collection_rules_text = self._normalize_multiline_text(options.get("stats_collection_rules_text") or "")
        tls_key_log_path = self._validate_single_line_value(str(options.get("tls_key_log_path") or ""), "tls_key_log")

        memory_pools_on = bool_value("memory_pools_on", True)
        memory_pools_limit_raw = options.get("memory_pools_limit_mb")
        if memory_pools_limit_raw is None or str(memory_pools_limit_raw).strip() == "":
            memory_pools_limit_value = "64 MB"
        elif str(memory_pools_limit_raw).strip().lower() == "none":
            memory_pools_limit_value = "none"
        else:
            memory_pools_limit_value = f"{int_value('memory_pools_limit_mb', 64, minimum=0)} MB"
        shared_memory_locking_on = bool_value("shared_memory_locking_on", False)
        max_open_disk_fds = int_value("max_open_disk_fds", 0, minimum=0)
        hopeless_kid_revival_delay_seconds = int_value("hopeless_kid_revival_delay_seconds", 3600, minimum=1)
        high_response_time_warning_ms = optional_int_value("high_response_time_warning_ms")
        high_page_fault_warning = optional_int_value("high_page_fault_warning")
        store_avg_object_size_kb = int_value("store_avg_object_size_kb", 13, minimum=0)
        store_objects_per_bucket = int_value("store_objects_per_bucket", 20, minimum=0)
        client_db_on = bool_value("client_db_on", True)
        offline_mode_on = bool_value("offline_mode_on", False)
        paranoid_hit_validation_value = self._validate_single_line_value(
            str(options.get("paranoid_hit_validation_value") or "0"),
            "paranoid_hit_validation",
        ) or "0"
        cpu_affinity_map = self._validate_cpu_affinity_map(str(options.get("cpu_affinity_map") or ""))
        max_filedescriptors = int_value("max_filedescriptors", 65535, minimum=0)

        client_idle_pconn_timeout_seconds = int_value("client_idle_pconn_timeout_seconds", 120, minimum=0)
        server_idle_pconn_timeout_seconds = int_value("server_idle_pconn_timeout_seconds", 60, minimum=0)
        pconn_lifetime_seconds = int_value("pconn_lifetime_seconds", 0, minimum=0)
        persistent_connection_after_error_on = bool_value("persistent_connection_after_error_on", True)
        detect_broken_pconn_on = bool_value("detect_broken_pconn_on", False)
        half_closed_clients_on = bool_value("half_closed_clients_on", False)
        connect_retries = int_value("connect_retries", 0, minimum=0, maximum=10)
        forward_max_tries = int_value("forward_max_tries", 25, minimum=1)
        retry_on_error_on = bool_value("retry_on_error_on", False)
        client_lifetime_seconds = int_value("client_lifetime_seconds", 24 * 3600, minimum=0)
        client_ip_max_connections = optional_int_value("client_ip_max_connections")
        tcp_recv_bufsize_kb = optional_int_value("tcp_recv_bufsize_kb")
        accept_filter_value = self._validate_single_line_value(str(options.get("accept_filter_value") or ""), "accept_filter")
        server_pconn_for_nonretriable_rules_text = self._normalize_multiline_text(options.get("server_pconn_for_nonretriable_rules_text") or "")
        client_dst_passthru_on = bool_value("client_dst_passthru_on", True)
        host_verify_strict_on = bool_value("host_verify_strict_on", False)
        on_unsupported_protocol_action = self._validate_choice(
            str(options.get("on_unsupported_protocol_action") or "respond"),
            ("respond", "tunnel"),
            "on_unsupported_protocol_action",
        )
        happy_eyeballs_connect_timeout_ms = int_value("happy_eyeballs_connect_timeout_ms", 250, minimum=0)
        happy_eyeballs_connect_gap_ms = optional_int_value("happy_eyeballs_connect_gap_ms")
        happy_eyeballs_connect_limit = optional_int_value("happy_eyeballs_connect_limit")

        connect_timeout_seconds = int_value("connect_timeout_seconds", 60, minimum=0)
        peer_connect_timeout_seconds = int_value("peer_connect_timeout_seconds", 30, minimum=0)
        request_start_timeout_seconds = int_value("request_start_timeout_seconds", 300, minimum=0)
        request_timeout_seconds = int_value("request_timeout_seconds", 300, minimum=0)
        read_timeout_seconds = int_value("read_timeout_seconds", 900, minimum=0)
        forward_timeout_seconds = int_value("forward_timeout_seconds", 240, minimum=0)
        write_timeout_seconds = int_value("write_timeout_seconds", 900, minimum=0)
        shutdown_lifetime_seconds = int_value("shutdown_lifetime_seconds", 30, minimum=0)

        dns_timeout_seconds = int_value("dns_timeout_seconds", 30, minimum=0)
        dns_retransmit_interval_seconds = int_value("dns_retransmit_interval_seconds", 5, minimum=0)
        dns_packet_max_raw = self._validate_single_line_value(str(options.get("dns_packet_max") or ""), "dns_packet_max")
        dns_nameservers = self._validate_dns_nameservers(str(options.get("dns_nameservers") or ""))
        hosts_file = self._validate_hosts_file_path(str(options.get("hosts_file") or "/etc/hosts")) or "/etc/hosts"
        append_domain = self._validate_append_domain(str(options.get("append_domain") or "")) if str(options.get("append_domain") or "").strip() else ""
        dns_defnames_on = bool_value("dns_defnames_on", False)
        dns_multicast_local_on = bool_value("dns_multicast_local_on", False)
        ignore_unknown_nameservers_on = bool_value("ignore_unknown_nameservers_on", True)
        check_hostnames_on = bool_value("check_hostnames_on", False)
        allow_underscore_on = bool_value("allow_underscore_on", True)
        positive_dns_ttl_seconds = int_value("positive_dns_ttl_seconds", 6 * 3600, minimum=1)
        negative_dns_ttl_seconds = int_value("negative_dns_ttl_seconds", 60, minimum=1)
        ipcache_size = int_value("ipcache_size", 8192, minimum=0)
        ipcache_low = int_value("ipcache_low", 90, minimum=0, maximum=100)
        ipcache_high = int_value("ipcache_high", 95, minimum=0, maximum=100)
        fqdncache_size = int_value("fqdncache_size", 8192, minimum=0)

        sslcrtd_program_cache_size_mb = int_value("sslcrtd_program_cache_size_mb", 16, minimum=1)
        sslcrtd_children = int_value("sslcrtd_children", 4, minimum=1, maximum=32)
        sslcrtd_children_startup = int_value("sslcrtd_children_startup", min(sslcrtd_children, 2), minimum=0)
        sslcrtd_children_idle = int_value("sslcrtd_children_idle", 1, minimum=1)
        sslcrtd_children_queue_size = int_value("sslcrtd_children_queue_size", max(32, sslcrtd_children * 8), minimum=1)
        dynamic_cert_mem_cache_size_mb = int_value("dynamic_cert_mem_cache_size_mb", 128, minimum=0)
        tls_outgoing_options_line = self._validate_single_line_value(
            str(options.get("tls_outgoing_options_line") or "min-version=1.2 options=NO_SSLv3"),
            "tls_outgoing_options",
        ) or "min-version=1.2 options=NO_SSLv3"
        sslproxy_session_ttl_seconds = int_value("sslproxy_session_ttl_seconds", 600, minimum=0)
        sslproxy_session_cache_size_mb = int_value("sslproxy_session_cache_size_mb", 32, minimum=0)
        sslproxy_foreign_intermediate_certs = self._validate_single_line_value(
            str(options.get("sslproxy_foreign_intermediate_certs") or ""),
            "sslproxy_foreign_intermediate_certs",
        )
        sslproxy_cert_sign_hash = self._validate_choice(
            str(options.get("sslproxy_cert_sign_hash") or "sha256"),
            ("sha256", "sha512", "sha1", "md5"),
            "sslproxy_cert_sign_hash",
        )
        ssl_unclean_shutdown_on = bool_value("ssl_unclean_shutdown_on", False)
        additional_ssl_rules_text = self._normalize_multiline_text(options.get("additional_ssl_rules_text") or "")
        sslproxy_cert_error_rules_text = self._normalize_multiline_text(options.get("sslproxy_cert_error_rules_text") or "")
        sslproxy_cert_sign_rules_text = self._normalize_multiline_text(options.get("sslproxy_cert_sign_rules_text") or "")
        sslproxy_cert_adapt_rules_text = self._normalize_multiline_text(options.get("sslproxy_cert_adapt_rules_text") or "")

        icap_enable_on = bool_value("icap_enable_on", True)
        icap_206_enable_on = bool_value("icap_206_enable_on", True)
        icap_send_client_ip_on = bool_value("icap_send_client_ip_on", True)
        icap_send_client_username_on = bool_value("icap_send_client_username_on", False)
        icap_client_username_header = self._validate_single_line_value(
            str(options.get("icap_client_username_header") or "X-Client-Username"),
            "icap_client_username_header",
        ) or "X-Client-Username"
        icap_client_username_encode_on = bool_value("icap_client_username_encode_on", False)
        icap_persistent_connections_on = bool_value("icap_persistent_connections_on", True)
        icap_preview_enable_on = bool_value("icap_preview_enable_on", True)
        icap_preview_size_kb = int_value("icap_preview_size_kb", 1024, minimum=0)
        icap_default_options_ttl_seconds = int_value("icap_default_options_ttl_seconds", 300, minimum=0)
        icap_connect_timeout_seconds = int_value("icap_connect_timeout_seconds", 15, minimum=0)
        icap_io_timeout_seconds = int_value("icap_io_timeout_seconds", 300, minimum=0)
        icap_service_failure_limit = int_value("icap_service_failure_limit", 10)
        icap_service_failure_limit_window_seconds = int_value("icap_service_failure_limit_window_seconds", 30, minimum=0)
        icap_service_revival_delay_seconds = int_value("icap_service_revival_delay_seconds", 60, minimum=0)
        adaptation_service_iteration_limit = int_value("adaptation_service_iteration_limit", 16, minimum=1)
        force_request_body_continuation_rules_text = self._normalize_multiline_text(
            options.get("force_request_body_continuation_rules_text") or ""
        )
        icap_retry_rules_text = self._normalize_multiline_text(options.get("icap_retry_rules_text") or "")
        icap_retry_limit = int_value("icap_retry_limit", 0, minimum=0)

        forwarded_for_value_raw = str(options.get("forwarded_for_value") or "").strip()
        if forwarded_for_value_raw and forwarded_for_value_raw not in ("on", "off", "transparent", "delete", "truncate"):
            forwarded_for_value_raw = ""
        via_on = bool_value("via_on", True)
        follow_x_forwarded_for_value = self._validate_single_line_value(
            str(options.get("follow_x_forwarded_for_value") or ""),
            "follow_x_forwarded_for",
        )
        client_netmask_value = self._validate_single_line_value(str(options.get("client_netmask_value") or ""), "client_netmask")
        strip_query_terms_on = bool_value("strip_query_terms_on", True)

        request_header_max_size_kb = int_value("request_header_max_size_kb", 64, minimum=1)
        reply_header_max_size_kb = int_value("reply_header_max_size_kb", 64, minimum=1)
        request_body_max_size_mb = int_value("request_body_max_size_mb", 0, minimum=0)
        client_request_buffer_max_size_kb = int_value("client_request_buffer_max_size_kb", 512, minimum=0)
        relaxed_header_parser_mode = self._validate_choice(
            str(options.get("relaxed_header_parser_mode") or "on"),
            ("on", "warn", "off"),
            "relaxed_header_parser",
        )
        uri_whitespace_mode = self._validate_choice(
            str(options.get("uri_whitespace_mode") or "strip"),
            ("strip", "deny", "allow", "encode", "chop"),
            "uri_whitespace",
        )
        http_upgrade_request_protocols_rules_text = self._normalize_multiline_text(options.get("http_upgrade_request_protocols_rules_text") or "")

        visible_hostname = self._validate_hostname(str(options.get("visible_hostname") or ""), "visible_hostname")
        httpd_suppress_version_string_on = bool_value("httpd_suppress_version_string_on", False)
        vary_ignore_expire_on = bool_value("vary_ignore_expire_on", False)

        workers = int_value("workers", 1, minimum=1)
        try:
            max_workers = int((os.environ.get("MAX_WORKERS") or "4").strip())
        except Exception:
            max_workers = 4
        max_workers = min(4, max(1, max_workers))
        workers = min(max_workers, workers)

        if cache_dir_type == "rock":
            cache_dir_parts = [
                f"cache_dir rock /var/spool/squid {cache_dir_size_mb}",
                f"slot-size={cache_dir_rock_slot_size_kb * 1024}",
            ]
            if cache_dir_rock_swap_timeout_ms is not None:
                cache_dir_parts.append(f"swap-timeout={cache_dir_rock_swap_timeout_ms}")
            if cache_dir_rock_max_swap_rate is not None:
                cache_dir_parts.append(f"max-swap-rate={cache_dir_rock_max_swap_rate}")
            cache_dir_line = " ".join(cache_dir_parts)
        else:
            cache_dir_line = f"cache_dir ufs /var/spool/squid {cache_dir_size_mb} {cache_dir_ufs_l1} {cache_dir_ufs_l2}"

        lines: list[str] = [self._MANAGED_SETTINGS_START]

        append_section(lines, "SMP mode", "Worker, helper, and TLS interception settings managed by the Admin UI.")
        lines.append(f"workers {workers}")
        lines.append(f"hopeless_kid_revival_delay {hopeless_kid_revival_delay_seconds} seconds")
        lines.append(f"sslcrtd_program /usr/lib/squid/ssl_crtd -s /var/lib/ssl_db/store -M {sslcrtd_program_cache_size_mb}MB")
        lines.append(
            f"sslcrtd_children {sslcrtd_children}"
            f" startup={sslcrtd_children_startup}"
            f" idle={sslcrtd_children_idle}"
            f" queue-size={sslcrtd_children_queue_size}"
        )
        lines.append("acl step1 at_step SslBump1")
        lines.append("ssl_bump peek step1")
        lines.append("include /etc/squid/conf.d/10-sslfilter.conf")
        lines.append("acl steam_sites ssl::server_name .steamserver.net")
        lines.append("note ssl_exception steam steam_sites")
        lines.append("ssl_bump splice steam_sites")
        append_block(lines, "CUSTOM_SSL_RULES", additional_ssl_rules_text)
        lines.append("ssl_bump bump all")

        append_section(lines, "Cache settings", "Disk layout, memory sizing, and cache heuristics.")
        lines.append(cache_dir_line)
        lines.append(f"store_dir_select_algorithm {store_dir_select_algorithm}")
        lines.append(f"maximum_object_size {maximum_object_size_mb} MB")
        lines.append(f"maximum_object_size_in_memory {maximum_object_size_in_memory_kb} KB")
        lines.append(f"minimum_object_size {minimum_object_size_kb} KB")
        lines.append(f"cache_mem {cache_mem_mb} MB")
        lines.append(f"memory_cache_mode {memory_cache_mode}")
        lines.append(f"memory_cache_shared {'on' if memory_cache_shared_on else 'off'}")
        lines.append(f"shared_transient_entries_limit {shared_transient_entries_limit}")
        lines.append(f"cache_replacement_policy {cache_replacement_policy}")
        lines.append(f"memory_replacement_policy {memory_replacement_policy}")
        lines.append(f"cache_swap_low {cache_swap_low}")
        lines.append(f"cache_swap_high {cache_swap_high}")
        lines.append(f"collapsed_forwarding {'on' if collapsed_forwarding_on else 'off'}")
        append_block(lines, "COLLAPSED_FORWARDING_ACCESS", collapsed_forwarding_access_rules_text)
        lines.append(f"range_offset_limit {range_offset_limit_value}")
        lines.append(f"cache_miss_revalidate {'on' if cache_miss_revalidate_on else 'off'}")
        lines.append(f"reload_into_ims {'on' if reload_into_ims_on else 'off'}")
        lines.append(f"pipeline_prefetch {pipeline_prefetch_count}")
        lines.append(f"read_ahead_gap {read_ahead_gap_kb} KB")
        lines.append(f"quick_abort_min {quick_abort_min_kb} KB")
        lines.append(f"quick_abort_max {quick_abort_max_kb} KB")
        lines.append(f"quick_abort_pct {quick_abort_pct}")
        lines.append(f"negative_ttl {negative_ttl_seconds} seconds")
        lines.append(f"minimum_expiry_time {minimum_expiry_time_seconds} seconds")
        lines.append(f"max_stale {max_stale_seconds} seconds")
        lines.append(f"refresh_all_ims {'on' if refresh_all_ims_on else 'off'}")
        append_block(lines, "CACHE_POLICY", cache_policy_rules_text)
        append_block(lines, "REFRESH_PATTERNS", refresh_patterns_text)

        append_section(lines, "Connection behavior", "Keep-alive reuse, retry behavior, and socket tuning.")
        lines.append(f"client_persistent_connections {'on' if client_persistent_connections_on else 'off'}")
        lines.append(f"server_persistent_connections {'on' if server_persistent_connections_on else 'off'}")
        lines.append(f"client_idle_pconn_timeout {client_idle_pconn_timeout_seconds} seconds")
        lines.append(f"server_idle_pconn_timeout {server_idle_pconn_timeout_seconds} seconds")
        lines.append(f"pconn_lifetime {pconn_lifetime_seconds} seconds")
        lines.append(f"persistent_connection_after_error {'on' if persistent_connection_after_error_on else 'off'}")
        lines.append(f"detect_broken_pconn {'on' if detect_broken_pconn_on else 'off'}")
        lines.append(f"half_closed_clients {'on' if half_closed_clients_on else 'off'}")
        append_block(lines, "SERVER_PCONN_FOR_NONRETRIABLE", server_pconn_for_nonretriable_rules_text)
        lines.append(f"connect_retries {connect_retries}")
        lines.append(f"forward_max_tries {forward_max_tries}")
        lines.append(f"retry_on_error {'on' if retry_on_error_on else 'off'}")
        lines.append(f"client_lifetime {client_lifetime_seconds} seconds")
        if client_ip_max_connections is not None:
            lines.append(f"client_ip_max_connections {max(0, client_ip_max_connections)}")
        if tcp_recv_bufsize_kb is not None:
            lines.append(f"tcp_recv_bufsize {max(0, tcp_recv_bufsize_kb)} KB")
        if accept_filter_value:
            lines.append(f"accept_filter {accept_filter_value}")
        lines.append(f"client_dst_passthru {'on' if client_dst_passthru_on else 'off'}")
        lines.append(f"host_verify_strict {'on' if host_verify_strict_on else 'off'}")
        lines.append(f"on_unsupported_protocol {on_unsupported_protocol_action} all")
        lines.append(f"happy_eyeballs_connect_timeout {happy_eyeballs_connect_timeout_ms} ms")
        if happy_eyeballs_connect_gap_ms is not None:
            lines.append(f"happy_eyeballs_connect_gap {max(0, happy_eyeballs_connect_gap_ms)} ms")
        if happy_eyeballs_connect_limit is not None:
            lines.append(f"happy_eyeballs_connect_limit {max(0, happy_eyeballs_connect_limit)}")

        append_section(lines, "Timeouts", "Request, forwarding, and shutdown timers.")
        lines.append(f"connect_timeout {connect_timeout_seconds} seconds")
        lines.append(f"peer_connect_timeout {peer_connect_timeout_seconds} seconds")
        lines.append(f"request_timeout {request_timeout_seconds} seconds")
        lines.append(f"read_timeout {read_timeout_seconds} seconds")
        lines.append(f"forward_timeout {forward_timeout_seconds} seconds")
        lines.append(f"request_start_timeout {request_start_timeout_seconds} seconds")
        lines.append(f"write_timeout {write_timeout_seconds} seconds")
        lines.append(f"shutdown_lifetime {shutdown_lifetime_seconds} seconds")

        append_section(lines, "Resolver and DNS cache tuning", "Resolver source selection, hostname validation, and DNS cache sizing.")
        lines.append(f"dns_timeout {dns_timeout_seconds} seconds")
        lines.append(f"dns_retransmit_interval {dns_retransmit_interval_seconds} seconds")
        if dns_packet_max_raw:
            if dns_packet_max_raw.lower() == "none":
                lines.append("dns_packet_max none")
            elif dns_packet_max_raw.isdigit():
                lines.append(f"dns_packet_max {int(dns_packet_max_raw)}")
        if dns_nameservers:
            lines.append(f"dns_nameservers {dns_nameservers}")
        lines.append(f"hosts_file {hosts_file}")
        if append_domain:
            lines.append(f"append_domain {append_domain}")
        lines.append(f"dns_defnames {'on' if dns_defnames_on else 'off'}")
        lines.append(f"dns_multicast_local {'on' if dns_multicast_local_on else 'off'}")
        lines.append(f"ignore_unknown_nameservers {'on' if ignore_unknown_nameservers_on else 'off'}")
        lines.append(f"check_hostnames {'on' if check_hostnames_on else 'off'}")
        lines.append(f"allow_underscore {'on' if allow_underscore_on else 'off'}")
        lines.append(f"positive_dns_ttl {positive_dns_ttl_seconds} seconds")
        lines.append(f"negative_dns_ttl {negative_dns_ttl_seconds} seconds")
        lines.append(f"ipcache_size {ipcache_size}")
        lines.append(f"ipcache_low {ipcache_low}")
        lines.append(f"ipcache_high {ipcache_high}")
        lines.append(f"fqdncache_size {fqdncache_size}")

        append_section(lines, "Origin-facing TLS", "Session reuse, signing policy, and certificate-chain behavior.")
        lines.append(f"tls_outgoing_options {tls_outgoing_options_line}")
        lines.append(f"sslproxy_session_ttl {sslproxy_session_ttl_seconds} seconds")
        lines.append(f"sslproxy_session_cache_size {sslproxy_session_cache_size_mb} MB")
        if sslproxy_foreign_intermediate_certs:
            lines.append(f"sslproxy_foreign_intermediate_certs {sslproxy_foreign_intermediate_certs}")
        lines.append(f"sslproxy_cert_sign_hash {sslproxy_cert_sign_hash}")
        lines.append(f"ssl_unclean_shutdown {'on' if ssl_unclean_shutdown_on else 'off'}")
        append_block(lines, "SSLPROXY_CERT_ERROR", sslproxy_cert_error_rules_text)
        append_block(lines, "SSLPROXY_CERT_SIGN", sslproxy_cert_sign_rules_text)
        append_block(lines, "SSLPROXY_CERT_ADAPT", sslproxy_cert_adapt_rules_text)

        append_section(lines, "Logging", "Rotation, MIME/header logging, and optional low-level diagnostics.")
        lines.append(f"logfile_rotate {logfile_rotate}")
        lines.append(f"buffered_logs {'on' if buffered_logs_on else 'off'}")
        lines.append(f"log_mime_hdrs {'on' if log_mime_hdrs_on else 'off'}")
        append_block(lines, "STATS_COLLECTION", stats_collection_rules_text)
        if tls_key_log_path:
            lines.append(f"tls_key_log {tls_key_log_path}")

        append_section(lines, "ICAP adaptation", "The container still generates service endpoints dynamically; these directives control Squid-side ICAP behavior.")
        lines.append(f"icap_enable {'on' if icap_enable_on else 'off'}")
        lines.append(f"icap_206_enable {'on' if icap_206_enable_on else 'off'}")
        lines.append(f"adaptation_send_client_ip {'on' if icap_send_client_ip_on else 'off'}")
        lines.append(f"adaptation_send_username {'on' if icap_send_client_username_on else 'off'}")
        lines.append(f"icap_client_username_header {icap_client_username_header}")
        lines.append(f"icap_client_username_encode {'on' if icap_client_username_encode_on else 'off'}")
        lines.append(f"icap_persistent_connections {'on' if icap_persistent_connections_on else 'off'}")
        lines.append(f"icap_preview_enable {'on' if icap_preview_enable_on else 'off'}")
        lines.append(f"icap_preview_size {icap_preview_size_kb} KB")
        lines.append(f"icap_default_options_ttl {icap_default_options_ttl_seconds}")
        lines.append(f"icap_service_failure_limit {icap_service_failure_limit} in {icap_service_failure_limit_window_seconds} seconds")
        lines.append(f"icap_service_revival_delay {icap_service_revival_delay_seconds} seconds")
        lines.append(f"icap_connect_timeout {icap_connect_timeout_seconds} seconds")
        lines.append(f"icap_io_timeout {icap_io_timeout_seconds} seconds")
        lines.append(f"adaptation_service_iteration_limit {adaptation_service_iteration_limit}")
        append_block(lines, "FORCE_REQUEST_BODY_CONTINUATION", force_request_body_continuation_rules_text)
        append_block(lines, "ICAP_RETRY", icap_retry_rules_text)
        lines.append(f"icap_retry_limit {icap_retry_limit}")
        lines.append("include /etc/squid/conf.d/20-icap.conf")

        append_section(lines, "Privacy and header handling", "Forwarding metadata, client anonymity, and parser tolerance.")
        if forwarded_for_value_raw:
            lines.append(f"forwarded_for {forwarded_for_value_raw}")
        lines.append(f"via {'on' if via_on else 'off'}")
        if follow_x_forwarded_for_value:
            lines.append(f"follow_x_forwarded_for {follow_x_forwarded_for_value}")
        if client_netmask_value:
            lines.append(f"client_netmask {client_netmask_value}")
        lines.append(f"strip_query_terms {'on' if strip_query_terms_on else 'off'}")
        lines.append(f"request_header_max_size {request_header_max_size_kb} KB")
        lines.append(f"reply_header_max_size {reply_header_max_size_kb} KB")
        lines.append(f"request_body_max_size {request_body_max_size_mb} MB")
        lines.append(f"client_request_buffer_max_size {client_request_buffer_max_size_kb} KB")
        lines.append(f"relaxed_header_parser {relaxed_header_parser_mode}")
        lines.append(f"uri_whitespace {uri_whitespace_mode}")
        append_block(lines, "HTTP_UPGRADE_REQUEST_PROTOCOLS", http_upgrade_request_protocols_rules_text)

        append_section(lines, "Performance and cache index behavior", "Memory pools, descriptor limits, and cache-hit integrity checks.")
        lines.append(f"memory_pools {'on' if memory_pools_on else 'off'}")
        lines.append(f"memory_pools_limit {memory_pools_limit_value}")
        lines.append(f"shared_memory_locking {'on' if shared_memory_locking_on else 'off'}")
        if high_response_time_warning_ms is not None:
            lines.append(f"high_response_time_warning {high_response_time_warning_ms}")
        if high_page_fault_warning is not None:
            lines.append(f"high_page_fault_warning {high_page_fault_warning}")
        lines.append(f"max_open_disk_fds {max_open_disk_fds}")
        lines.append(f"store_avg_object_size {store_avg_object_size_kb} KB")
        lines.append(f"store_objects_per_bucket {store_objects_per_bucket}")
        lines.append(f"client_db {'on' if client_db_on else 'off'}")
        lines.append(f"offline_mode {'on' if offline_mode_on else 'off'}")
        lines.append(f"paranoid_hit_validation {paranoid_hit_validation_value}")
        if cpu_affinity_map:
            lines.append(f"cpu_affinity_map {cpu_affinity_map}")
        lines.append(f"max_filedescriptors {max_filedescriptors}")

        append_section(lines, "HTTP identity", "How Squid identifies itself and handles a few compatibility edge cases.")
        if visible_hostname:
            lines.append(f"visible_hostname {visible_hostname}")
        lines.append(f"httpd_suppress_version_string {'on' if httpd_suppress_version_string_on else 'off'}")
        lines.append(f"vary_ignore_expire {'on' if vary_ignore_expire_on else 'off'}")

        lines.append(self._MANAGED_SETTINGS_END)
        return "\n".join(lines)

    def _read_file(self, path: str) -> str:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()

    def _replace_or_append_line(self, text: str, key: str, new_line: str) -> str:
        pattern = re.compile(rf"^(\s*{re.escape(key)}\s+).*$", re.M)
        if pattern.search(text):
            return pattern.sub(new_line, text, count=1)
        return text.rstrip() + "\n" + new_line + "\n"

    def _replace_cache_dir_line(self, text: str, new_line: str) -> str:
        pattern = re.compile(r"^\s*cache_dir\s+\w+\s+\S+.*$", re.M)
        if pattern.search(text):
            return pattern.sub(new_line, text, count=1)
        return text.rstrip() + "\n" + new_line + "\n"

    def _replace_http_port_option(self, text: str, option_name: str, option_value: str) -> str:
        pattern = re.compile(rf"({re.escape(option_name)}=)(\S+)", re.I)
        if pattern.search(text):
            return pattern.sub(lambda match: f"{match.group(1)}{option_value}", text, count=1)
        return text

    def get_tunable_options(self, config_text: Optional[str] = None) -> Dict[str, Any]:
        text = config_text if config_text is not None else (self.get_current_config() or "")

        def find_int(pattern: str) -> Optional[int]:
            match = re.search(pattern, text, re.M | re.I)
            return int(match.group(1)) if match else None

        def find_int_or_none(key: str) -> Optional[Any]:
            match = re.search(rf"^\s*{re.escape(key)}\s+(\S+)\s*$", text, re.M | re.I)
            if not match:
                return None
            value = (match.group(1) or "").strip()
            if value.lower() == "none":
                return "none"
            try:
                return int(value)
            except Exception:
                return None

        def find_on_off(key: str) -> Optional[bool]:
            match = re.search(rf"^\s*{re.escape(key)}\s+(on|off)\s*$", text, re.M | re.I)
            if not match:
                return None
            return match.group(1).lower() == "on"

        def find_choice_token(key: str, allowed: tuple[str, ...]) -> Optional[str]:
            match = re.search(rf"^\s*{re.escape(key)}\s+(\S+)\s*$", text, re.M | re.I)
            if not match:
                return None
            token = (match.group(1) or "").strip()
            return token if token in allowed else None

        def find_time_seconds(key: str) -> Optional[int]:
            match = re.search(rf"^\s*{re.escape(key)}\s+(\d+)\s*([a-zA-Z]+)?\s*$", text, re.M)
            if not match:
                return None
            try:
                value = int(match.group(1))
            except Exception:
                return None
            unit = (match.group(2) or "").strip().lower()
            if not unit:
                return value
            if unit in ("s", "sec", "secs", "second", "seconds"):
                return value
            if unit in ("m", "min", "mins", "minute", "minutes"):
                return value * 60
            if unit in ("h", "hr", "hrs", "hour", "hours"):
                return value * 3600
            if unit in ("d", "day", "days"):
                return value * 86400
            return value

        def find_time_milliseconds(key: str) -> Optional[int]:
            match = re.search(rf"^\s*{re.escape(key)}\s+(\d+)\s*([a-zA-Z]+)?\s*$", text, re.M | re.I)
            if not match:
                return None
            try:
                value = int(match.group(1))
            except Exception:
                return None
            unit = (match.group(2) or "").strip().lower()
            if not unit:
                return value
            if unit in ("ms", "msec", "msecs", "millisecond", "milliseconds"):
                return value
            if unit in ("s", "sec", "secs", "second", "seconds"):
                return value * 1000
            if unit in ("m", "min", "mins", "minute", "minutes"):
                return value * 60 * 1000
            return value

        def find_str(key: str) -> Optional[str]:
            match = re.search(rf"^\s*{re.escape(key)}\s+(.+?)\s*$", text, re.M | re.I)
            return match.group(1).strip() if match else None

        def find_kb(key: str) -> Optional[int]:
            match = re.search(rf"^\s*{re.escape(key)}\s+(\d+)\s*(KB|K|KBYTES)?\s*$", text, re.M | re.I)
            return int(match.group(1)) if match else None

        def find_pct(key: str) -> Optional[int]:
            match = re.search(rf"^\s*{re.escape(key)}\s+(\d+)\s*%?\s*$", text, re.M | re.I)
            return int(match.group(1)) if match else None

        def _size_to_bytes(value: str, unit: str) -> Optional[int]:
            try:
                number = int(value)
            except Exception:
                return None
            normalized_unit = (unit or "").strip().lower()
            if normalized_unit in ("", "b", "bytes"):
                return number
            if normalized_unit in ("k", "kb", "kib", "kbytes"):
                return number * 1024
            if normalized_unit in ("m", "mb", "mib", "mbytes"):
                return number * 1024 * 1024
            if normalized_unit in ("g", "gb", "gib", "gbytes"):
                return number * 1024 * 1024 * 1024
            return None

        def find_size_kb(key: str) -> Optional[int]:
            match = re.search(rf"^\s*{re.escape(key)}\s+(\d+)\s*([A-Za-z]+)?\s*$", text, re.M | re.I)
            if not match:
                return None
            size_bytes = _size_to_bytes(match.group(1), match.group(2) or "")
            if size_bytes is None:
                return None
            return int(size_bytes // 1024)

        def find_size_mb(key: str) -> Optional[int]:
            match = re.search(rf"^\s*{re.escape(key)}\s+(\d+)\s*([A-Za-z]+)?\s*$", text, re.M | re.I)
            if not match:
                return None
            size_bytes = _size_to_bytes(match.group(1), match.group(2) or "")
            if size_bytes is None:
                return None
            return int(size_bytes // (1024 * 1024))

        def find_size_mb_or_none(key: str) -> Optional[Any]:
            match = re.search(rf"^\s*{re.escape(key)}\s+(\S+)(?:\s+([A-Za-z]+))?\s*$", text, re.M | re.I)
            if not match:
                return None
            token = (match.group(1) or "").strip()
            if token.lower() == "none":
                return "none"
            token_match = re.match(r"^(\d+)([A-Za-z]+)?$", token)
            value_part = token
            unit_part = match.group(2) or ""
            if token_match:
                value_part = token_match.group(1)
                unit_part = token_match.group(2) or unit_part
            size_bytes = _size_to_bytes(value_part, unit_part)
            if size_bytes is None:
                return None
            return int(size_bytes // (1024 * 1024))

        def find_range_offset_limit_mb() -> Optional[int]:
            match = re.search(r"^\s*range_offset_limit\s+(-?\d+)\s*([A-Za-z]+)?\s*$", text, re.M | re.I)
            if not match:
                return None
            if match.group(1) == "-1":
                return -1
            size_bytes = _size_to_bytes(match.group(1), match.group(2) or "")
            if size_bytes is None:
                return None
            return int(size_bytes // (1024 * 1024))

        def find_range_offset_limit_value() -> Optional[str]:
            match = re.search(r"^\s*range_offset_limit\s+(.+?)\s*$", text, re.M | re.I)
            return (match.group(1) or "").strip() if match else None

        def find_pipeline_prefetch_bool() -> Optional[bool]:
            match = re.search(r"^\s*pipeline_prefetch\s+(\S+)\s*$", text, re.M | re.I)
            if not match:
                return None
            value = (match.group(1) or "").strip().lower()
            if value in ("on", "true", "yes"):
                return True
            if value in ("off", "false", "no"):
                return False
            try:
                return int(value) >= 1
            except Exception:
                return None

        def find_pipeline_prefetch_count() -> Optional[int]:
            match = re.search(r"^\s*pipeline_prefetch\s+(\S+)\s*$", text, re.M | re.I)
            if not match:
                return None
            value = (match.group(1) or "").strip().lower()
            if value in ("on", "true", "yes"):
                return 1
            if value in ("off", "false", "no"):
                return 0
            try:
                return max(0, int(value))
            except Exception:
                return None

        def find_cache_dir_settings() -> dict[str, Any]:
            for line in (text or "").splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if not stripped.lower().startswith("cache_dir "):
                    continue
                parts = stripped.split()
                if len(parts) < 4:
                    continue
                store_type = (parts[1] or "").strip().lower()
                result: dict[str, Any] = {}
                if store_type in ("rock", "ufs"):
                    result["cache_dir_type"] = store_type
                try:
                    result["cache_dir_size_mb"] = int(parts[3])
                except Exception:
                    pass
                if store_type == "ufs":
                    try:
                        result["cache_dir_ufs_l1"] = int(parts[4])
                        result["cache_dir_ufs_l2"] = int(parts[5])
                    except Exception:
                        pass
                if store_type == "rock":
                    for token in parts[4:]:
                        key, sep, raw_value = token.partition("=")
                        if sep != "=" or not raw_value:
                            continue
                        if key == "slot-size":
                            size_bytes = _size_to_bytes(raw_value, "")
                            if size_bytes is not None:
                                result["cache_dir_rock_slot_size_kb"] = int(size_bytes // 1024)
                        elif key == "swap-timeout":
                            try:
                                result["cache_dir_rock_swap_timeout_ms"] = int(raw_value)
                            except Exception:
                                pass
                        elif key == "max-swap-rate":
                            try:
                                result["cache_dir_rock_max_swap_rate"] = int(raw_value)
                            except Exception:
                                pass
                return result
            return {}

        def find_sslcrtd_program_cache_size_mb() -> Optional[int]:
            match = re.search(r"^\s*sslcrtd_program\s+.*?\s-M\s*(\d+)\s*([A-Za-z]+)?\s*$", text, re.M | re.I)
            if not match:
                return None
            size_bytes = _size_to_bytes(match.group(1), match.group(2) or "")
            if size_bytes is None:
                return None
            return int(size_bytes // (1024 * 1024))

        def find_sslcrtd_children_settings() -> dict[str, Any]:
            value = find_str("sslcrtd_children")
            if not value:
                return {}
            parts = value.split()
            result: dict[str, Any] = {}
            try:
                if parts:
                    result["sslcrtd_children"] = int(parts[0])
            except Exception:
                pass
            for token in parts[1:]:
                key, sep, raw_value = token.partition("=")
                if sep != "=" or not raw_value:
                    continue
                try:
                    parsed = int(raw_value)
                except Exception:
                    continue
                if key == "startup":
                    result["sslcrtd_children_startup"] = parsed
                elif key == "idle":
                    result["sslcrtd_children_idle"] = parsed
                elif key == "queue-size":
                    result["sslcrtd_children_queue_size"] = parsed
            return result

        def find_dynamic_cert_mem_cache_size_mb() -> Optional[int]:
            match = re.search(r"dynamic_cert_mem_cache_size\s*=\s*(\d+)\s*([A-Za-z]+)?", text, re.I)
            if not match:
                return None
            size_bytes = _size_to_bytes(match.group(1), match.group(2) or "")
            if size_bytes is None:
                return None
            return int(size_bytes // (1024 * 1024))

        def find_icap_service_failure_limit() -> dict[str, Any]:
            match = re.search(
                r"^\s*icap_service_failure_limit\s+(-?\d+)(?:\s+in\s+(\d+)\s*([A-Za-z]+)?)?\s*$",
                text,
                re.M | re.I,
            )
            if not match:
                return {}
            result: dict[str, Any] = {}
            try:
                result["icap_service_failure_limit"] = int(match.group(1))
            except Exception:
                pass
            if match.group(2):
                try:
                    window_value = int(match.group(2))
                except Exception:
                    window_value = 0
                unit = (match.group(3) or "").strip().lower()
                multiplier = 1
                if unit in ("m", "min", "mins", "minute", "minutes"):
                    multiplier = 60
                elif unit in ("h", "hr", "hrs", "hour", "hours"):
                    multiplier = 3600
                elif unit in ("d", "day", "days"):
                    multiplier = 86400
                result["icap_service_failure_limit_window_seconds"] = window_value * multiplier
            return result

        def find_block_or_lines(block_name: str, *, prefixes: tuple[str, ...] = ()) -> Optional[str]:
            block = self._extract_managed_subblock(text, block_name)
            if block is not None:
                return block
            if not prefixes:
                return None
            lines: list[str] = []
            for line in (text or "").splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                lower = stripped.lower()
                if any(lower.startswith(prefix) for prefix in prefixes):
                    lines.append(stripped)
            if not lines:
                return None
            return "\n".join(lines)

        cache_dir_settings = find_cache_dir_settings()
        sslcrtd_settings = find_sslcrtd_children_settings()
        icap_failure_settings = find_icap_service_failure_limit()
        on_unsupported_protocol_value = find_str("on_unsupported_protocol")
        on_unsupported_protocol_action = None
        if on_unsupported_protocol_value:
            on_unsupported_protocol_action = (on_unsupported_protocol_value.split() or [None])[0]

        return {
            "cache_dir_type": cache_dir_settings.get("cache_dir_type"),
            "cache_dir_size_mb": cache_dir_settings.get("cache_dir_size_mb"),
            "cache_dir_ufs_l1": cache_dir_settings.get("cache_dir_ufs_l1"),
            "cache_dir_ufs_l2": cache_dir_settings.get("cache_dir_ufs_l2"),
            "cache_dir_rock_slot_size_kb": cache_dir_settings.get("cache_dir_rock_slot_size_kb"),
            "cache_dir_rock_swap_timeout_ms": cache_dir_settings.get("cache_dir_rock_swap_timeout_ms"),
            "cache_dir_rock_max_swap_rate": cache_dir_settings.get("cache_dir_rock_max_swap_rate"),
            "store_dir_select_algorithm": find_choice_token("store_dir_select_algorithm", ("least-load", "round-robin")),
            "cache_mem_mb": find_int(r"^\s*cache_mem\s+(\d+)\s*MB\s*$"),
            "maximum_object_size_mb": find_int(r"^\s*maximum_object_size\s+(\d+)\s*MB\s*$"),
            "maximum_object_size_in_memory_kb": find_int(r"^\s*maximum_object_size_in_memory\s+(\d+)\s*KB\s*$"),
            "minimum_object_size_kb": find_kb("minimum_object_size"),
            "memory_cache_mode": find_str("memory_cache_mode"),
            "memory_cache_shared": find_on_off("memory_cache_shared"),
            "shared_transient_entries_limit": find_int(r"^\s*shared_transient_entries_limit\s+(\d+)\s*$"),
            "cache_swap_low": find_int(r"^\s*cache_swap_low\s+(\d+)\s*$"),
            "cache_swap_high": find_int(r"^\s*cache_swap_high\s+(\d+)\s*$"),
            "collapsed_forwarding": find_on_off("collapsed_forwarding"),
            "range_offset_limit": find_range_offset_limit_mb(),
            "range_offset_limit_value": find_range_offset_limit_value(),
            "collapsed_forwarding_access_rules_text": find_block_or_lines("COLLAPSED_FORWARDING_ACCESS", prefixes=("collapsed_forwarding_access ",)),
            "client_persistent_connections": find_on_off("client_persistent_connections"),
            "server_persistent_connections": find_on_off("server_persistent_connections"),
            "negative_ttl_seconds": find_time_seconds("negative_ttl"),
            "positive_dns_ttl_seconds": find_time_seconds("positive_dns_ttl"),
            "negative_dns_ttl_seconds": find_time_seconds("negative_dns_ttl"),
            "minimum_expiry_time_seconds": find_time_seconds("minimum_expiry_time"),
            "max_stale_seconds": find_time_seconds("max_stale"),
            "refresh_all_ims": find_on_off("refresh_all_ims"),
            "reload_into_ims": find_on_off("reload_into_ims"),
            "read_ahead_gap_kb": find_kb("read_ahead_gap"),
            "workers": find_int(r"^\s*workers\s+(\d+)\s*$"),
            "hopeless_kid_revival_delay_seconds": find_time_seconds("hopeless_kid_revival_delay"),
            "cache_replacement_policy": find_str("cache_replacement_policy"),
            "memory_replacement_policy": find_str("memory_replacement_policy"),
            "cache_miss_revalidate": find_on_off("cache_miss_revalidate"),
            "pipeline_prefetch": find_pipeline_prefetch_bool(),
            "pipeline_prefetch_count": find_pipeline_prefetch_count(),
            "quick_abort_min_kb": find_kb("quick_abort_min"),
            "quick_abort_max_kb": find_kb("quick_abort_max"),
            "quick_abort_pct": find_pct("quick_abort_pct"),
            "connect_timeout_seconds": find_time_seconds("connect_timeout"),
            "peer_connect_timeout_seconds": find_time_seconds("peer_connect_timeout"),
            "request_timeout_seconds": find_time_seconds("request_timeout"),
            "read_timeout_seconds": find_time_seconds("read_timeout"),
            "forward_timeout_seconds": find_time_seconds("forward_timeout"),
            "request_start_timeout_seconds": find_time_seconds("request_start_timeout"),
            "write_timeout_seconds": find_time_seconds("write_timeout"),
            "shutdown_lifetime_seconds": find_time_seconds("shutdown_lifetime"),
            "logfile_rotate": find_int(r"^\s*logfile_rotate\s+(\d+)\s*$"),
            "buffered_logs": find_on_off("buffered_logs"),
            "log_mime_hdrs": find_on_off("log_mime_hdrs"),
            "server_idle_pconn_timeout_seconds": find_time_seconds("server_idle_pconn_timeout") or find_time_seconds("pconn_timeout"),
            "client_idle_pconn_timeout_seconds": find_time_seconds("client_idle_pconn_timeout"),
            "pconn_timeout_seconds": find_time_seconds("server_idle_pconn_timeout") or find_time_seconds("pconn_timeout"),
            "pconn_lifetime_seconds": find_time_seconds("pconn_lifetime"),
            "persistent_connection_after_error": find_on_off("persistent_connection_after_error"),
            "detect_broken_pconn": find_on_off("detect_broken_pconn"),
            "half_closed_clients": find_on_off("half_closed_clients"),
            "connect_retries": find_int(r"^\s*connect_retries\s+(\d+)\s*$"),
            "forward_max_tries": find_int(r"^\s*forward_max_tries\s+(\d+)\s*$"),
            "retry_on_error": find_on_off("retry_on_error"),
            "client_lifetime_seconds": find_time_seconds("client_lifetime"),
            "client_ip_max_connections": find_int(r"^\s*client_ip_max_connections\s+(\d+)\s*$"),
            "accept_filter_value": find_str("accept_filter"),
            "client_dst_passthru": find_on_off("client_dst_passthru"),
            "host_verify_strict": find_on_off("host_verify_strict"),
            "on_unsupported_protocol_action": on_unsupported_protocol_action,
            "happy_eyeballs_connect_timeout_ms": find_time_milliseconds("happy_eyeballs_connect_timeout"),
            "happy_eyeballs_connect_gap_ms": find_time_milliseconds("happy_eyeballs_connect_gap"),
            "happy_eyeballs_connect_limit": find_int(r"^\s*happy_eyeballs_connect_limit\s+(\d+)\s*$"),
            "server_pconn_for_nonretriable_rules_text": find_block_or_lines(
                "SERVER_PCONN_FOR_NONRETRIABLE",
                prefixes=("server_pconn_for_nonretriable ",),
            ),
            "max_filedescriptors": find_int(r"^\s*max_filedescriptors\s+(\d+)\s*$"),
            "dns_timeout_seconds": find_time_seconds("dns_timeout"),
            "dns_retransmit_interval_seconds": find_time_seconds("dns_retransmit_interval"),
            "dns_packet_max": find_int_or_none("dns_packet_max"),
            "dns_nameservers": find_str("dns_nameservers"),
            "hosts_file": find_str("hosts_file"),
            "append_domain": find_str("append_domain"),
            "dns_defnames": find_on_off("dns_defnames"),
            "dns_multicast_local": find_on_off("dns_multicast_local"),
            "ignore_unknown_nameservers": find_on_off("ignore_unknown_nameservers"),
            "check_hostnames": find_on_off("check_hostnames"),
            "allow_underscore": find_on_off("allow_underscore"),
            "ipcache_size": find_int(r"^\s*ipcache_size\s+(\d+)\s*$"),
            "ipcache_low": find_int(r"^\s*ipcache_low\s+(\d+)\s*$"),
            "ipcache_high": find_int(r"^\s*ipcache_high\s+(\d+)\s*$"),
            "fqdncache_size": find_int(r"^\s*fqdncache_size\s+(\d+)\s*$"),
            "sslcrtd_program_cache_size_mb": find_sslcrtd_program_cache_size_mb(),
            "sslcrtd_children": sslcrtd_settings.get("sslcrtd_children"),
            "sslcrtd_children_startup": sslcrtd_settings.get("sslcrtd_children_startup"),
            "sslcrtd_children_idle": sslcrtd_settings.get("sslcrtd_children_idle"),
            "sslcrtd_children_queue_size": sslcrtd_settings.get("sslcrtd_children_queue_size"),
            "dynamic_cert_mem_cache_size_mb": find_dynamic_cert_mem_cache_size_mb(),
            "tls_outgoing_options_line": find_str("tls_outgoing_options"),
            "sslproxy_session_ttl_seconds": find_time_seconds("sslproxy_session_ttl"),
            "sslproxy_session_cache_size_mb": find_size_mb("sslproxy_session_cache_size"),
            "sslproxy_foreign_intermediate_certs": find_str("sslproxy_foreign_intermediate_certs"),
            "sslproxy_cert_sign_hash": find_str("sslproxy_cert_sign_hash"),
            "ssl_unclean_shutdown": find_on_off("ssl_unclean_shutdown"),
            "additional_ssl_rules_text": find_block_or_lines("CUSTOM_SSL_RULES"),
            "sslproxy_cert_error_rules_text": find_block_or_lines("SSLPROXY_CERT_ERROR", prefixes=("sslproxy_cert_error ",)),
            "sslproxy_cert_sign_rules_text": find_block_or_lines("SSLPROXY_CERT_SIGN", prefixes=("sslproxy_cert_sign ",)),
            "sslproxy_cert_adapt_rules_text": find_block_or_lines("SSLPROXY_CERT_ADAPT", prefixes=("sslproxy_cert_adapt ",)),
            "icap_enable": find_on_off("icap_enable"),
            "icap_206_enable": find_on_off("icap_206_enable"),
            "icap_send_client_ip": next(
                (value for value in (find_on_off("adaptation_send_client_ip"), find_on_off("icap_send_client_ip")) if value is not None),
                None,
            ),
            "icap_send_client_username": next(
                (value for value in (find_on_off("adaptation_send_username"), find_on_off("icap_send_client_username")) if value is not None),
                None,
            ),
            "icap_client_username_header": find_str("icap_client_username_header"),
            "icap_client_username_encode": find_on_off("icap_client_username_encode"),
            "icap_persistent_connections": find_on_off("icap_persistent_connections"),
            "icap_preview_enable": find_on_off("icap_preview_enable"),
            "icap_preview_size_kb": find_size_kb("icap_preview_size"),
            "icap_default_options_ttl_seconds": find_time_seconds("icap_default_options_ttl"),
            "icap_connect_timeout_seconds": find_time_seconds("icap_connect_timeout"),
            "icap_io_timeout_seconds": find_time_seconds("icap_io_timeout"),
            "icap_service_failure_limit": icap_failure_settings.get("icap_service_failure_limit"),
            "icap_service_failure_limit_window_seconds": icap_failure_settings.get("icap_service_failure_limit_window_seconds"),
            "icap_service_revival_delay_seconds": find_time_seconds("icap_service_revival_delay"),
            "adaptation_service_iteration_limit": find_int(r"^\s*adaptation_service_iteration_limit\s+(\d+)\s*$"),
            "force_request_body_continuation_rules_text": find_block_or_lines(
                "FORCE_REQUEST_BODY_CONTINUATION",
                prefixes=("force_request_body_continuation ",),
            ),
            "icap_retry_rules_text": find_block_or_lines("ICAP_RETRY", prefixes=("icap_retry ",)),
            "icap_retry_limit": find_int(r"^\s*icap_retry_limit\s+(\d+)\s*$"),
            "forwarded_for_value": find_str("forwarded_for"),
            "via": find_on_off("via"),
            "follow_x_forwarded_for_value": find_str("follow_x_forwarded_for"),
            "request_header_max_size_kb": find_size_kb("request_header_max_size"),
            "reply_header_max_size_kb": find_size_kb("reply_header_max_size"),
            "request_body_max_size_mb": find_size_mb("request_body_max_size"),
            "client_request_buffer_max_size_kb": find_size_kb("client_request_buffer_max_size"),
            "relaxed_header_parser_mode": find_choice_token("relaxed_header_parser", ("on", "warn", "off")),
            "uri_whitespace_mode": find_choice_token("uri_whitespace", ("strip", "deny", "allow", "encode", "chop")),
            "http_upgrade_request_protocols_rules_text": find_block_or_lines(
                "HTTP_UPGRADE_REQUEST_PROTOCOLS",
                prefixes=("http_upgrade_request_protocols ",),
            ),
            "vary_ignore_expire": find_on_off("vary_ignore_expire"),
            "memory_pools": find_on_off("memory_pools"),
            "memory_pools_limit_mb": find_size_mb_or_none("memory_pools_limit"),
            "shared_memory_locking": find_on_off("shared_memory_locking"),
            "high_response_time_warning_ms": find_int(r"^\s*high_response_time_warning\s+(\d+)\s*$"),
            "high_page_fault_warning": find_int(r"^\s*high_page_fault_warning\s+(\d+)\s*$"),
            "max_open_disk_fds": find_int(r"^\s*max_open_disk_fds\s+(\d+)\s*$"),
            "tcp_recv_bufsize_kb": find_size_kb("tcp_recv_bufsize"),
            "store_avg_object_size_kb": find_size_kb("store_avg_object_size"),
            "store_objects_per_bucket": find_int(r"^\s*store_objects_per_bucket\s+(\d+)\s*$"),
            "client_db": find_on_off("client_db"),
            "offline_mode": find_on_off("offline_mode"),
            "paranoid_hit_validation_value": find_str("paranoid_hit_validation"),
            "cpu_affinity_map": find_str("cpu_affinity_map"),
            "visible_hostname": find_str("visible_hostname"),
            "httpd_suppress_version_string": find_on_off("httpd_suppress_version_string"),
            "client_netmask_value": find_str("client_netmask"),
            "strip_query_terms": find_on_off("strip_query_terms"),
            "stats_collection_rules_text": find_block_or_lines("STATS_COLLECTION", prefixes=("stats_collection ",)),
            "tls_key_log_path": find_str("tls_key_log"),
            "cache_policy_rules_text": find_block_or_lines("CACHE_POLICY"),
            "refresh_patterns_text": find_block_or_lines("REFRESH_PATTERNS", prefixes=("refresh_pattern ",)),
        }

    def _get_lines(self, config_text: Optional[str], keys: tuple[str, ...], *, include_icap_include: bool = False) -> list[str]:
        text = config_text if config_text is not None else (self.get_current_config() or "")
        out: list[str] = []
        for line in (text or "").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            lower = stripped.lower()
            if include_icap_include and lower.startswith("include") and "/etc/squid/conf.d/20-icap.conf" in lower:
                out.append(line)
                continue
            if any(lower.startswith(key) for key in keys):
                out.append(line)
        return out

    def get_network_lines(self, config_text: Optional[str] = None) -> list[str]:
        return self._get_lines(
            config_text,
            (
                "client_persistent_connections",
                "server_persistent_connections",
                "client_idle_pconn_timeout",
                "server_idle_pconn_timeout",
                "pconn_timeout",
                "pconn_lifetime",
                "persistent_connection_after_error",
                "detect_broken_pconn",
                "half_closed_clients",
                "server_pconn_for_nonretriable",
                "connect_retries",
                "forward_max_tries",
                "retry_on_error",
                "client_lifetime",
                "client_ip_max_connections",
                "tcp_recv_bufsize",
                "accept_filter",
                "client_dst_passthru",
                "host_verify_strict",
                "on_unsupported_protocol",
                "happy_eyeballs_connect_timeout",
                "happy_eyeballs_connect_gap",
                "happy_eyeballs_connect_limit",
            ),
        )

    def get_dns_lines(self, config_text: Optional[str] = None) -> list[str]:
        return self._get_lines(
            config_text,
            (
                "dns_timeout",
                "dns_retransmit_interval",
                "dns_packet_max",
                "dns_nameservers",
                "hosts_file",
                "append_domain",
                "dns_defnames",
                "dns_multicast_local",
                "ignore_unknown_nameservers",
                "check_hostnames",
                "allow_underscore",
                "positive_dns_ttl",
                "negative_dns_ttl",
                "ipcache_size",
                "ipcache_low",
                "ipcache_high",
                "fqdncache_size",
            ),
        )

    def get_ssl_lines(self, config_text: Optional[str] = None) -> list[str]:
        lines = self._get_lines(
            config_text,
            (
                "sslcrtd_program",
                "sslcrtd_children",
                "sslproxy_session_ttl",
                "sslproxy_session_cache_size",
                "tls_outgoing_options",
                "sslproxy_foreign_intermediate_certs",
                "sslproxy_cert_sign_hash",
                "ssl_unclean_shutdown",
                "sslproxy_cert_error",
                "sslproxy_cert_sign",
                "sslproxy_cert_adapt",
                "ssl_bump",
            ),
        )
        tunables = self.get_tunable_options(config_text)
        dynamic_cert_cache_mb = tunables.get("dynamic_cert_mem_cache_size_mb")
        if dynamic_cert_cache_mb is not None:
            lines.append(f"dynamic_cert_mem_cache_size={dynamic_cert_cache_mb}MB")
        return lines

    def get_icap_lines(self, config_text: Optional[str] = None) -> list[str]:
        return self._get_lines(config_text, ("icap_", "adaptation_", "force_request_body_continuation"), include_icap_include=True)

    def get_privacy_lines(self, config_text: Optional[str] = None) -> list[str]:
        return self._get_lines(config_text, ("forwarded_for", "via", "follow_x_forwarded_for", "client_netmask", "strip_query_terms"))

    def get_limits_lines(self, config_text: Optional[str] = None) -> list[str]:
        return self._get_lines(
            config_text,
            (
                "request_header_max_size",
                "reply_header_max_size",
                "request_body_max_size",
                "client_request_buffer_max_size",
                "relaxed_header_parser",
                "uri_whitespace",
                "http_upgrade_request_protocols",
            ),
        )

    def get_performance_lines(self, config_text: Optional[str] = None) -> list[str]:
        return self._get_lines(
            config_text,
            (
                "workers",
                "hopeless_kid_revival_delay",
                "memory_pools",
                "memory_pools_limit",
                "shared_memory_locking",
                "high_response_time_warning",
                "high_page_fault_warning",
                "max_open_disk_fds",
                "store_avg_object_size",
                "store_objects_per_bucket",
                "client_db",
                "offline_mode",
                "paranoid_hit_validation",
                "cpu_affinity_map",
                "max_filedescriptors",
            ),
        )

    def get_http_lines(self, config_text: Optional[str] = None) -> list[str]:
        return self._get_lines(config_text, ("visible_hostname", "httpd_suppress_version_string", "vary_ignore_expire"))

    def get_logging_lines(self, config_text: Optional[str] = None) -> list[str]:
        return self._get_lines(
            config_text,
            (
                "logformat",
                "access_log",
                "cache_log",
                "cache_store_log",
                "icap_log",
                "logfile_rotate",
                "buffered_logs",
                "log_mime_hdrs",
                "stats_collection",
                "tls_key_log",
            ),
        )

    def get_timeout_lines(self, config_text: Optional[str] = None) -> list[str]:
        return self._get_lines(
            config_text,
            (
                "connect_timeout",
                "peer_connect_timeout",
                "request_timeout",
                "read_timeout",
                "forward_timeout",
                "request_start_timeout",
                "write_timeout",
                "shutdown_lifetime",
            ),
        )

    def get_cache_override_options(self, config_text: Optional[str] = None) -> Dict[str, bool]:
        text = config_text if config_text is not None else self.get_current_config()

        def find_bool(name: str) -> bool:
            match = re.search(rf"^\s*#\s*{re.escape(name)}\s*=\s*([01])\s*$", text or "", re.M)
            return bool(match and match.group(1) == "1")

        return {
            "client_no_cache": find_bool("override_client_no_cache"),
            "client_no_store": find_bool("override_client_no_store"),
            "origin_private": find_bool("override_origin_private"),
            "origin_no_store": find_bool("override_origin_no_store"),
            "origin_no_cache": find_bool("override_origin_no_cache"),
            "ignore_auth": find_bool("override_ignore_auth"),
        }

    def get_caching_lines(self, config_text: Optional[str] = None) -> list[str]:
        return self._get_lines(
            config_text,
            (
                "cache_dir",
                "store_dir_select_algorithm",
                "cache_mem",
                "minimum_object_size",
                "maximum_object_size",
                "maximum_object_size_in_memory",
                "memory_cache_mode",
                "memory_cache_shared",
                "shared_transient_entries_limit",
                "cache_swap_low",
                "cache_swap_high",
                "cache_replacement_policy",
                "memory_replacement_policy",
                "cache_miss_revalidate",
                "pipeline_prefetch",
                "collapsed_forwarding",
                "collapsed_forwarding_access",
                "range_offset_limit",
                "quick_abort_min",
                "quick_abort_max",
                "quick_abort_pct",
                "read_ahead_gap",
                "reload_into_ims",
                "cache ",
                "send_hit",
                "store_miss",
                "refresh_pattern",
                "negative_ttl",
                "minimum_expiry_time",
                "max_stale",
                "refresh_all_ims",
            ),
        )

    def apply_cache_overrides(self, config_text: str, overrides: Dict[str, bool]) -> str:
        values = overrides or {}
        flags = []
        if bool(values.get("client_no_cache")):
            flags.append("ignore-reload")
        if bool(values.get("origin_no_cache")):
            flags.append("ignore-reload")
        if bool(values.get("origin_private")):
            flags.append("ignore-private")
        if bool(values.get("client_no_store")) or bool(values.get("origin_no_store")):
            flags.append("ignore-no-store")

        start_marker = "# Cache overrides (managed by web UI)"
        end_marker = "# End cache overrides"
        text = re.sub(
            rf"^\s*{re.escape(start_marker)}\s*$.*?^\s*{re.escape(end_marker)}\s*$\n?",
            "",
            config_text or "",
            flags=re.M | re.S,
        )

        override_tokens = ("ignore-reload", "ignore-no-cache", "ignore-no-store", "ignore-private", "ignore-auth")

        def should_skip_refresh_pattern(line: str) -> bool:
            return "(/cgi-bin/|\\?)" in line

        out_lines = []
        saw_refresh = False
        for line in text.splitlines(True):
            if re.match(r"^\s*refresh_pattern\b", line):
                saw_refresh = True
                if should_skip_refresh_pattern(line):
                    out_lines.append(line)
                    continue
                stripped = line
                for token in override_tokens:
                    stripped = re.sub(rf"\s+{re.escape(token)}\b", "", stripped)
                if flags:
                    newline = "\n" if stripped.endswith("\n") else ""
                    core = stripped.rstrip("\r\n").rstrip()
                    stripped = core + " " + " ".join(flags) + newline
                out_lines.append(stripped)
                continue
            out_lines.append(line)

        rendered = "".join(out_lines)
        meta_block = "\n".join(
            [
                start_marker,
                f"# override_client_no_cache={'1' if bool(values.get('client_no_cache')) else '0'}",
                f"# override_client_no_store={'1' if bool(values.get('client_no_store')) else '0'}",
                f"# override_origin_private={'1' if bool(values.get('origin_private')) else '0'}",
                f"# override_origin_no_store={'1' if bool(values.get('origin_no_store')) else '0'}",
                f"# override_origin_no_cache={'1' if bool(values.get('origin_no_cache')) else '0'}",
                f"# override_ignore_auth={'1' if bool(values.get('ignore_auth')) else '0'}",
                end_marker,
                "",
            ]
        )

        if saw_refresh:
            rendered = re.sub(r"^(\s*refresh_pattern\b)", meta_block + "\n" + r"\1", rendered, count=1, flags=re.M)
        else:
            rendered = rendered.rstrip() + "\n\n" + meta_block + "\n"
        return rendered

    def generate_config_from_template(self, options: Dict[str, Any]) -> str:
        if not os.path.exists(self.squid_conf_template_path):
            raise FileNotFoundError(self.squid_conf_template_path)

        template_text = self._read_file(self.squid_conf_template_path)

        try:
            dynamic_cert_mem_cache_size_mb = max(0, int(str(options.get("dynamic_cert_mem_cache_size_mb") or "128").strip()))
        except Exception:
            dynamic_cert_mem_cache_size_mb = 128

        rendered = self._replace_http_port_option(template_text, "dynamic_cert_mem_cache_size", f"{dynamic_cert_mem_cache_size_mb}MB")
        managed_block = self._render_managed_settings(options)
        return self._replace_managed_settings_block(rendered, managed_block)

    def generate_config_from_template_with_exclusions(self, options: Dict[str, Any], exclusions: Any) -> str:
        base = self.generate_config_from_template(options)
        domains = [domain.strip().lower().lstrip(".") for domain in (getattr(exclusions, "domains", []) or []) if domain.strip()]
        src_nets = [cidr.strip() for cidr in (getattr(exclusions, "src_nets", []) or []) if cidr.strip()]
        private_dst_nets = PRIVATE_NETS_V4 if bool(getattr(exclusions, "exclude_private_nets", False)) else []

        acl_lines = []
        note_lines = []
        splice_lines = []
        cache_deny_lines = []

        if domains:
            acl_lines.append("acl excluded_domains dstdomain " + " ".join(domains))
            note_lines.append("note exclusion_rule domain excluded_domains")
            splice_lines.append("ssl_bump splice excluded_domains")
            cache_deny_lines.append("cache deny excluded_domains")
        if private_dst_nets:
            acl_lines.append("acl excluded_private_dst dst " + " ".join(private_dst_nets))
            note_lines.append("note exclusion_rule private_dst excluded_private_dst")
            splice_lines.append("ssl_bump splice excluded_private_dst")
            cache_deny_lines.append("cache deny excluded_private_dst")
        if src_nets:
            acl_lines.append("acl excluded_src src " + " ".join(src_nets))
            note_lines.append("note exclusion_rule src excluded_src")
            splice_lines.append("ssl_bump splice excluded_src")
            cache_deny_lines.append("cache deny excluded_src")
        if not (acl_lines or splice_lines or cache_deny_lines):
            return base

        insert_ssl = "\n".join(["", "# Exclusions (managed by web UI)"] + acl_lines + note_lines + splice_lines) + "\n"
        base = base.replace("ssl_bump bump all", insert_ssl + "ssl_bump bump all", 1)

        deny_block = "\n".join(["", "# Exclusions (managed by web UI)"] + cache_deny_lines) + "\n"
        for marker in ("# Logging", "# Log settings", self._MANAGED_SETTINGS_END):
            if marker in base:
                base = base.replace(marker, deny_block + "\n" + marker, 1)
                break
        else:
            base = base.rstrip() + deny_block
        return base

    def start_squid(self):
        try:
            proc = self._run(
                ["supervisorctl", "-c", "/etc/supervisord.conf", "start", "squid"],
                capture_output=True,
                timeout=12,
            )
            if proc.returncode == 0:
                return proc.stdout or b"", proc.stderr or b""
        except FileNotFoundError:
            pass
        except Exception:
            log_exception_throttled(
                logger,
                "squidctl.start_squid.supervisor",
                interval_seconds=300.0,
                message="supervisorctl start squid failed",
            )

        try:
            proc = self._run(["squid", "-f", self.squid_conf_path], capture_output=True, timeout=12)
            return proc.stdout or b"", proc.stderr or b""
        except FileNotFoundError:
            return b"", b"squid binary not found"
        except Exception as exc:
            return b"", str(exc).encode("utf-8", errors="replace")

    def stop_squid(self):
        try:
            proc = self._run(["squid", "-k", "shutdown"], capture_output=True, timeout=12)
            return proc.stdout or b"", proc.stderr or b""
        except FileNotFoundError:
            return b"", b"squid binary not found"
        except Exception as exc:
            return b"", str(exc).encode("utf-8", errors="replace")

    def update_config(self, config_text: str):
        self.apply_config_text(config_text)
