from __future__ import annotations

import contextlib
import logging
import os
import pathlib
import re
from typing import Any

from services.logutil import log_exception_throttled
from services.squid_config_forms import (
    DEFAULT_CACHE_POLICY_RULES,
    DEFAULT_HTTP_UPGRADE_REQUEST_PROTOCOLS_RULES,
    DEFAULT_REFRESH_PATTERNS,
    coerce_config_bool,
)
from services.squid_core import SquidController as _CoreSquidController

logger = logging.getLogger(__name__)


class SquidController(_CoreSquidController):
    # -------------------------------------------------------------------------
    # Input validation helpers for config injection prevention
    # -------------------------------------------------------------------------
    _MANAGED_SETTINGS_START = "# BEGIN SQUID-UI MANAGED SETTINGS"
    _MANAGED_SETTINGS_END = "# END SQUID-UI MANAGED SETTINGS"
    _HOSTNAME_RE = re.compile(
        r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$",
    )
    _IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    _IPV6_SIMPLE_RE = re.compile(r"^[a-fA-F0-9:]+$")
    _CPU_AFFINITY_RE = re.compile(r"^[A-Za-z0-9_,= ]+$")

    def __init__(
        self,
        squid_conf_path: str = "/etc/squid/squid.conf",
        *,
        cmd_run=None,
    ) -> None:
        super().__init__(
            squid_conf_path=squid_conf_path,
            cmd_run=cmd_run or __import__("subprocess").run,
        )
        self.squid_conf_template_path = "/etc/squid/squid.conf.template"
        if (not pathlib.Path(self.squid_conf_template_path).exists()) and pathlib.Path(
            "/squid/squid.conf.template",
        ).exists():
            self.squid_conf_template_path = "/squid/squid.conf.template"

    def _sanitize_single_line(self, value: str, field_name: str) -> str:
        if not value:
            return ""
        clean = value.strip()
        if "\n" in clean or "\r" in clean:
            msg = f"{field_name} must not contain newlines"
            raise ValueError(msg)
        return clean

    def _validate_hostname(self, value: str, field_name: str = "hostname") -> str:
        clean = self._sanitize_single_line(value, field_name)
        if not clean:
            return ""
        if len(clean) > 253:
            msg = f"{field_name} too long (max 253 characters)"
            raise ValueError(msg)
        if not self._HOSTNAME_RE.match(clean):
            msg = f"{field_name} contains invalid characters"
            raise ValueError(msg)
        return clean

    def _validate_hosts_file_path(
        self,
        value: str,
        field_name: str = "hosts_file",
    ) -> str:
        clean = self._sanitize_single_line(value, field_name)
        if not clean:
            return ""
        if clean.lower() == "none":
            return "none"
        forbidden = set("|;&$`\"'\\<>(){}[]!#~")
        if any(char in clean for char in forbidden):
            msg = f"{field_name} contains forbidden characters"
            raise ValueError(msg)
        if not clean.startswith("/"):
            msg = f"{field_name} must be an absolute path"
            raise ValueError(msg)
        return clean

    def _validate_append_domain(
        self,
        value: str,
        field_name: str = "append_domain",
    ) -> str:
        clean = self._sanitize_single_line(value, field_name)
        if not clean:
            return ""
        if not clean.startswith("."):
            msg = f"{field_name} must begin with a dot"
            raise ValueError(msg)
        return clean

    def _validate_dns_nameservers(
        self,
        value: str,
        field_name: str = "dns_nameservers",
    ) -> str:
        clean = self._sanitize_single_line(value, field_name)
        if not clean:
            return ""
        for part in clean.split():
            if self._IP_RE.match(part):
                for octet in part.split("."):
                    if int(octet) > 255:
                        msg = f"{field_name} contains invalid IP address: {part}"
                        raise ValueError(msg)
            elif self._IPV6_SIMPLE_RE.match(part) or self._HOSTNAME_RE.match(part):
                pass
            else:
                msg = f"{field_name} contains invalid entry: {part}"
                raise ValueError(msg)
        return clean

    def _validate_choice(
        self,
        value: str,
        allowed: tuple[str, ...],
        field_name: str,
    ) -> str:
        clean = self._sanitize_single_line(value, field_name).lower()
        if clean not in allowed:
            msg = f"{field_name} must be one of: {', '.join(allowed)}"
            raise ValueError(msg)
        return clean

    def _validate_cpu_affinity_map(
        self,
        value: str,
        field_name: str = "cpu_affinity_map",
    ) -> str:
        clean = self._sanitize_single_line(value, field_name)
        if not clean:
            return ""
        if not self._CPU_AFFINITY_RE.match(clean):
            msg = f"{field_name} contains invalid characters"
            raise ValueError(msg)
        return clean

    def _validate_single_line_value(self, value: str, field_name: str) -> str:
        return self._sanitize_single_line(value, field_name)

    def _extract_managed_subblock(self, text: str, block_name: str) -> str | None:
        pattern = re.compile(
            rf"^\s*# BEGIN SQUID-UI BLOCK: {re.escape(block_name)}\s*$\n?(.*?)^\s*# END SQUID-UI BLOCK: {re.escape(block_name)}\s*$",
            re.MULTILINE | re.DOTALL,
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
            re.MULTILINE | re.DOTALL,
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

    def _render_managed_settings(self, options: dict[str, Any]) -> str:
        def int_value(
            name: str,
            default: int,
            *,
            minimum: int | None = None,
            maximum: int | None = None,
        ) -> int:
            raw = options.get(name)
            try:
                value = (
                    int(str(raw).strip())
                    if raw is not None and str(raw).strip() != ""
                    else int(default)
                )
            except Exception:
                value = int(default)
            if minimum is not None:
                value = max(minimum, value)
            if maximum is not None:
                value = min(maximum, value)
            return value

        def optional_int_value(name: str) -> int | None:
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
            return coerce_config_bool(raw, default)

        def append_section(lines: list[str], title: str, description: str = "") -> None:
            if lines and lines[-1] != "":
                lines.append("")
            lines.append(f"# {title}")
            if description:
                lines.append(f"# {description}")

        def append_block(lines: list[str], block_name: str, content: str) -> None:
            rendered = self._render_managed_subblock(
                block_name,
                self._normalize_multiline_text(content),
            )
            lines.extend(rendered.splitlines())

        cache_dir_type = self._validate_choice(
            str(options.get("cache_dir_type") or "rock"),
            ("rock", "ufs"),
            "cache_dir_type",
        )
        cache_dir_size_mb = int_value("cache_dir_size_mb", 10000, minimum=100)
        cache_dir_ufs_l1 = int_value("cache_dir_ufs_l1", 16, minimum=1)
        cache_dir_ufs_l2 = int_value("cache_dir_ufs_l2", 256, minimum=1)
        cache_dir_rock_slot_size_kb = int_value(
            "cache_dir_rock_slot_size_kb",
            32,
            minimum=4,
        )
        cache_dir_rock_swap_timeout_ms = optional_int_value(
            "cache_dir_rock_swap_timeout_ms",
        )
        cache_dir_rock_max_swap_rate = optional_int_value(
            "cache_dir_rock_max_swap_rate",
        )
        store_dir_select_algorithm = self._validate_choice(
            str(options.get("store_dir_select_algorithm") or "least-load"),
            ("least-load", "round-robin"),
            "store_dir_select_algorithm",
        )

        cache_mem_mb = int_value("cache_mem_mb", 256, minimum=16)
        maximum_object_size_mb = int_value("maximum_object_size_mb", 128, minimum=1)
        maximum_object_size_in_memory_kb = int_value(
            "maximum_object_size_in_memory_kb",
            2048,
            minimum=0,
        )
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

        shared_transient_entries_limit = int_value(
            "shared_transient_entries_limit",
            16384,
            minimum=0,
        )
        cache_swap_low = int_value("cache_swap_low", 90, minimum=0, maximum=100)
        cache_swap_high = int_value("cache_swap_high", 95, minimum=0, maximum=100)
        collapsed_forwarding_on = bool_value("collapsed_forwarding_on", True)
        collapsed_forwarding_access_rules_text = self._normalize_multiline_text(
            options.get("collapsed_forwarding_access_rules_text") or "",
        )
        range_cache_on = bool_value("range_cache_on", True)
        range_offset_limit_value = self._sanitize_single_line(
            str(options.get("range_offset_limit_value") or "128 MB"),
            "range_offset_limit_value",
        )
        if not range_cache_on:
            range_offset_limit_value = "0"
        else:
            normalized_range = range_offset_limit_value.strip().lower()
            if normalized_range in {
                "",
                "0",
                "0 b",
                "0 byte",
                "0 bytes",
                "0 kb",
                "0 mb",
                "off",
                "false",
            }:
                range_offset_limit_value = "128 MB"
            elif normalized_range == "-1":
                range_offset_limit_value = "none"
        cache_miss_revalidate_on = bool_value("cache_miss_revalidate_on", True)
        reload_into_ims_on = bool_value("reload_into_ims_on", False)
        pipeline_prefetch_on = bool_value("pipeline_prefetch_on", False)
        pipeline_prefetch_count = int_value(
            "pipeline_prefetch_count",
            0,
            minimum=0,
            maximum=16,
        )
        if not pipeline_prefetch_on:
            pipeline_prefetch_count = 0
        elif pipeline_prefetch_count <= 0:
            pipeline_prefetch_count = 1
        read_ahead_gap_kb = int_value("read_ahead_gap_kb", 16, minimum=0)
        quick_abort_min_kb = int_value("quick_abort_min_kb", 16)
        quick_abort_max_kb = int_value("quick_abort_max_kb", 16, minimum=0)
        quick_abort_pct = int_value("quick_abort_pct", 95, minimum=0, maximum=100)
        negative_ttl_seconds = int_value("negative_ttl_seconds", 0, minimum=0)
        minimum_expiry_time_seconds = int_value(
            "minimum_expiry_time_seconds",
            60,
            minimum=0,
        )
        max_stale_seconds = int_value("max_stale_seconds", 7 * 24 * 3600, minimum=0)
        refresh_all_ims_on = bool_value("refresh_all_ims_on", False)
        cache_policy_rules_text = self._normalize_multiline_text(
            options.get("cache_policy_rules_text") or DEFAULT_CACHE_POLICY_RULES,
        )
        refresh_patterns_text = self._normalize_multiline_text(
            options.get("refresh_patterns_text") or DEFAULT_REFRESH_PATTERNS,
        )

        client_persistent_connections_on = bool_value(
            "client_persistent_connections_on",
            True,
        )
        server_persistent_connections_on = bool_value(
            "server_persistent_connections_on",
            True,
        )
        buffered_logs_on = bool_value("buffered_logs_on", False)
        log_mime_hdrs_on = bool_value("log_mime_hdrs_on", False)
        logfile_rotate = int_value("logfile_rotate", 10, minimum=0)
        stats_collection_rules_text = self._normalize_multiline_text(
            options.get("stats_collection_rules_text") or "",
        )
        tls_key_log_path = self._validate_single_line_value(
            str(options.get("tls_key_log_path") or ""),
            "tls_key_log",
        )

        memory_pools_on = bool_value("memory_pools_on", True)
        memory_pools_limit_raw = options.get("memory_pools_limit_mb")
        if memory_pools_limit_raw is None or str(memory_pools_limit_raw).strip() == "":
            memory_pools_limit_value = "64 MB"
        elif str(memory_pools_limit_raw).strip().lower() == "none":
            memory_pools_limit_value = "none"
        else:
            memory_pools_limit_value = (
                f"{int_value('memory_pools_limit_mb', 64, minimum=0)} MB"
            )
        shared_memory_locking_on = bool_value("shared_memory_locking_on", False)
        max_open_disk_fds = int_value("max_open_disk_fds", 0, minimum=0)
        hopeless_kid_revival_delay_seconds = int_value(
            "hopeless_kid_revival_delay_seconds",
            3600,
            minimum=1,
        )
        high_response_time_warning_ms = optional_int_value(
            "high_response_time_warning_ms",
        )
        high_page_fault_warning = optional_int_value("high_page_fault_warning")
        store_avg_object_size_kb = int_value("store_avg_object_size_kb", 13, minimum=0)
        store_objects_per_bucket = int_value("store_objects_per_bucket", 20, minimum=0)
        client_db_on = bool_value("client_db_on", True)
        offline_mode_on = bool_value("offline_mode_on", False)
        paranoid_hit_validation_value = (
            self._validate_single_line_value(
                str(options.get("paranoid_hit_validation_value") or "0"),
                "paranoid_hit_validation",
            )
            or "0"
        )
        cpu_affinity_map = self._validate_cpu_affinity_map(
            str(options.get("cpu_affinity_map") or ""),
        )
        max_filedescriptors = int_value("max_filedescriptors", 65535, minimum=0)

        client_idle_pconn_timeout_seconds = int_value(
            "client_idle_pconn_timeout_seconds",
            120,
            minimum=0,
        )
        server_idle_pconn_timeout_seconds = int_value(
            "server_idle_pconn_timeout_seconds",
            60,
            minimum=0,
        )
        pconn_lifetime_seconds = int_value("pconn_lifetime_seconds", 0, minimum=0)
        persistent_connection_after_error_on = bool_value(
            "persistent_connection_after_error_on",
            True,
        )
        detect_broken_pconn_on = bool_value("detect_broken_pconn_on", False)
        half_closed_clients_on = bool_value("half_closed_clients_on", False)
        connect_retries = int_value("connect_retries", 0, minimum=0, maximum=10)
        forward_max_tries = int_value("forward_max_tries", 25, minimum=1)
        retry_on_error_on = bool_value("retry_on_error_on", False)
        client_lifetime_seconds = int_value(
            "client_lifetime_seconds",
            24 * 3600,
            minimum=0,
        )
        client_ip_max_connections = optional_int_value("client_ip_max_connections")
        tcp_recv_bufsize_kb = optional_int_value("tcp_recv_bufsize_kb")
        accept_filter_value = self._validate_single_line_value(
            str(options.get("accept_filter_value") or ""),
            "accept_filter",
        )
        server_pconn_for_nonretriable_rules_text = self._normalize_multiline_text(
            options.get("server_pconn_for_nonretriable_rules_text") or "",
        )
        client_dst_passthru_on = bool_value("client_dst_passthru_on", True)
        host_verify_strict_on = bool_value("host_verify_strict_on", False)
        on_unsupported_protocol_action = self._validate_choice(
            str(options.get("on_unsupported_protocol_action") or "respond"),
            ("respond", "tunnel"),
            "on_unsupported_protocol_action",
        )
        happy_eyeballs_connect_timeout_ms = int_value(
            "happy_eyeballs_connect_timeout_ms",
            250,
            minimum=0,
        )
        happy_eyeballs_connect_gap_ms = optional_int_value(
            "happy_eyeballs_connect_gap_ms",
        )
        happy_eyeballs_connect_limit = optional_int_value(
            "happy_eyeballs_connect_limit",
        )

        connect_timeout_seconds = int_value("connect_timeout_seconds", 60, minimum=0)
        peer_connect_timeout_seconds = int_value(
            "peer_connect_timeout_seconds",
            30,
            minimum=0,
        )
        request_start_timeout_seconds = int_value(
            "request_start_timeout_seconds",
            300,
            minimum=0,
        )
        request_timeout_seconds = int_value("request_timeout_seconds", 300, minimum=0)
        read_timeout_seconds = int_value("read_timeout_seconds", 900, minimum=0)
        forward_timeout_seconds = int_value("forward_timeout_seconds", 240, minimum=0)
        write_timeout_seconds = int_value("write_timeout_seconds", 900, minimum=0)
        shutdown_lifetime_seconds = int_value(
            "shutdown_lifetime_seconds",
            30,
            minimum=0,
        )

        dns_timeout_seconds = int_value("dns_timeout_seconds", 30, minimum=0)
        dns_retransmit_interval_seconds = int_value(
            "dns_retransmit_interval_seconds",
            5,
            minimum=0,
        )
        dns_packet_max_raw = self._validate_single_line_value(
            str(options.get("dns_packet_max") or ""),
            "dns_packet_max",
        )
        dns_nameservers = self._validate_dns_nameservers(
            str(options.get("dns_nameservers") or ""),
        )
        hosts_file = (
            self._validate_hosts_file_path(
                str(options.get("hosts_file") or "/etc/hosts"),
            )
            or "/etc/hosts"
        )
        append_domain = (
            self._validate_append_domain(str(options.get("append_domain") or ""))
            if str(options.get("append_domain") or "").strip()
            else ""
        )
        dns_defnames_on = bool_value("dns_defnames_on", False)
        dns_multicast_local_on = bool_value("dns_multicast_local_on", False)
        ignore_unknown_nameservers_on = bool_value(
            "ignore_unknown_nameservers_on",
            True,
        )
        check_hostnames_on = bool_value("check_hostnames_on", False)
        allow_underscore_on = bool_value("allow_underscore_on", True)
        positive_dns_ttl_seconds = int_value(
            "positive_dns_ttl_seconds",
            6 * 3600,
            minimum=1,
        )
        negative_dns_ttl_seconds = int_value("negative_dns_ttl_seconds", 60, minimum=1)
        ipcache_size = int_value("ipcache_size", 8192, minimum=0)
        ipcache_low = int_value("ipcache_low", 90, minimum=0, maximum=100)
        ipcache_high = int_value("ipcache_high", 95, minimum=0, maximum=100)
        fqdncache_size = int_value("fqdncache_size", 8192, minimum=0)

        sslcrtd_program_cache_size_mb = int_value(
            "sslcrtd_program_cache_size_mb",
            16,
            minimum=1,
        )
        sslcrtd_children = int_value("sslcrtd_children", 4, minimum=1, maximum=32)
        sslcrtd_children_startup = int_value(
            "sslcrtd_children_startup",
            min(sslcrtd_children, 2),
            minimum=0,
        )
        sslcrtd_children_idle = int_value("sslcrtd_children_idle", 1, minimum=1)
        sslcrtd_children_queue_size = int_value(
            "sslcrtd_children_queue_size",
            max(32, sslcrtd_children * 8),
            minimum=1,
        )
        tls_outgoing_options_line = (
            self._validate_single_line_value(
                str(
                    options.get("tls_outgoing_options_line")
                    or "min-version=1.2 options=NO_SSLv3",
                ),
                "tls_outgoing_options",
            )
            or "min-version=1.2 options=NO_SSLv3"
        )
        sslproxy_session_ttl_seconds = int_value(
            "sslproxy_session_ttl_seconds",
            600,
            minimum=0,
        )
        sslproxy_session_cache_size_mb = int_value(
            "sslproxy_session_cache_size_mb",
            32,
            minimum=0,
        )
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
        additional_ssl_rules_text = self._normalize_multiline_text(
            options.get("additional_ssl_rules_text") or "",
        )
        sslproxy_cert_error_rules_text = self._normalize_multiline_text(
            options.get("sslproxy_cert_error_rules_text") or "",
        )
        sslproxy_cert_sign_rules_text = self._normalize_multiline_text(
            options.get("sslproxy_cert_sign_rules_text") or "",
        )
        sslproxy_cert_adapt_rules_text = self._normalize_multiline_text(
            options.get("sslproxy_cert_adapt_rules_text") or "",
        )

        icap_enable_on = bool_value("icap_enable_on", True)
        icap_206_enable_on = bool_value("icap_206_enable_on", True)
        icap_send_client_ip_on = bool_value("icap_send_client_ip_on", True)
        icap_send_client_username_on = bool_value("icap_send_client_username_on", False)
        icap_client_username_header = (
            self._validate_single_line_value(
                str(options.get("icap_client_username_header") or "X-Client-Username"),
                "icap_client_username_header",
            )
            or "X-Client-Username"
        )
        icap_client_username_encode_on = bool_value(
            "icap_client_username_encode_on",
            False,
        )
        icap_persistent_connections_on = bool_value(
            "icap_persistent_connections_on",
            True,
        )
        icap_preview_enable_on = bool_value("icap_preview_enable_on", True)
        icap_preview_size_kb = int_value("icap_preview_size_kb", 128, minimum=0)
        icap_default_options_ttl_seconds = int_value(
            "icap_default_options_ttl_seconds",
            300,
            minimum=0,
        )
        icap_connect_timeout_seconds = int_value(
            "icap_connect_timeout_seconds",
            15,
            minimum=0,
        )
        icap_io_timeout_seconds = int_value("icap_io_timeout_seconds", 300, minimum=0)
        icap_service_failure_limit = int_value("icap_service_failure_limit", 10)
        icap_service_failure_limit_window_seconds = int_value(
            "icap_service_failure_limit_window_seconds",
            30,
            minimum=0,
        )
        icap_service_revival_delay_seconds = int_value(
            "icap_service_revival_delay_seconds",
            60,
            minimum=0,
        )
        adaptation_service_iteration_limit = int_value(
            "adaptation_service_iteration_limit",
            16,
            minimum=1,
        )
        force_request_body_continuation_rules_text = self._normalize_multiline_text(
            options.get("force_request_body_continuation_rules_text") or "",
        )
        icap_retry_rules_text = self._normalize_multiline_text(
            options.get("icap_retry_rules_text") or "",
        )
        icap_retry_limit = int_value("icap_retry_limit", 0, minimum=0)

        forwarded_for_value_raw = str(options.get("forwarded_for_value") or "").strip()
        if forwarded_for_value_raw and forwarded_for_value_raw not in {
            "on",
            "off",
            "transparent",
            "delete",
            "truncate",
        }:
            forwarded_for_value_raw = ""
        via_on = bool_value("via_on", True)
        follow_x_forwarded_for_value = self._validate_single_line_value(
            str(options.get("follow_x_forwarded_for_value") or ""),
            "follow_x_forwarded_for",
        )
        client_netmask_value = self._validate_single_line_value(
            str(options.get("client_netmask_value") or ""),
            "client_netmask",
        )
        strip_query_terms_on = bool_value("strip_query_terms_on", True)

        request_header_max_size_kb = int_value(
            "request_header_max_size_kb",
            64,
            minimum=1,
        )
        reply_header_max_size_kb = int_value("reply_header_max_size_kb", 64, minimum=1)
        request_body_max_size_mb = int_value("request_body_max_size_mb", 0, minimum=0)
        client_request_buffer_max_size_kb = int_value(
            "client_request_buffer_max_size_kb",
            512,
            minimum=0,
        )
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
        http_upgrade_request_protocols_rules_text = self._normalize_multiline_text(
            options.get("http_upgrade_request_protocols_rules_text")
            if options.get("http_upgrade_request_protocols_rules_text") is not None
            else DEFAULT_HTTP_UPGRADE_REQUEST_PROTOCOLS_RULES,
        )

        visible_hostname = self._validate_hostname(
            str(options.get("visible_hostname") or ""),
            "visible_hostname",
        )
        cache_mgr_email = (
            self._validate_single_line_value(
                str(options.get("cache_mgr_email") or "proxy-admin@example.invalid"),
                "cache_mgr",
            )
            or "proxy-admin@example.invalid"
        )
        httpd_suppress_version_string_on = bool_value(
            "httpd_suppress_version_string_on",
            False,
        )
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

        append_section(
            lines,
            "SMP mode",
            "Worker, helper, and TLS interception settings managed by the Admin UI.",
        )
        lines.extend(
            (
                f"workers {workers}",
                f"hopeless_kid_revival_delay {hopeless_kid_revival_delay_seconds} seconds",
                f"sslcrtd_program /usr/lib/squid/ssl_crtd -s /var/lib/ssl_db/store -M {sslcrtd_program_cache_size_mb}MB",
                f"sslcrtd_children {sslcrtd_children} startup={sslcrtd_children_startup} idle={sslcrtd_children_idle} queue-size={sslcrtd_children_queue_size}",
                "acl step1 at_step SslBump1",
                "acl step2 at_step SslBump2",
                "acl step3 at_step SslBump3",
                "# Peek at step 1 to learn ClientHello/SNI without sacrificing later bumping.",
                "ssl_bump peek step1",
            ),
        )
        if coerce_config_bool(
            options.get("https_intercept_enabled_on"),
        ) and coerce_config_bool(
            options.get("https_intercept_splice_only_on"),
        ):
            lines.extend(
                (
                    "# Splice all traffic arriving on the dedicated HTTPS NAT intercept listener.",
                    "acl https_intercept_listener myportname https_intercept",
                    "ssl_bump splice https_intercept_listener",
                ),
            )
        lines.append("include /etc/squid/conf.d/10-sslfilter.conf")
        append_block(lines, "CUSTOM_SSL_RULES", additional_ssl_rules_text)
        lines.extend(
            (
                "# Stare at step 2 so the default path can inspect server certificates and still bump at step 3.",
                "ssl_bump stare step2",
                "ssl_bump bump step3",
            ),
        )

        append_section(
            lines,
            "Cache settings",
            "Disk layout, memory sizing, and cache heuristics.",
        )
        lines.extend(
            (
                cache_dir_line,
                f"store_dir_select_algorithm {store_dir_select_algorithm}",
                f"maximum_object_size {maximum_object_size_mb} MB",
                f"maximum_object_size_in_memory {maximum_object_size_in_memory_kb} KB",
                f"minimum_object_size {minimum_object_size_kb} KB",
                f"cache_mem {cache_mem_mb} MB",
                f"memory_cache_mode {memory_cache_mode}",
                f"memory_cache_shared {'on' if memory_cache_shared_on else 'off'}",
                f"shared_transient_entries_limit {shared_transient_entries_limit}",
                f"cache_replacement_policy {cache_replacement_policy}",
                f"memory_replacement_policy {memory_replacement_policy}",
                f"cache_swap_low {cache_swap_low}",
                f"cache_swap_high {cache_swap_high}",
                f"collapsed_forwarding {'on' if collapsed_forwarding_on else 'off'}",
            ),
        )
        append_block(
            lines,
            "COLLAPSED_FORWARDING_ACCESS",
            collapsed_forwarding_access_rules_text,
        )
        lines.extend(
            (
                f"range_offset_limit {range_offset_limit_value}",
                f"cache_miss_revalidate {'on' if cache_miss_revalidate_on else 'off'}",
                f"reload_into_ims {'on' if reload_into_ims_on else 'off'}",
                f"pipeline_prefetch {pipeline_prefetch_count}",
                f"read_ahead_gap {read_ahead_gap_kb} KB",
                f"quick_abort_min {quick_abort_min_kb} KB",
                f"quick_abort_max {quick_abort_max_kb} KB",
                f"quick_abort_pct {quick_abort_pct}",
                f"negative_ttl {negative_ttl_seconds} seconds",
                f"minimum_expiry_time {minimum_expiry_time_seconds} seconds",
                f"max_stale {max_stale_seconds} seconds",
                f"refresh_all_ims {'on' if refresh_all_ims_on else 'off'}",
            ),
        )
        append_block(lines, "CACHE_POLICY", cache_policy_rules_text)
        append_block(lines, "REFRESH_PATTERNS", refresh_patterns_text)

        append_section(
            lines,
            "Connection behavior",
            "Keep-alive reuse, retry behavior, and socket tuning.",
        )
        lines.extend(
            (
                f"client_persistent_connections {'on' if client_persistent_connections_on else 'off'}",
                f"server_persistent_connections {'on' if server_persistent_connections_on else 'off'}",
                f"client_idle_pconn_timeout {client_idle_pconn_timeout_seconds} seconds",
                f"server_idle_pconn_timeout {server_idle_pconn_timeout_seconds} seconds",
                f"pconn_lifetime {pconn_lifetime_seconds} seconds",
                f"persistent_connection_after_error {'on' if persistent_connection_after_error_on else 'off'}",
                f"detect_broken_pconn {'on' if detect_broken_pconn_on else 'off'}",
                f"half_closed_clients {'on' if half_closed_clients_on else 'off'}",
            ),
        )
        append_block(
            lines,
            "SERVER_PCONN_FOR_NONRETRIABLE",
            server_pconn_for_nonretriable_rules_text,
        )
        lines.extend(
            (
                f"connect_retries {connect_retries}",
                f"forward_max_tries {forward_max_tries}",
                f"retry_on_error {'on' if retry_on_error_on else 'off'}",
                f"client_lifetime {client_lifetime_seconds} seconds",
            ),
        )
        if client_ip_max_connections is not None:
            lines.append(
                f"client_ip_max_connections {max(0, client_ip_max_connections)}",
            )
        if tcp_recv_bufsize_kb is not None:
            lines.append(f"tcp_recv_bufsize {max(0, tcp_recv_bufsize_kb)} KB")
        if accept_filter_value:
            lines.append(f"accept_filter {accept_filter_value}")
        lines.extend(
            (
                f"client_dst_passthru {'on' if client_dst_passthru_on else 'off'}",
                f"host_verify_strict {'on' if host_verify_strict_on else 'off'}",
                f"on_unsupported_protocol {on_unsupported_protocol_action} all",
                f"happy_eyeballs_connect_timeout {happy_eyeballs_connect_timeout_ms} ms",
            ),
        )
        if happy_eyeballs_connect_gap_ms is not None:
            lines.append(
                f"happy_eyeballs_connect_gap {max(0, happy_eyeballs_connect_gap_ms)} ms",
            )
        if happy_eyeballs_connect_limit is not None:
            lines.append(
                f"happy_eyeballs_connect_limit {max(0, happy_eyeballs_connect_limit)}",
            )

        append_section(lines, "Timeouts", "Request, forwarding, and shutdown timers.")
        lines.extend(
            (
                f"connect_timeout {connect_timeout_seconds} seconds",
                f"peer_connect_timeout {peer_connect_timeout_seconds} seconds",
                f"request_timeout {request_timeout_seconds} seconds",
                f"read_timeout {read_timeout_seconds} seconds",
                f"forward_timeout {forward_timeout_seconds} seconds",
                f"request_start_timeout {request_start_timeout_seconds} seconds",
                f"write_timeout {write_timeout_seconds} seconds",
                f"shutdown_lifetime {shutdown_lifetime_seconds} seconds",
            ),
        )

        append_section(
            lines,
            "Resolver and DNS cache tuning",
            "Resolver source selection, hostname validation, and DNS cache sizing.",
        )
        lines.extend(
            (
                f"dns_timeout {dns_timeout_seconds} seconds",
                f"dns_retransmit_interval {dns_retransmit_interval_seconds} seconds",
            ),
        )
        if dns_packet_max_raw:
            if dns_packet_max_raw.lower() == "none":
                lines.append("dns_packet_max none")
            elif dns_packet_max_raw.isdigit():
                lines.append(f"dns_packet_max {int(dns_packet_max_raw)} bytes")
        if dns_nameservers:
            lines.append(f"dns_nameservers {dns_nameservers}")
        lines.append(f"hosts_file {hosts_file}")
        if append_domain:
            lines.append(f"append_domain {append_domain}")
        lines.extend(
            (
                f"dns_defnames {'on' if dns_defnames_on else 'off'}",
                f"dns_multicast_local {'on' if dns_multicast_local_on else 'off'}",
                f"ignore_unknown_nameservers {'on' if ignore_unknown_nameservers_on else 'off'}",
                f"check_hostnames {'on' if check_hostnames_on else 'off'}",
                f"allow_underscore {'on' if allow_underscore_on else 'off'}",
                f"positive_dns_ttl {positive_dns_ttl_seconds} seconds",
                f"negative_dns_ttl {negative_dns_ttl_seconds} seconds",
                f"ipcache_size {ipcache_size}",
                f"ipcache_low {ipcache_low}",
                f"ipcache_high {ipcache_high}",
                f"fqdncache_size {fqdncache_size}",
            ),
        )

        append_section(
            lines,
            "Origin-facing TLS",
            "Session reuse, signing policy, and certificate-chain behavior.",
        )
        lines.extend(
            (
                f"tls_outgoing_options {tls_outgoing_options_line}",
                f"sslproxy_session_ttl {sslproxy_session_ttl_seconds} seconds",
                f"sslproxy_session_cache_size {sslproxy_session_cache_size_mb} MB",
            ),
        )
        if sslproxy_foreign_intermediate_certs:
            lines.append(
                f"sslproxy_foreign_intermediate_certs {sslproxy_foreign_intermediate_certs}",
            )
        lines.extend(
            (
                f"sslproxy_cert_sign_hash {sslproxy_cert_sign_hash}",
                f"ssl_unclean_shutdown {'on' if ssl_unclean_shutdown_on else 'off'}",
            ),
        )
        append_block(lines, "SSLPROXY_CERT_ERROR", sslproxy_cert_error_rules_text)
        append_block(lines, "SSLPROXY_CERT_SIGN", sslproxy_cert_sign_rules_text)
        append_block(lines, "SSLPROXY_CERT_ADAPT", sslproxy_cert_adapt_rules_text)

        append_section(
            lines,
            "Logging",
            "Rotation, MIME/header logging, and optional low-level diagnostics.",
        )
        lines.extend(
            (
                f"logfile_rotate {logfile_rotate}",
                f"buffered_logs {'on' if buffered_logs_on else 'off'}",
                f"log_mime_hdrs {'on' if log_mime_hdrs_on else 'off'}",
            ),
        )
        append_block(lines, "STATS_COLLECTION", stats_collection_rules_text)
        if tls_key_log_path:
            lines.append(f"tls_key_log {tls_key_log_path}")

        append_section(
            lines,
            "ICAP adaptation",
            "The container still generates service endpoints dynamically; these directives control Squid-side ICAP behavior.",
        )
        lines.extend(
            (
                f"icap_enable {'on' if icap_enable_on else 'off'}",
                f"icap_206_enable {'on' if icap_206_enable_on else 'off'}",
                f"adaptation_send_client_ip {'on' if icap_send_client_ip_on else 'off'}",
                f"adaptation_send_username {'on' if icap_send_client_username_on else 'off'}",
                f"icap_client_username_header {icap_client_username_header}",
                f"icap_client_username_encode {'on' if icap_client_username_encode_on else 'off'}",
                f"icap_persistent_connections {'on' if icap_persistent_connections_on else 'off'}",
                f"icap_preview_enable {'on' if icap_preview_enable_on else 'off'}",
                f"icap_preview_size {icap_preview_size_kb} KB",
                f"icap_default_options_ttl {icap_default_options_ttl_seconds}",
                f"icap_service_failure_limit {icap_service_failure_limit} in {icap_service_failure_limit_window_seconds} seconds",
                f"icap_service_revival_delay {icap_service_revival_delay_seconds} seconds",
                f"icap_connect_timeout {icap_connect_timeout_seconds} seconds",
                f"icap_io_timeout {icap_io_timeout_seconds} seconds",
                f"adaptation_service_iteration_limit {adaptation_service_iteration_limit}",
            ),
        )
        append_block(
            lines,
            "FORCE_REQUEST_BODY_CONTINUATION",
            force_request_body_continuation_rules_text,
        )
        append_block(lines, "ICAP_RETRY", icap_retry_rules_text)
        lines.extend(
            (
                f"icap_retry_limit {icap_retry_limit}",
                "include /etc/squid/conf.d/20-icap.conf",
            ),
        )

        append_section(
            lines,
            "Privacy and header handling",
            "Forwarding metadata, client anonymity, and parser tolerance.",
        )
        if forwarded_for_value_raw:
            lines.append(f"forwarded_for {forwarded_for_value_raw}")
        lines.append(f"via {'on' if via_on else 'off'}")
        if follow_x_forwarded_for_value:
            lines.append(f"follow_x_forwarded_for {follow_x_forwarded_for_value}")
        if client_netmask_value:
            lines.append(f"client_netmask {client_netmask_value}")
        lines.extend(
            (
                f"strip_query_terms {'on' if strip_query_terms_on else 'off'}",
                f"request_header_max_size {request_header_max_size_kb} KB",
                f"reply_header_max_size {reply_header_max_size_kb} KB",
                f"request_body_max_size {request_body_max_size_mb} MB",
                f"client_request_buffer_max_size {client_request_buffer_max_size_kb} KB",
                f"relaxed_header_parser {relaxed_header_parser_mode}",
                f"uri_whitespace {uri_whitespace_mode}",
            ),
        )
        append_block(
            lines,
            "HTTP_UPGRADE_REQUEST_PROTOCOLS",
            http_upgrade_request_protocols_rules_text,
        )

        append_section(
            lines,
            "Performance and cache index behavior",
            "Memory pools, descriptor limits, and cache-hit integrity checks.",
        )
        lines.extend(
            (
                f"memory_pools {'on' if memory_pools_on else 'off'}",
                f"memory_pools_limit {memory_pools_limit_value}",
                f"shared_memory_locking {'on' if shared_memory_locking_on else 'off'}",
            ),
        )
        if high_response_time_warning_ms is not None:
            lines.append(f"high_response_time_warning {high_response_time_warning_ms}")
        if high_page_fault_warning is not None:
            lines.append(f"high_page_fault_warning {high_page_fault_warning}")
        lines.extend(
            (
                f"max_open_disk_fds {max_open_disk_fds}",
                f"store_avg_object_size {store_avg_object_size_kb} KB",
                f"store_objects_per_bucket {store_objects_per_bucket}",
                f"client_db {'on' if client_db_on else 'off'}",
                f"offline_mode {'on' if offline_mode_on else 'off'}",
                f"paranoid_hit_validation {paranoid_hit_validation_value}",
            ),
        )
        if cpu_affinity_map:
            lines.append(f"cpu_affinity_map {cpu_affinity_map}")
        lines.append(f"max_filedescriptors {max_filedescriptors}")

        append_section(
            lines,
            "HTTP identity",
            "How Squid identifies itself and handles a few compatibility edge cases.",
        )
        if visible_hostname:
            lines.append(f"visible_hostname {visible_hostname}")
        lines.extend(
            (
                f"cache_mgr {cache_mgr_email}",
                f"httpd_suppress_version_string {'on' if httpd_suppress_version_string_on else 'off'}",
                f"vary_ignore_expire {'on' if vary_ignore_expire_on else 'off'}",
                self._MANAGED_SETTINGS_END,
            ),
        )
        return "\n".join(lines)

    def _read_file(self, path: str) -> str:
        with pathlib.Path(path).open(encoding="utf-8") as handle:
            return handle.read()

    def _replace_or_append_line(self, text: str, key: str, new_line: str) -> str:
        pattern = re.compile(rf"^(\s*{re.escape(key)}\s+).*$", re.MULTILINE)
        if pattern.search(text):
            return pattern.sub(new_line, text, count=1)
        return text.rstrip() + "\n" + new_line + "\n"

    def _replace_cache_dir_line(self, text: str, new_line: str) -> str:
        pattern = re.compile(r"^\s*cache_dir\s+\w+\s+\S+.*$", re.MULTILINE)
        if pattern.search(text):
            return pattern.sub(new_line, text, count=1)
        return text.rstrip() + "\n" + new_line + "\n"

    def _replace_http_port_option(
        self,
        text: str,
        option_name: str,
        option_value: str,
    ) -> str:
        pattern = re.compile(rf"({re.escape(option_name)}=)(\S+)", re.IGNORECASE)
        if pattern.search(text):
            return pattern.sub(
                lambda match: f"{match.group(1)}{option_value}",
                text,
                count=1,
            )
        return text

    def _coerce_port(self, value: Any, default: int) -> int:
        try:
            parsed = int(str(value or "").strip() or str(default))
        except Exception:
            parsed = int(default)
        return min(65535, max(1, parsed))

    def _default_intercept_port(self, explicit_port: int) -> int:
        return explicit_port + 1 if explicit_port < 65535 else 3129

    def _first_available_port(self, preferred: int, used_ports: set[int]) -> int:
        candidate = self._coerce_port(preferred, 3130)
        for _ in range(65535):
            if candidate not in used_ports:
                return candidate
            candidate = 1 if candidate >= 65535 else candidate + 1
        msg = "No available TCP listener ports remain."
        raise ValueError(msg)

    def _logical_config_lines(self, text: str) -> list[tuple[list[str], str]]:
        logical: list[tuple[list[str], str]] = []
        pending: list[str] = []
        for raw_line in (text or "").splitlines():
            pending.append(raw_line)
            if raw_line.rstrip().endswith("\\"):
                continue
            joined = " ".join(
                line.rstrip().rstrip("\\").strip() for line in pending
            ).strip()
            logical.append((pending, joined))
            pending = []
        if pending:
            joined = " ".join(
                line.rstrip().rstrip("\\").strip() for line in pending
            ).strip()
            logical.append((pending, joined))
        return logical

    def _extract_http_port_number(self, address_token: str) -> int | None:
        token = (address_token or "").strip()
        if not token:
            return None
        if token.isdigit():
            return self._coerce_port(token, 3128)
        if (token.startswith("[") and "]:" in token) or ":" in token:
            candidate = token.rsplit(":", 1)[1]
        else:
            return None
        if not candidate.isdigit():
            return None
        return self._coerce_port(candidate, 3128)

    def _http_port_listener_settings(self, text: str) -> dict[str, Any]:
        explicit_port: int | None = None
        intercept_port: int | None = None
        https_intercept_port: int | None = None
        for _physical_lines, logical in self._logical_config_lines(text):
            stripped = logical.strip()
            if not stripped or stripped.startswith("#"):
                continue
            lower = stripped.lower()
            if not (lower.startswith(("http_port ", "https_port "))):
                continue
            parts = stripped.split()
            if len(parts) < 2:
                continue
            port = self._extract_http_port_number(parts[1])
            if port is None:
                continue
            modes = {part.strip().lower() for part in parts[2:]}
            if lower.startswith("https_port ") and "intercept" in modes:
                if https_intercept_port is None:
                    https_intercept_port = port
            elif lower.startswith("http_port ") and "intercept" in modes:
                if intercept_port is None:
                    intercept_port = port
            elif lower.startswith("http_port ") and "tproxy" not in modes:
                if explicit_port is None:
                    explicit_port = port

        explicit = explicit_port if explicit_port is not None else 3128
        https_intercept_splice_only = bool(
            re.search(
                r"^\s*ssl_bump\s+splice\s+https_intercept_listener\s*$",
                text or "",
                re.MULTILINE | re.IGNORECASE,
            ),
        )
        return {
            "explicit_proxy_port": explicit,
            "intercept_enabled": intercept_port is not None,
            "intercept_port": intercept_port
            if intercept_port is not None
            else self._default_intercept_port(explicit),
            "https_intercept_enabled": https_intercept_port is not None,
            "https_intercept_port": https_intercept_port
            if https_intercept_port is not None
            else (3130 if explicit != 3130 else 3131),
            "https_intercept_splice_only": https_intercept_splice_only
            and https_intercept_port is not None,
        }

    def _render_explicit_http_port(
        self,
        port: int,
        dynamic_cert_mem_cache_size_mb: int,
    ) -> list[str]:
        return [
            f"http_port 0.0.0.0:{self._coerce_port(port, 3128)} ssl-bump \\",
            "\tcert=/etc/squid/ssl/certs/ca.crt \\",
            "\tkey=/etc/squid/ssl/certs/ca.key \\",
            "\tgenerate-host-certificates=on \\",
            f"\tdynamic_cert_mem_cache_size={max(0, int(dynamic_cert_mem_cache_size_mb))}MB",
        ]

    def _render_intercept_http_port_block(self, port: int) -> list[str]:
        return [
            "# BEGIN SQUID-UI INTERCEPT LISTENER",
            "# HTTP NAT intercept listener. Requires external REDIRECT/DNAT rules; do not expose directly.",
            f"http_port 0.0.0.0:{self._coerce_port(port, 3129)} intercept",
            "# END SQUID-UI INTERCEPT LISTENER",
        ]

    def _render_https_intercept_port_block(
        self,
        port: int,
        dynamic_cert_mem_cache_size_mb: int,
    ) -> list[str]:
        return [
            "# BEGIN SQUID-UI HTTPS INTERCEPT LISTENER",
            "# HTTPS NAT intercept listener. Requires TCP/443 REDIRECT/DNAT and explicit operator consent.",
            f"https_port 0.0.0.0:{self._coerce_port(port, 3130)} intercept ssl-bump \\",
            "\tname=https_intercept \\",
            "\tcert=/etc/squid/ssl/certs/ca.crt \\",
            "\tkey=/etc/squid/ssl/certs/ca.key \\",
            "\tgenerate-host-certificates=on \\",
            f"\tdynamic_cert_mem_cache_size={max(0, int(dynamic_cert_mem_cache_size_mb))}MB",
            "# END SQUID-UI HTTPS INTERCEPT LISTENER",
        ]

    def _render_http_port_listeners(
        self,
        text: str,
        options: dict[str, Any],
        dynamic_cert_mem_cache_size_mb: int,
    ) -> str:
        explicit_port = self._coerce_port(options.get("explicit_proxy_port"), 3128)
        intercept_enabled = coerce_config_bool(options.get("intercept_enabled_on"))
        intercept_port = self._coerce_port(
            options.get("intercept_port"),
            self._default_intercept_port(explicit_port),
        )
        https_intercept_enabled = coerce_config_bool(
            options.get("https_intercept_enabled_on"),
        )
        https_intercept_port = self._coerce_port(
            options.get("https_intercept_port"),
            3130 if explicit_port != 3130 else 3131,
        )
        logical_lines = self._logical_config_lines(text)
        unmanaged_listener_ports: set[int] = set()
        found_replaced_explicit = False
        scanning_managed_intercept = False
        for physical_lines, logical in logical_lines:
            if any(
                "# BEGIN SQUID-UI INTERCEPT LISTENER" in line for line in physical_lines
            ) or any(
                "# BEGIN SQUID-UI HTTPS INTERCEPT LISTENER" in line
                for line in physical_lines
            ):
                scanning_managed_intercept = True
            if scanning_managed_intercept:
                if any(
                    "# END SQUID-UI INTERCEPT LISTENER" in line
                    for line in physical_lines
                ) or any(
                    "# END SQUID-UI HTTPS INTERCEPT LISTENER" in line
                    for line in physical_lines
                ):
                    scanning_managed_intercept = False
                continue

            stripped = logical.strip()
            if not stripped or stripped.startswith("#"):
                continue
            lower = stripped.lower()
            if not lower.startswith(("http_port ", "https_port ")):
                continue
            parts = stripped.split()
            if len(parts) < 2:
                continue
            port = self._extract_http_port_number(parts[1])
            if port is None:
                continue
            modes = {part.strip().lower() for part in parts[2:]}
            if (
                lower.startswith("http_port ")
                and "intercept" not in modes
                and "tproxy" not in modes
                and not found_replaced_explicit
            ):
                found_replaced_explicit = True
                continue
            unmanaged_listener_ports.add(port)

        if intercept_port == explicit_port:
            intercept_port = self._default_intercept_port(explicit_port)
            if intercept_port == explicit_port:
                intercept_port = 3129 if explicit_port != 3129 else 3130
        used_ports = {
            explicit_port,
            intercept_port if intercept_enabled else None,
            *unmanaged_listener_ports,
        }
        https_intercept_port = self._first_available_port(
            https_intercept_port,
            used_ports,
        )

        rendered_lines: list[str] = []
        replaced_explicit = False
        skipping_managed_intercept = False
        for physical_lines, logical in logical_lines:
            stripped = logical.strip()
            if any(
                "# BEGIN SQUID-UI INTERCEPT LISTENER" in line for line in physical_lines
            ) or any(
                "# BEGIN SQUID-UI HTTPS INTERCEPT LISTENER" in line
                for line in physical_lines
            ):
                skipping_managed_intercept = True
            if skipping_managed_intercept:
                if any(
                    "# END SQUID-UI INTERCEPT LISTENER" in line
                    for line in physical_lines
                ) or any(
                    "# END SQUID-UI HTTPS INTERCEPT LISTENER" in line
                    for line in physical_lines
                ):
                    skipping_managed_intercept = False
                continue

            if (
                stripped
                and not stripped.startswith("#")
                and stripped.lower().startswith("http_port ")
            ):
                parts = stripped.split()
                modes = {part.strip().lower() for part in parts[2:]}
                if (
                    "intercept" not in modes
                    and "tproxy" not in modes
                    and not replaced_explicit
                ):
                    rendered_lines.extend(
                        self._render_explicit_http_port(
                            explicit_port,
                            dynamic_cert_mem_cache_size_mb,
                        ),
                    )
                    if intercept_enabled:
                        rendered_lines.extend(
                            self._render_intercept_http_port_block(intercept_port),
                        )
                    if https_intercept_enabled:
                        rendered_lines.extend(
                            self._render_https_intercept_port_block(
                                https_intercept_port,
                                dynamic_cert_mem_cache_size_mb,
                            ),
                        )
                    replaced_explicit = True
                    continue

            rendered_lines.extend(physical_lines)

        if not replaced_explicit:
            prefix = self._render_explicit_http_port(
                explicit_port,
                dynamic_cert_mem_cache_size_mb,
            )
            if intercept_enabled:
                prefix.extend(self._render_intercept_http_port_block(intercept_port))
            if https_intercept_enabled:
                prefix.extend(
                    self._render_https_intercept_port_block(
                        https_intercept_port,
                        dynamic_cert_mem_cache_size_mb,
                    ),
                )
            rendered_lines = [*prefix, "", *rendered_lines]
        return "\n".join(rendered_lines) + ("\n" if text.endswith("\n") else "")

    def get_tunable_options(self, config_text: str | None = None) -> dict[str, Any]:
        text = (
            config_text
            if config_text is not None
            else (self.get_current_config() or "")
        )

        def find_int(pattern: str) -> int | None:
            match = re.search(pattern, text, re.MULTILINE | re.IGNORECASE)
            return int(match.group(1)) if match else None

        def find_int_or_none(key: str) -> Any | None:
            match = re.search(
                rf"^\s*{re.escape(key)}\s+(\S+)(?:\s+\S+)?\s*$",
                text,
                re.MULTILINE | re.IGNORECASE,
            )
            if not match:
                return None
            value = (match.group(1) or "").strip()
            if value.lower() == "none":
                return "none"
            try:
                return int(value)
            except Exception:
                return None

        def find_on_off(key: str) -> bool | None:
            match = re.search(
                rf"^\s*{re.escape(key)}\s+(on|off)\s*$",
                text,
                re.MULTILINE | re.IGNORECASE,
            )
            if not match:
                return None
            return match.group(1).lower() == "on"

        def find_choice_token(key: str, allowed: tuple[str, ...]) -> str | None:
            match = re.search(
                rf"^\s*{re.escape(key)}\s+(\S+)\s*$",
                text,
                re.MULTILINE | re.IGNORECASE,
            )
            if not match:
                return None
            token = (match.group(1) or "").strip()
            return token if token in allowed else None

        def find_time_seconds(key: str) -> int | None:
            match = re.search(
                rf"^\s*{re.escape(key)}\s+(\d+)\s*([a-zA-Z]+)?\s*$",
                text,
                re.MULTILINE,
            )
            if not match:
                return None
            try:
                value = int(match.group(1))
            except Exception:
                return None
            unit = (match.group(2) or "").strip().lower()
            if not unit:
                return value
            if unit in {"s", "sec", "secs", "second", "seconds"}:
                return value
            if unit in {"m", "min", "mins", "minute", "minutes"}:
                return value * 60
            if unit in {"h", "hr", "hrs", "hour", "hours"}:
                return value * 3600
            if unit in {"d", "day", "days"}:
                return value * 86400
            return value

        def find_time_milliseconds(key: str) -> int | None:
            match = re.search(
                rf"^\s*{re.escape(key)}\s+(\d+)\s*([a-zA-Z]+)?\s*$",
                text,
                re.MULTILINE | re.IGNORECASE,
            )
            if not match:
                return None
            try:
                value = int(match.group(1))
            except Exception:
                return None
            unit = (match.group(2) or "").strip().lower()
            if not unit:
                return value
            if unit in {"ms", "msec", "msecs", "millisecond", "milliseconds"}:
                return value
            if unit in {"s", "sec", "secs", "second", "seconds"}:
                return value * 1000
            if unit in {"m", "min", "mins", "minute", "minutes"}:
                return value * 60 * 1000
            return value

        def find_str(key: str) -> str | None:
            match = re.search(
                rf"^\s*{re.escape(key)}\s+(.+?)\s*$",
                text,
                re.MULTILINE | re.IGNORECASE,
            )
            return match.group(1).strip() if match else None

        def find_kb(key: str) -> int | None:
            match = re.search(
                rf"^\s*{re.escape(key)}\s+(\d+)\s*(KB|K|KBYTES)?\s*$",
                text,
                re.MULTILINE | re.IGNORECASE,
            )
            return int(match.group(1)) if match else None

        def find_pct(key: str) -> int | None:
            match = re.search(
                rf"^\s*{re.escape(key)}\s+(\d+)\s*%?\s*$",
                text,
                re.MULTILINE | re.IGNORECASE,
            )
            return int(match.group(1)) if match else None

        def _size_to_bytes(value: str, unit: str) -> int | None:
            try:
                number = int(value)
            except Exception:
                return None
            normalized_unit = (unit or "").strip().lower()
            if normalized_unit in {"", "b", "bytes"}:
                return number
            if normalized_unit in {"k", "kb", "kib", "kbytes"}:
                return number * 1024
            if normalized_unit in {"m", "mb", "mib", "mbytes"}:
                return number * 1024 * 1024
            if normalized_unit in {"g", "gb", "gib", "gbytes"}:
                return number * 1024 * 1024 * 1024
            return None

        def find_size_kb(key: str) -> int | None:
            match = re.search(
                rf"^\s*{re.escape(key)}\s+(\d+)\s*([A-Za-z]+)?\s*$",
                text,
                re.MULTILINE | re.IGNORECASE,
            )
            if not match:
                return None
            size_bytes = _size_to_bytes(match.group(1), match.group(2) or "")
            if size_bytes is None:
                return None
            return int(size_bytes // 1024)

        def find_size_mb(key: str) -> int | None:
            match = re.search(
                rf"^\s*{re.escape(key)}\s+(\d+)\s*([A-Za-z]+)?\s*$",
                text,
                re.MULTILINE | re.IGNORECASE,
            )
            if not match:
                return None
            size_bytes = _size_to_bytes(match.group(1), match.group(2) or "")
            if size_bytes is None:
                return None
            return int(size_bytes // (1024 * 1024))

        def find_size_mb_or_none(key: str) -> Any | None:
            match = re.search(
                rf"^\s*{re.escape(key)}\s+(\S+)(?:\s+([A-Za-z]+))?\s*$",
                text,
                re.MULTILINE | re.IGNORECASE,
            )
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

        def find_range_offset_limit_mb() -> int | None:
            match = re.search(
                r"^\s*range_offset_limit\s+(-?\d+)\s*([A-Za-z]+)?\s*$",
                text,
                re.MULTILINE | re.IGNORECASE,
            )
            if not match:
                return None
            if match.group(1) == "-1":
                return -1
            size_bytes = _size_to_bytes(match.group(1), match.group(2) or "")
            if size_bytes is None:
                return None
            return int(size_bytes // (1024 * 1024))

        def find_range_offset_limit_value() -> str | None:
            match = re.search(
                r"^\s*range_offset_limit\s+(.+?)\s*$",
                text,
                re.MULTILINE | re.IGNORECASE,
            )
            return (match.group(1) or "").strip() if match else None

        def find_pipeline_prefetch_bool() -> bool | None:
            match = re.search(
                r"^\s*pipeline_prefetch\s+(\S+)\s*$",
                text,
                re.MULTILINE | re.IGNORECASE,
            )
            if not match:
                return None
            value = (match.group(1) or "").strip().lower()
            if value in {"on", "true", "yes"}:
                return True
            if value in {"off", "false", "no"}:
                return False
            try:
                return int(value) >= 1
            except Exception:
                return None

        def find_pipeline_prefetch_count() -> int | None:
            match = re.search(
                r"^\s*pipeline_prefetch\s+(\S+)\s*$",
                text,
                re.MULTILINE | re.IGNORECASE,
            )
            if not match:
                return None
            value = (match.group(1) or "").strip().lower()
            if value in {"on", "true", "yes"}:
                return 1
            if value in {"off", "false", "no"}:
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
                if store_type in {"rock", "ufs"}:
                    result["cache_dir_type"] = store_type
                with contextlib.suppress(Exception):
                    result["cache_dir_size_mb"] = int(parts[3])
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
                                result["cache_dir_rock_slot_size_kb"] = int(
                                    size_bytes // 1024,
                                )
                        elif key == "swap-timeout":
                            with contextlib.suppress(Exception):
                                result["cache_dir_rock_swap_timeout_ms"] = int(
                                    raw_value,
                                )
                        elif key == "max-swap-rate":
                            with contextlib.suppress(Exception):
                                result["cache_dir_rock_max_swap_rate"] = int(raw_value)
                return result
            return {}

        def find_sslcrtd_program_cache_size_mb() -> int | None:
            match = re.search(
                r"^\s*sslcrtd_program\s+.*?\s-M\s*(\d+)\s*([A-Za-z]+)?\s*$",
                text,
                re.MULTILINE | re.IGNORECASE,
            )
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

        def find_dynamic_cert_mem_cache_size_mb() -> int | None:
            match = re.search(
                r"dynamic_cert_mem_cache_size\s*=\s*(\d+)\s*([A-Za-z]+)?",
                text,
                re.IGNORECASE,
            )
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
                re.MULTILINE | re.IGNORECASE,
            )
            if not match:
                return {}
            result: dict[str, Any] = {}
            with contextlib.suppress(Exception):
                result["icap_service_failure_limit"] = int(match.group(1))
            if match.group(2):
                try:
                    window_value = int(match.group(2))
                except Exception:
                    window_value = 0
                unit = (match.group(3) or "").strip().lower()
                multiplier = 1
                if unit in {"m", "min", "mins", "minute", "minutes"}:
                    multiplier = 60
                elif unit in {"h", "hr", "hrs", "hour", "hours"}:
                    multiplier = 3600
                elif unit in {"d", "day", "days"}:
                    multiplier = 86400
                result["icap_service_failure_limit_window_seconds"] = (
                    window_value * multiplier
                )
            return result

        def find_block_or_lines(
            block_name: str,
            *,
            prefixes: tuple[str, ...] = (),
        ) -> str | None:
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
        http_listener_settings = self._http_port_listener_settings(text)
        sslcrtd_settings = find_sslcrtd_children_settings()
        icap_failure_settings = find_icap_service_failure_limit()
        on_unsupported_protocol_value = find_str("on_unsupported_protocol")
        on_unsupported_protocol_action = None
        if on_unsupported_protocol_value:
            on_unsupported_protocol_action = (
                on_unsupported_protocol_value.split() or [None]
            )[0]

        return {
            "cache_dir_type": cache_dir_settings.get("cache_dir_type"),
            "cache_dir_size_mb": cache_dir_settings.get("cache_dir_size_mb"),
            "cache_dir_ufs_l1": cache_dir_settings.get("cache_dir_ufs_l1"),
            "cache_dir_ufs_l2": cache_dir_settings.get("cache_dir_ufs_l2"),
            "cache_dir_rock_slot_size_kb": cache_dir_settings.get(
                "cache_dir_rock_slot_size_kb",
            ),
            "cache_dir_rock_swap_timeout_ms": cache_dir_settings.get(
                "cache_dir_rock_swap_timeout_ms",
            ),
            "cache_dir_rock_max_swap_rate": cache_dir_settings.get(
                "cache_dir_rock_max_swap_rate",
            ),
            "store_dir_select_algorithm": find_choice_token(
                "store_dir_select_algorithm",
                ("least-load", "round-robin"),
            ),
            "cache_mem_mb": find_int(r"^\s*cache_mem\s+(\d+)\s*MB\s*$"),
            "maximum_object_size_mb": find_int(
                r"^\s*maximum_object_size\s+(\d+)\s*MB\s*$",
            ),
            "maximum_object_size_in_memory_kb": find_int(
                r"^\s*maximum_object_size_in_memory\s+(\d+)\s*KB\s*$",
            ),
            "minimum_object_size_kb": find_kb("minimum_object_size"),
            "memory_cache_mode": find_str("memory_cache_mode"),
            "memory_cache_shared": find_on_off("memory_cache_shared"),
            "shared_transient_entries_limit": find_int(
                r"^\s*shared_transient_entries_limit\s+(\d+)\s*$",
            ),
            "cache_swap_low": find_int(r"^\s*cache_swap_low\s+(\d+)\s*$"),
            "cache_swap_high": find_int(r"^\s*cache_swap_high\s+(\d+)\s*$"),
            "collapsed_forwarding": find_on_off("collapsed_forwarding"),
            "range_offset_limit": find_range_offset_limit_mb(),
            "range_offset_limit_value": find_range_offset_limit_value(),
            "collapsed_forwarding_access_rules_text": find_block_or_lines(
                "COLLAPSED_FORWARDING_ACCESS",
                prefixes=("collapsed_forwarding_access ",),
            ),
            "client_persistent_connections": find_on_off(
                "client_persistent_connections",
            ),
            "server_persistent_connections": find_on_off(
                "server_persistent_connections",
            ),
            "negative_ttl_seconds": find_time_seconds("negative_ttl"),
            "positive_dns_ttl_seconds": find_time_seconds("positive_dns_ttl"),
            "negative_dns_ttl_seconds": find_time_seconds("negative_dns_ttl"),
            "minimum_expiry_time_seconds": find_time_seconds("minimum_expiry_time"),
            "max_stale_seconds": find_time_seconds("max_stale"),
            "refresh_all_ims": find_on_off("refresh_all_ims"),
            "reload_into_ims": find_on_off("reload_into_ims"),
            "read_ahead_gap_kb": find_kb("read_ahead_gap"),
            "workers": find_int(r"^\s*workers\s+(\d+)\s*$"),
            "hopeless_kid_revival_delay_seconds": find_time_seconds(
                "hopeless_kid_revival_delay",
            ),
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
            "server_idle_pconn_timeout_seconds": find_time_seconds(
                "server_idle_pconn_timeout",
            )
            or find_time_seconds("pconn_timeout"),
            "client_idle_pconn_timeout_seconds": find_time_seconds(
                "client_idle_pconn_timeout",
            ),
            "pconn_timeout_seconds": find_time_seconds("server_idle_pconn_timeout")
            or find_time_seconds("pconn_timeout"),
            "pconn_lifetime_seconds": find_time_seconds("pconn_lifetime"),
            "persistent_connection_after_error": find_on_off(
                "persistent_connection_after_error",
            ),
            "detect_broken_pconn": find_on_off("detect_broken_pconn"),
            "half_closed_clients": find_on_off("half_closed_clients"),
            "connect_retries": find_int(r"^\s*connect_retries\s+(\d+)\s*$"),
            "forward_max_tries": find_int(r"^\s*forward_max_tries\s+(\d+)\s*$"),
            "retry_on_error": find_on_off("retry_on_error"),
            "client_lifetime_seconds": find_time_seconds("client_lifetime"),
            "client_ip_max_connections": find_int(
                r"^\s*client_ip_max_connections\s+(\d+)\s*$",
            ),
            "accept_filter_value": find_str("accept_filter"),
            "client_dst_passthru": find_on_off("client_dst_passthru"),
            "host_verify_strict": find_on_off("host_verify_strict"),
            "on_unsupported_protocol_action": on_unsupported_protocol_action,
            "happy_eyeballs_connect_timeout_ms": find_time_milliseconds(
                "happy_eyeballs_connect_timeout",
            ),
            "happy_eyeballs_connect_gap_ms": find_time_milliseconds(
                "happy_eyeballs_connect_gap",
            ),
            "happy_eyeballs_connect_limit": find_int(
                r"^\s*happy_eyeballs_connect_limit\s+(\d+)\s*$",
            ),
            "server_pconn_for_nonretriable_rules_text": find_block_or_lines(
                "SERVER_PCONN_FOR_NONRETRIABLE",
                prefixes=("server_pconn_for_nonretriable ",),
            ),
            "explicit_proxy_port": http_listener_settings.get("explicit_proxy_port"),
            "intercept_enabled": http_listener_settings.get("intercept_enabled"),
            "intercept_enabled_on": http_listener_settings.get("intercept_enabled"),
            "intercept_port": http_listener_settings.get("intercept_port"),
            "https_intercept_enabled": http_listener_settings.get(
                "https_intercept_enabled",
            ),
            "https_intercept_enabled_on": http_listener_settings.get(
                "https_intercept_enabled",
            ),
            "https_intercept_port": http_listener_settings.get("https_intercept_port"),
            "https_intercept_splice_only": http_listener_settings.get(
                "https_intercept_splice_only",
            ),
            "https_intercept_splice_only_on": http_listener_settings.get(
                "https_intercept_splice_only",
            ),
            "max_filedescriptors": find_int(r"^\s*max_filedescriptors\s+(\d+)\s*$"),
            "dns_timeout_seconds": find_time_seconds("dns_timeout"),
            "dns_retransmit_interval_seconds": find_time_seconds(
                "dns_retransmit_interval",
            ),
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
            "sslcrtd_children_startup": sslcrtd_settings.get(
                "sslcrtd_children_startup",
            ),
            "sslcrtd_children_idle": sslcrtd_settings.get("sslcrtd_children_idle"),
            "sslcrtd_children_queue_size": sslcrtd_settings.get(
                "sslcrtd_children_queue_size",
            ),
            "dynamic_cert_mem_cache_size_mb": find_dynamic_cert_mem_cache_size_mb(),
            "tls_outgoing_options_line": find_str("tls_outgoing_options"),
            "sslproxy_session_ttl_seconds": find_time_seconds("sslproxy_session_ttl"),
            "sslproxy_session_cache_size_mb": find_size_mb(
                "sslproxy_session_cache_size",
            ),
            "sslproxy_foreign_intermediate_certs": find_str(
                "sslproxy_foreign_intermediate_certs",
            ),
            "sslproxy_cert_sign_hash": find_str("sslproxy_cert_sign_hash"),
            "ssl_unclean_shutdown": find_on_off("ssl_unclean_shutdown"),
            "additional_ssl_rules_text": find_block_or_lines("CUSTOM_SSL_RULES"),
            "sslproxy_cert_error_rules_text": find_block_or_lines(
                "SSLPROXY_CERT_ERROR",
                prefixes=("sslproxy_cert_error ",),
            ),
            "sslproxy_cert_sign_rules_text": find_block_or_lines(
                "SSLPROXY_CERT_SIGN",
                prefixes=("sslproxy_cert_sign ",),
            ),
            "sslproxy_cert_adapt_rules_text": find_block_or_lines(
                "SSLPROXY_CERT_ADAPT",
                prefixes=("sslproxy_cert_adapt ",),
            ),
            "icap_enable": find_on_off("icap_enable"),
            "icap_206_enable": find_on_off("icap_206_enable"),
            "icap_send_client_ip": next(
                (
                    value
                    for value in (
                        find_on_off("adaptation_send_client_ip"),
                        find_on_off("icap_send_client_ip"),
                    )
                    if value is not None
                ),
                None,
            ),
            "icap_send_client_username": next(
                (
                    value
                    for value in (
                        find_on_off("adaptation_send_username"),
                        find_on_off("icap_send_client_username"),
                    )
                    if value is not None
                ),
                None,
            ),
            "icap_client_username_header": find_str("icap_client_username_header"),
            "icap_client_username_encode": find_on_off("icap_client_username_encode"),
            "icap_persistent_connections": find_on_off("icap_persistent_connections"),
            "icap_preview_enable": find_on_off("icap_preview_enable"),
            "icap_preview_size_kb": find_size_kb("icap_preview_size"),
            "icap_default_options_ttl_seconds": find_time_seconds(
                "icap_default_options_ttl",
            ),
            "icap_connect_timeout_seconds": find_time_seconds("icap_connect_timeout"),
            "icap_io_timeout_seconds": find_time_seconds("icap_io_timeout"),
            "icap_service_failure_limit": icap_failure_settings.get(
                "icap_service_failure_limit",
            ),
            "icap_service_failure_limit_window_seconds": icap_failure_settings.get(
                "icap_service_failure_limit_window_seconds",
            ),
            "icap_service_revival_delay_seconds": find_time_seconds(
                "icap_service_revival_delay",
            ),
            "adaptation_service_iteration_limit": find_int(
                r"^\s*adaptation_service_iteration_limit\s+(\d+)\s*$",
            ),
            "force_request_body_continuation_rules_text": find_block_or_lines(
                "FORCE_REQUEST_BODY_CONTINUATION",
                prefixes=("force_request_body_continuation ",),
            ),
            "icap_retry_rules_text": find_block_or_lines(
                "ICAP_RETRY",
                prefixes=("icap_retry ",),
            ),
            "icap_retry_limit": find_int(r"^\s*icap_retry_limit\s+(\d+)\s*$"),
            "forwarded_for_value": find_str("forwarded_for"),
            "via": find_on_off("via"),
            "follow_x_forwarded_for_value": find_str("follow_x_forwarded_for"),
            "request_header_max_size_kb": find_size_kb("request_header_max_size"),
            "reply_header_max_size_kb": find_size_kb("reply_header_max_size"),
            "request_body_max_size_mb": find_size_mb("request_body_max_size"),
            "client_request_buffer_max_size_kb": find_size_kb(
                "client_request_buffer_max_size",
            ),
            "relaxed_header_parser_mode": find_choice_token(
                "relaxed_header_parser",
                ("on", "warn", "off"),
            ),
            "uri_whitespace_mode": find_choice_token(
                "uri_whitespace",
                ("strip", "deny", "allow", "encode", "chop"),
            ),
            "http_upgrade_request_protocols_rules_text": find_block_or_lines(
                "HTTP_UPGRADE_REQUEST_PROTOCOLS",
                prefixes=("http_upgrade_request_protocols ",),
            ),
            "vary_ignore_expire": find_on_off("vary_ignore_expire"),
            "memory_pools": find_on_off("memory_pools"),
            "memory_pools_limit_mb": find_size_mb_or_none("memory_pools_limit"),
            "shared_memory_locking": find_on_off("shared_memory_locking"),
            "high_response_time_warning_ms": find_int(
                r"^\s*high_response_time_warning\s+(\d+)\s*$",
            ),
            "high_page_fault_warning": find_int(
                r"^\s*high_page_fault_warning\s+(\d+)\s*$",
            ),
            "max_open_disk_fds": find_int(r"^\s*max_open_disk_fds\s+(\d+)\s*$"),
            "tcp_recv_bufsize_kb": find_size_kb("tcp_recv_bufsize"),
            "store_avg_object_size_kb": find_size_kb("store_avg_object_size"),
            "store_objects_per_bucket": find_int(
                r"^\s*store_objects_per_bucket\s+(\d+)\s*$",
            ),
            "client_db": find_on_off("client_db"),
            "offline_mode": find_on_off("offline_mode"),
            "paranoid_hit_validation_value": find_str("paranoid_hit_validation"),
            "cpu_affinity_map": find_str("cpu_affinity_map"),
            "visible_hostname": find_str("visible_hostname"),
            "cache_mgr_email": find_str("cache_mgr"),
            "httpd_suppress_version_string": find_on_off(
                "httpd_suppress_version_string",
            ),
            "client_netmask_value": find_str("client_netmask"),
            "strip_query_terms": find_on_off("strip_query_terms"),
            "stats_collection_rules_text": find_block_or_lines(
                "STATS_COLLECTION",
                prefixes=("stats_collection ",),
            ),
            "tls_key_log_path": find_str("tls_key_log"),
            "cache_policy_rules_text": find_block_or_lines("CACHE_POLICY"),
            "refresh_patterns_text": find_block_or_lines(
                "REFRESH_PATTERNS",
                prefixes=("refresh_pattern ",),
            ),
        }

    def _get_lines(
        self,
        config_text: str | None,
        keys: tuple[str, ...],
        *,
        include_icap_include: bool = False,
    ) -> list[str]:
        text = (
            config_text
            if config_text is not None
            else (self.get_current_config() or "")
        )
        out: list[str] = []
        for line in (text or "").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            lower = stripped.lower()
            if (
                include_icap_include
                and lower.startswith("include")
                and "/etc/squid/conf.d/20-icap.conf" in lower
            ):
                out.append(line)
                continue
            if any(lower.startswith(key) for key in keys):
                out.append(line)
        return out

    def get_network_lines(self, config_text: str | None = None) -> list[str]:
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
                "http_port",
                "https_port",
            ),
        )

    def get_dns_lines(self, config_text: str | None = None) -> list[str]:
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

    def get_ssl_lines(self, config_text: str | None = None) -> list[str]:
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

    def get_icap_lines(self, config_text: str | None = None) -> list[str]:
        return self._get_lines(
            config_text,
            ("icap_", "adaptation_", "force_request_body_continuation"),
            include_icap_include=True,
        )

    def get_privacy_lines(self, config_text: str | None = None) -> list[str]:
        return self._get_lines(
            config_text,
            (
                "forwarded_for",
                "via",
                "follow_x_forwarded_for",
                "client_netmask",
                "strip_query_terms",
            ),
        )

    def get_limits_lines(self, config_text: str | None = None) -> list[str]:
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

    def get_performance_lines(self, config_text: str | None = None) -> list[str]:
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

    def get_http_lines(self, config_text: str | None = None) -> list[str]:
        return self._get_lines(
            config_text,
            (
                "visible_hostname",
                "cache_mgr",
                "httpd_suppress_version_string",
                "vary_ignore_expire",
            ),
        )

    def get_logging_lines(self, config_text: str | None = None) -> list[str]:
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

    def get_timeout_lines(self, config_text: str | None = None) -> list[str]:
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

    def get_cache_override_options(
        self,
        config_text: str | None = None,
    ) -> dict[str, bool]:
        text = config_text if config_text is not None else self.get_current_config()

        def find_bool(name: str) -> bool:
            match = re.search(
                rf"^\s*#\s*{re.escape(name)}\s*=\s*([01])\s*$",
                text or "",
                re.MULTILINE,
            )
            return bool(match and match.group(1) == "1")

        return {
            "override_expire": find_bool("override_expire"),
            "override_lastmod": find_bool("override_lastmod"),
            "reload_into_ims": find_bool("reload_into_ims"),
            "ignore_reload": find_bool("ignore_reload")
            or find_bool("override_client_no_cache")
            or find_bool("override_origin_no_cache"),
            "ignore_no_store": find_bool("ignore_no_store")
            or find_bool("override_client_no_store")
            or find_bool("override_origin_no_store"),
            "ignore_private": find_bool("ignore_private")
            or find_bool("override_origin_private"),
        }

    def get_caching_lines(self, config_text: str | None = None) -> list[str]:
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

    def apply_cache_overrides(
        self,
        config_text: str,
        overrides: dict[str, bool],
    ) -> str:
        values = overrides or {}
        override_flag_map = (
            ("override_expire", "override-expire"),
            ("override_lastmod", "override-lastmod"),
            ("reload_into_ims", "reload-into-ims"),
            ("ignore_reload", "ignore-reload", "client_no_cache", "origin_no_cache"),
            (
                "ignore_no_store",
                "ignore-no-store",
                "client_no_store",
                "origin_no_store",
            ),
            ("ignore_private", "ignore-private", "origin_private"),
        )
        flags = [
            option
            for key, option, *legacy_keys in override_flag_map
            if bool(values.get(key))
            or any(bool(values.get(legacy_key)) for legacy_key in legacy_keys)
        ]

        start_marker = "# Cache overrides (managed by web UI)"
        end_marker = "# End cache overrides"
        text = re.sub(
            rf"^\s*{re.escape(start_marker)}\s*$.*?^\s*{re.escape(end_marker)}\s*$\n?",
            "",
            config_text or "",
            flags=re.MULTILINE | re.DOTALL,
        )

        override_tokens = (
            "override-expire",
            "override-lastmod",
            "reload-into-ims",
            "ignore-reload",
            "ignore-no-store",
            "ignore-private",
            # Obsolete legacy options accepted with warnings by some Squid builds; strip them too.
            "ignore-no-cache",
            "ignore-must-revalidate",
            "ignore-auth",
        )

        def should_skip_refresh_pattern(line: str) -> bool:
            return "(/cgi-bin/|\\?)" in line

        out_lines = []
        saw_refresh = False
        for line in text.splitlines(True):
            if re.match(r"^\s*refresh_pattern\b", line):
                saw_refresh = True
                stripped = line
                for token in override_tokens:
                    stripped = re.sub(rf"\s+{re.escape(token)}\b", "", stripped)
                if should_skip_refresh_pattern(line):
                    out_lines.append(stripped)
                    continue
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
                f"# override_expire={'1' if bool(values.get('override_expire')) else '0'}",
                f"# override_lastmod={'1' if bool(values.get('override_lastmod')) else '0'}",
                f"# reload_into_ims={'1' if bool(values.get('reload_into_ims')) else '0'}",
                f"# ignore_reload={'1' if bool(values.get('ignore_reload')) else '0'}",
                f"# ignore_no_store={'1' if bool(values.get('ignore_no_store')) else '0'}",
                f"# ignore_private={'1' if bool(values.get('ignore_private')) else '0'}",
                end_marker,
                "",
            ],
        )

        if saw_refresh:
            rendered = re.sub(
                r"^(\s*refresh_pattern\b)",
                meta_block + "\n" + r"\1",
                rendered,
                count=1,
                flags=re.MULTILINE,
            )
        else:
            rendered = rendered.rstrip() + "\n\n" + meta_block + "\n"
        return rendered

    def generate_config_from_template(self, options: dict[str, Any]) -> str:
        if not pathlib.Path(self.squid_conf_template_path).exists():
            raise FileNotFoundError(self.squid_conf_template_path)

        template_text = self._read_file(self.squid_conf_template_path)

        try:
            dynamic_cert_mem_cache_size_mb = max(
                0,
                int(
                    str(options.get("dynamic_cert_mem_cache_size_mb") or "128").strip(),
                ),
            )
        except Exception:
            dynamic_cert_mem_cache_size_mb = 128

        rendered = self._render_http_port_listeners(
            template_text,
            options,
            dynamic_cert_mem_cache_size_mb,
        )
        managed_block = self._render_managed_settings(options)
        return self._replace_managed_settings_block(rendered, managed_block)

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
            proc = self._run(
                ["squid", "-f", self.squid_conf_path],
                capture_output=True,
                timeout=12,
            )
            return proc.stdout or b"", proc.stderr or b""
        except FileNotFoundError:
            return b"", b"squid binary not found"
        except Exception as exc:
            return b"", str(exc).encode("utf-8", errors="replace")

    def stop_squid(self):
        try:
            proc = self._run(
                ["squid", "-k", "shutdown"],
                capture_output=True,
                timeout=12,
            )
            return proc.stdout or b"", proc.stderr or b""
        except FileNotFoundError:
            return b"", b"squid binary not found"
        except Exception as exc:
            return b"", str(exc).encode("utf-8", errors="replace")

    def update_config(self, config_text: str) -> None:
        self.apply_config_text(config_text)
