from __future__ import annotations

import os
import re
from typing import Any, Dict, Optional

import logging

from services.errors import public_error_message
from services.logutil import log_exception_throttled
from services.squid_core import SquidController as _CoreSquidController


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
    _HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$")
    _IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    _IPV6_SIMPLE_RE = re.compile(r"^[a-fA-F0-9:]+$")

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
        forbidden = set('|;&$`"\'\\<>(){}[]!#~')
        if any(char in clean for char in forbidden):
            raise ValueError(f"{field_name} contains forbidden characters")
        if not clean.startswith("/"):
            raise ValueError(f"{field_name} must be an absolute path")
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

    def _read_file(self, path: str) -> str:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()

    def _replace_or_append_line(self, text: str, key: str, new_line: str) -> str:
        pattern = re.compile(rf"^(\s*{re.escape(key)}\s+).*$", re.M)
        if pattern.search(text):
            return pattern.sub(new_line, text, count=1)
        return text.rstrip() + "\n" + new_line + "\n"

    def _replace_cache_dir_size_mb(self, text: str, size_mb: int) -> str:
        pattern = re.compile(r"^(\s*cache_dir\s+ufs\s+\S+\s+)(\d+)(\s+\d+\s+\d+.*)$", re.M)
        if pattern.search(text):
            return pattern.sub(lambda match: f"{match.group(1)}{int(size_mb)}{match.group(3)}", text, count=1)
        return text.rstrip() + f"\ncache_dir ufs /var/spool/squid {int(size_mb)} 16 256\n"

    def get_tunable_options(self, config_text: Optional[str] = None) -> Dict[str, Any]:
        text = config_text if config_text is not None else (self.get_current_config() or "")

        def find_int(pattern: str) -> Optional[int]:
            match = re.search(pattern, text, re.M | re.I)
            return int(match.group(1)) if match else None

        def find_on_off(key: str) -> Optional[bool]:
            match = re.search(rf"^\s*{re.escape(key)}\s+(on|off)\s*$", text, re.M | re.I)
            if not match:
                return None
            return match.group(1).lower() == "on"

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

        return {
            "cache_dir_size_mb": find_int(r"^\s*cache_dir\s+ufs\s+\S+\s+(\d+)\s+\d+\s+\d+"),
            "cache_mem_mb": find_int(r"^\s*cache_mem\s+(\d+)\s*MB\s*$"),
            "maximum_object_size_mb": find_int(r"^\s*maximum_object_size\s+(\d+)\s*MB\s*$"),
            "maximum_object_size_in_memory_kb": find_int(r"^\s*maximum_object_size_in_memory\s+(\d+)\s*KB\s*$"),
            "minimum_object_size_kb": find_kb("minimum_object_size"),
            "cache_swap_low": find_int(r"^\s*cache_swap_low\s+(\d+)\s*$"),
            "cache_swap_high": find_int(r"^\s*cache_swap_high\s+(\d+)\s*$"),
            "collapsed_forwarding": find_on_off("collapsed_forwarding"),
            "range_offset_limit": find_range_offset_limit_mb(),
            "client_persistent_connections": find_on_off("client_persistent_connections"),
            "server_persistent_connections": find_on_off("server_persistent_connections"),
            "negative_ttl_seconds": find_time_seconds("negative_ttl"),
            "positive_dns_ttl_seconds": find_time_seconds("positive_dns_ttl"),
            "negative_dns_ttl_seconds": find_time_seconds("negative_dns_ttl"),
            "read_ahead_gap_kb": find_kb("read_ahead_gap"),
            "workers": find_int(r"^\s*workers\s+(\d+)\s*$"),
            "cache_replacement_policy": find_str("cache_replacement_policy"),
            "memory_replacement_policy": find_str("memory_replacement_policy"),
            "pipeline_prefetch": find_pipeline_prefetch_bool(),
            "quick_abort_min_kb": find_kb("quick_abort_min"),
            "quick_abort_max_kb": find_kb("quick_abort_max"),
            "quick_abort_pct": find_pct("quick_abort_pct"),
            "connect_timeout_seconds": find_time_seconds("connect_timeout"),
            "request_timeout_seconds": find_time_seconds("request_timeout"),
            "read_timeout_seconds": find_time_seconds("read_timeout"),
            "forward_timeout_seconds": find_time_seconds("forward_timeout"),
            "shutdown_lifetime_seconds": find_time_seconds("shutdown_lifetime"),
            "logfile_rotate": find_int(r"^\s*logfile_rotate\s+(\d+)\s*$"),
            "pconn_timeout_seconds": find_time_seconds("pconn_timeout"),
            "client_lifetime_seconds": find_time_seconds("client_lifetime"),
            "max_filedescriptors": find_int(r"^\s*max_filedescriptors\s+(\d+)\s*$"),
            "dns_timeout_seconds": find_time_seconds("dns_timeout"),
            "dns_nameservers": find_str("dns_nameservers"),
            "hosts_file": find_str("hosts_file"),
            "ipcache_size": find_int(r"^\s*ipcache_size\s+(\d+)\s*$"),
            "fqdncache_size": find_int(r"^\s*fqdncache_size\s+(\d+)\s*$"),
            "sslcrtd_children": find_int(r"^\s*sslcrtd_children\s+(\d+)\s*$"),
            "icap_enable": find_on_off("icap_enable"),
            "icap_send_client_ip": find_on_off("icap_send_client_ip"),
            "icap_send_client_username": find_on_off("icap_send_client_username"),
            "icap_preview_enable": find_on_off("icap_preview_enable"),
            "icap_preview_size_kb": find_size_kb("icap_preview_size"),
            "icap_connect_timeout_seconds": find_time_seconds("icap_connect_timeout"),
            "icap_io_timeout_seconds": find_time_seconds("icap_io_timeout"),
            "forwarded_for_value": find_str("forwarded_for"),
            "via": find_on_off("via"),
            "follow_x_forwarded_for_value": find_str("follow_x_forwarded_for"),
            "request_header_max_size_kb": find_size_kb("request_header_max_size"),
            "reply_header_max_size_kb": find_size_kb("reply_header_max_size"),
            "request_body_max_size_mb": find_size_mb("request_body_max_size"),
            "client_request_buffer_max_size_kb": find_size_kb("client_request_buffer_max_size"),
            "memory_pools": find_on_off("memory_pools"),
            "memory_pools_limit_mb": find_size_mb("memory_pools_limit"),
            "store_avg_object_size_kb": find_size_kb("store_avg_object_size"),
            "store_objects_per_bucket": find_int(r"^\s*store_objects_per_bucket\s+(\d+)\s*$"),
            "visible_hostname": find_str("visible_hostname"),
            "httpd_suppress_version_string": find_on_off("httpd_suppress_version_string"),
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
        return self._get_lines(config_text, ("pconn_timeout", "client_lifetime", "max_filedescriptors"))

    def get_dns_lines(self, config_text: Optional[str] = None) -> list[str]:
        return self._get_lines(config_text, ("dns_timeout", "dns_nameservers", "hosts_file", "positive_dns_ttl", "negative_dns_ttl", "ipcache_size", "fqdncache_size"))

    def get_ssl_lines(self, config_text: Optional[str] = None) -> list[str]:
        return self._get_lines(config_text, ("sslcrtd_program", "sslcrtd_children", "ssl_bump"))

    def get_icap_lines(self, config_text: Optional[str] = None) -> list[str]:
        return self._get_lines(config_text, ("icap_", "adaptation_"), include_icap_include=True)

    def get_privacy_lines(self, config_text: Optional[str] = None) -> list[str]:
        return self._get_lines(config_text, ("forwarded_for", "via", "follow_x_forwarded_for"))

    def get_limits_lines(self, config_text: Optional[str] = None) -> list[str]:
        return self._get_lines(config_text, ("request_header_max_size", "reply_header_max_size", "request_body_max_size", "client_request_buffer_max_size"))

    def get_performance_lines(self, config_text: Optional[str] = None) -> list[str]:
        return self._get_lines(config_text, ("memory_pools", "memory_pools_limit", "store_avg_object_size", "store_objects_per_bucket"))

    def get_http_lines(self, config_text: Optional[str] = None) -> list[str]:
        return self._get_lines(config_text, ("visible_hostname", "httpd_suppress_version_string"))

    def get_logging_lines(self, config_text: Optional[str] = None) -> list[str]:
        return self._get_lines(config_text, ("logformat", "access_log", "cache_log", "cache_store_log", "logfile_rotate"))

    def get_timeout_lines(self, config_text: Optional[str] = None) -> list[str]:
        return self._get_lines(config_text, ("connect_timeout", "request_timeout", "read_timeout", "forward_timeout", "shutdown_lifetime"))

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
                "cache_mem",
                "minimum_object_size",
                "maximum_object_size",
                "maximum_object_size_in_memory",
                "cache_swap_low",
                "cache_swap_high",
                "cache_replacement_policy",
                "memory_replacement_policy",
                "pipeline_prefetch",
                "collapsed_forwarding",
                "range_offset_limit",
                "quick_abort_min",
                "quick_abort_max",
                "quick_abort_pct",
                "client_persistent_connections",
                "server_persistent_connections",
                "read_ahead_gap",
                "refresh_pattern",
                "negative_ttl",
                "positive_dns_ttl",
                "negative_dns_ttl",
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

        cache_dir_size_mb = int(options.get("cache_dir_size_mb") or 10000)
        cache_mem_mb = int(options.get("cache_mem_mb") or 96)
        maximum_object_size_mb = int(options.get("maximum_object_size_mb") or 64)
        maximum_object_size_in_memory_kb = int(options.get("maximum_object_size_in_memory_kb") or 1024)
        minimum_object_size_kb = int(options.get("minimum_object_size_kb") if options.get("minimum_object_size_kb") is not None else 0)
        cache_swap_low = int(options.get("cache_swap_low") or 90)
        cache_swap_high = int(options.get("cache_swap_high") or 95)
        collapsed_forwarding_on = bool(options.get("collapsed_forwarding_on", True))
        range_cache_on = bool(options.get("range_cache_on", True))
        cache_replacement_policy = (options.get("cache_replacement_policy") or "heap GDSF").strip()
        memory_replacement_policy = (options.get("memory_replacement_policy") or "heap GDSF").strip()
        pipeline_prefetch_on = bool(options.get("pipeline_prefetch_on", True))
        client_persistent_connections_on = bool(options.get("client_persistent_connections_on", True))
        server_persistent_connections_on = bool(options.get("server_persistent_connections_on", True))
        negative_ttl_seconds = options.get("negative_ttl_seconds")
        positive_dns_ttl_seconds = options.get("positive_dns_ttl_seconds")
        negative_dns_ttl_seconds = options.get("negative_dns_ttl_seconds")
        read_ahead_gap_kb = options.get("read_ahead_gap_kb")
        connect_timeout_seconds = options.get("connect_timeout_seconds")
        request_timeout_seconds = options.get("request_timeout_seconds")
        read_timeout_seconds = options.get("read_timeout_seconds")
        forward_timeout_seconds = options.get("forward_timeout_seconds")
        shutdown_lifetime_seconds = options.get("shutdown_lifetime_seconds")
        logfile_rotate = options.get("logfile_rotate")
        pconn_timeout_seconds = options.get("pconn_timeout_seconds")
        client_lifetime_seconds = options.get("client_lifetime_seconds")
        max_filedescriptors = options.get("max_filedescriptors")
        dns_timeout_seconds = options.get("dns_timeout_seconds")
        dns_nameservers = self._validate_dns_nameservers(options.get("dns_nameservers") or "")
        hosts_file = self._validate_hosts_file_path(options.get("hosts_file") or "")
        ipcache_size = options.get("ipcache_size")
        fqdncache_size = options.get("fqdncache_size")
        sslcrtd_children = options.get("sslcrtd_children")
        icap_enable_on = bool(options.get("icap_enable_on", True))
        icap_send_client_ip_on = bool(options.get("icap_send_client_ip_on", True))
        icap_send_client_username_on = bool(options.get("icap_send_client_username_on", False))
        icap_preview_enable_on = bool(options.get("icap_preview_enable_on", False))
        icap_preview_size_kb = options.get("icap_preview_size_kb")
        icap_connect_timeout_seconds = options.get("icap_connect_timeout_seconds")
        icap_io_timeout_seconds = options.get("icap_io_timeout_seconds")
        forwarded_for_value = (options.get("forwarded_for_value") or "").strip()
        follow_x_forwarded_for_value = (options.get("follow_x_forwarded_for_value") or "").strip()
        via_on = options.get("via_on")
        request_header_max_size_kb = options.get("request_header_max_size_kb")
        reply_header_max_size_kb = options.get("reply_header_max_size_kb")
        request_body_max_size_mb = options.get("request_body_max_size_mb")
        client_request_buffer_max_size_kb = options.get("client_request_buffer_max_size_kb")
        memory_pools_on = options.get("memory_pools_on")
        memory_pools_limit_mb = options.get("memory_pools_limit_mb")
        store_avg_object_size_kb = options.get("store_avg_object_size_kb")
        store_objects_per_bucket = options.get("store_objects_per_bucket")
        visible_hostname = self._validate_hostname(options.get("visible_hostname") or "", "visible_hostname")
        httpd_suppress_version_string_on = options.get("httpd_suppress_version_string_on")
        workers = int(options.get("workers") or 1)
        if workers < 1:
            workers = 1
        try:
            max_workers = int((os.environ.get("MAX_WORKERS") or "4").strip())
        except Exception:
            max_workers = 4
        max_workers = min(4, max(1, max_workers))
        if workers > max_workers:
            workers = max_workers
        quick_abort_min_kb = int(options.get("quick_abort_min_kb") if options.get("quick_abort_min_kb") is not None else 0)
        quick_abort_max_kb = int(options.get("quick_abort_max_kb") if options.get("quick_abort_max_kb") is not None else 0)
        quick_abort_pct = int(options.get("quick_abort_pct") if options.get("quick_abort_pct") is not None else 100)

        out = template_text
        out = self._replace_cache_dir_size_mb(out, cache_dir_size_mb)
        out = self._replace_or_append_line(out, "cache_mem", f"cache_mem {cache_mem_mb} MB")
        out = self._replace_or_append_line(out, "maximum_object_size", f"maximum_object_size {maximum_object_size_mb} MB")
        out = self._replace_or_append_line(out, "maximum_object_size_in_memory", f"maximum_object_size_in_memory {maximum_object_size_in_memory_kb} KB")
        out = self._replace_or_append_line(out, "minimum_object_size", f"minimum_object_size {minimum_object_size_kb} KB")
        out = self._replace_or_append_line(out, "cache_swap_low", f"cache_swap_low {cache_swap_low}")
        out = self._replace_or_append_line(out, "cache_swap_high", f"cache_swap_high {cache_swap_high}")
        out = self._replace_or_append_line(out, "collapsed_forwarding", f"collapsed_forwarding {'on' if collapsed_forwarding_on else 'off'}")
        out = self._replace_or_append_line(out, "range_offset_limit", f"range_offset_limit {'128 MB' if range_cache_on else '0'}")
        out = self._replace_or_append_line(out, "cache_replacement_policy", f"cache_replacement_policy {cache_replacement_policy}")
        out = self._replace_or_append_line(out, "memory_replacement_policy", f"memory_replacement_policy {memory_replacement_policy}")
        out = self._replace_or_append_line(out, "pipeline_prefetch", f"pipeline_prefetch {1 if pipeline_prefetch_on else 0}")
        out = self._replace_or_append_line(out, "client_persistent_connections", f"client_persistent_connections {'on' if client_persistent_connections_on else 'off'}")
        out = self._replace_or_append_line(out, "server_persistent_connections", f"server_persistent_connections {'on' if server_persistent_connections_on else 'off'}")

        if negative_ttl_seconds is not None:
            out = self._replace_or_append_line(out, "negative_ttl", f"negative_ttl {int(negative_ttl_seconds)} seconds")
        if positive_dns_ttl_seconds is not None:
            out = self._replace_or_append_line(out, "positive_dns_ttl", f"positive_dns_ttl {int(positive_dns_ttl_seconds)} seconds")
        if negative_dns_ttl_seconds is not None:
            out = self._replace_or_append_line(out, "negative_dns_ttl", f"negative_dns_ttl {int(negative_dns_ttl_seconds)} seconds")
        if read_ahead_gap_kb is not None:
            out = self._replace_or_append_line(out, "read_ahead_gap", f"read_ahead_gap {int(read_ahead_gap_kb)} KB")
        if connect_timeout_seconds is not None:
            out = self._replace_or_append_line(out, "connect_timeout", f"connect_timeout {int(connect_timeout_seconds)} seconds")
        if request_timeout_seconds is not None:
            out = self._replace_or_append_line(out, "request_timeout", f"request_timeout {int(request_timeout_seconds)} seconds")
        if read_timeout_seconds is not None:
            out = self._replace_or_append_line(out, "read_timeout", f"read_timeout {int(read_timeout_seconds)} seconds")
        if forward_timeout_seconds is not None:
            out = self._replace_or_append_line(out, "forward_timeout", f"forward_timeout {int(forward_timeout_seconds)} seconds")
        if shutdown_lifetime_seconds is not None:
            out = self._replace_or_append_line(out, "shutdown_lifetime", f"shutdown_lifetime {int(shutdown_lifetime_seconds)} seconds")
        out = self._replace_or_append_line(out, "half_closed_clients", "half_closed_clients off")
        if logfile_rotate is not None:
            out = self._replace_or_append_line(out, "logfile_rotate", f"logfile_rotate {int(logfile_rotate)}")
        if pconn_timeout_seconds is not None:
            out = self._replace_or_append_line(out, "pconn_timeout", f"pconn_timeout {int(pconn_timeout_seconds)} seconds")
        if client_lifetime_seconds is not None:
            out = self._replace_or_append_line(out, "client_lifetime", f"client_lifetime {int(client_lifetime_seconds)} seconds")
        if max_filedescriptors is not None:
            out = self._replace_or_append_line(out, "max_filedescriptors", f"max_filedescriptors {int(max_filedescriptors)}")
        if dns_timeout_seconds is not None:
            out = self._replace_or_append_line(out, "dns_timeout", f"dns_timeout {int(dns_timeout_seconds)} seconds")
        if dns_nameservers:
            out = self._replace_or_append_line(out, "dns_nameservers", f"dns_nameservers {dns_nameservers}")
        if hosts_file:
            out = self._replace_or_append_line(out, "hosts_file", f"hosts_file {hosts_file}")
        if ipcache_size is not None:
            out = self._replace_or_append_line(out, "ipcache_size", f"ipcache_size {int(ipcache_size)}")
        if fqdncache_size is not None:
            out = self._replace_or_append_line(out, "fqdncache_size", f"fqdncache_size {int(fqdncache_size)}")
        if sslcrtd_children is not None:
            out = self._replace_or_append_line(out, "sslcrtd_children", f"sslcrtd_children {int(sslcrtd_children)}")
        out = self._replace_or_append_line(out, "icap_enable", f"icap_enable {'on' if icap_enable_on else 'off'}")
        out = self._replace_or_append_line(out, "icap_send_client_ip", f"icap_send_client_ip {'on' if icap_send_client_ip_on else 'off'}")
        out = self._replace_or_append_line(out, "icap_send_client_username", f"icap_send_client_username {'on' if icap_send_client_username_on else 'off'}")
        out = self._replace_or_append_line(out, "icap_preview_enable", f"icap_preview_enable {'on' if icap_preview_enable_on else 'off'}")
        if icap_preview_size_kb is not None:
            out = self._replace_or_append_line(out, "icap_preview_size", f"icap_preview_size {int(icap_preview_size_kb)} KB")
        if icap_connect_timeout_seconds is not None:
            out = self._replace_or_append_line(out, "icap_connect_timeout", f"icap_connect_timeout {int(icap_connect_timeout_seconds)} seconds")
        if icap_io_timeout_seconds is not None:
            out = self._replace_or_append_line(out, "icap_io_timeout", f"icap_io_timeout {int(icap_io_timeout_seconds)} seconds")
        if forwarded_for_value:
            out = self._replace_or_append_line(out, "forwarded_for", f"forwarded_for {forwarded_for_value}")
        if via_on is not None:
            out = self._replace_or_append_line(out, "via", f"via {'on' if bool(via_on) else 'off'}")
        if follow_x_forwarded_for_value:
            out = self._replace_or_append_line(out, "follow_x_forwarded_for", f"follow_x_forwarded_for {follow_x_forwarded_for_value}")
        if request_header_max_size_kb is not None:
            out = self._replace_or_append_line(out, "request_header_max_size", f"request_header_max_size {int(request_header_max_size_kb)} KB")
        if reply_header_max_size_kb is not None:
            out = self._replace_or_append_line(out, "reply_header_max_size", f"reply_header_max_size {int(reply_header_max_size_kb)} KB")
        if request_body_max_size_mb is not None:
            out = self._replace_or_append_line(out, "request_body_max_size", f"request_body_max_size {int(request_body_max_size_mb)} MB")
        if client_request_buffer_max_size_kb is not None:
            out = self._replace_or_append_line(out, "client_request_buffer_max_size", f"client_request_buffer_max_size {int(client_request_buffer_max_size_kb)} KB")
        if memory_pools_on is not None:
            out = self._replace_or_append_line(out, "memory_pools", f"memory_pools {'on' if bool(memory_pools_on) else 'off'}")
        if memory_pools_limit_mb is not None:
            out = self._replace_or_append_line(out, "memory_pools_limit", f"memory_pools_limit {int(memory_pools_limit_mb)} MB")
        if store_avg_object_size_kb is not None:
            out = self._replace_or_append_line(out, "store_avg_object_size", f"store_avg_object_size {int(store_avg_object_size_kb)} KB")
        if store_objects_per_bucket is not None:
            out = self._replace_or_append_line(out, "store_objects_per_bucket", f"store_objects_per_bucket {int(store_objects_per_bucket)}")
        if visible_hostname:
            out = self._replace_or_append_line(out, "visible_hostname", f"visible_hostname {visible_hostname}")
        if httpd_suppress_version_string_on is not None:
            out = self._replace_or_append_line(out, "httpd_suppress_version_string", f"httpd_suppress_version_string {'on' if bool(httpd_suppress_version_string_on) else 'off'}")
        out = self._replace_or_append_line(out, "workers", f"workers {workers}")
        out = self._replace_or_append_line(out, "quick_abort_min", f"quick_abort_min {quick_abort_min_kb} KB")
        out = self._replace_or_append_line(out, "quick_abort_max", f"quick_abort_max {quick_abort_max_kb} KB")
        out = self._replace_or_append_line(out, "quick_abort_pct", f"quick_abort_pct {quick_abort_pct}")
        return out

    def generate_config_from_template_with_exclusions(self, options: Dict[str, Any], exclusions: Any) -> str:
        base = self.generate_config_from_template(options)
        domains = [domain.strip().lower().lstrip(".") for domain in (getattr(exclusions, "domains", []) or []) if domain.strip()]
        src_nets = [cidr.strip() for cidr in (getattr(exclusions, "src_nets", []) or []) if cidr.strip()]
        private_dst_nets = PRIVATE_NETS_V4 if bool(getattr(exclusions, "exclude_private_nets", False)) else []

        acl_lines = []
        splice_lines = []
        cache_deny_lines = []

        if domains:
            acl_lines.append("acl excluded_domains dstdomain " + " ".join(domains))
            splice_lines.append("ssl_bump splice excluded_domains")
            cache_deny_lines.append("cache deny excluded_domains")
        if private_dst_nets:
            acl_lines.append("acl excluded_private_dst dst " + " ".join(private_dst_nets))
            splice_lines.append("ssl_bump splice excluded_private_dst")
            cache_deny_lines.append("cache deny excluded_private_dst")
        if src_nets:
            acl_lines.append("acl excluded_src src " + " ".join(src_nets))
            splice_lines.append("ssl_bump splice excluded_src")
            cache_deny_lines.append("cache deny excluded_src")
        if not (acl_lines or splice_lines or cache_deny_lines):
            return base

        insert_ssl = "\n".join(["", "# Exclusions (managed by web UI)"] + acl_lines + splice_lines) + "\n"
        base = base.replace("ssl_bump bump all", insert_ssl + "ssl_bump bump all", 1)

        deny_block = "\n".join(["", "# Exclusions (managed by web UI)"] + cache_deny_lines) + "\n"
        if "# Cache settings" in base:
            marker = "# Log settings"
            if marker in base:
                base = base.replace(marker, deny_block + "\n" + marker, 1)
            else:
                base = base.rstrip() + deny_block
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
