from __future__ import annotations

import os
import re
import tempfile
import shutil
from pathlib import Path
from subprocess import run
from typing import Any, Dict, Optional, Tuple

import logging

from services.errors import public_error_message
from services.logutil import log_exception_throttled


logger = logging.getLogger(__name__)

try:
    from services.exclusions_store import Exclusions, PRIVATE_NETS_V4
except Exception:  # pragma: no cover
    Exclusions = None  # type: ignore[assignment]
    PRIVATE_NETS_V4 = []  # type: ignore[assignment]

class SquidController:
    def __init__(self, squid_conf_path: str = "/etc/squid/squid.conf"):
        self.squid_conf_path = squid_conf_path
        self.squid_conf_template_path = "/etc/squid/squid.conf.template"
        self.persisted_squid_conf_path = os.environ.get(
            "PERSISTED_SQUID_CONF_PATH", "/var/lib/squid-flask-proxy/squid.conf"
        )
        if (not os.path.exists(self.squid_conf_template_path)) and os.path.exists("/squid/squid.conf.template"):
            self.squid_conf_template_path = "/squid/squid.conf.template"

        self._squid_version_major: Optional[int] = None

    def _get_squid_version_major(self) -> Optional[int]:
        # Best-effort: used only to avoid generating directives that are obsolete
        # or removed in newer Squid versions. Must not fail on dev hosts/tests.
        if self._squid_version_major is not None:
            return self._squid_version_major
        try:
            if not shutil.which("squid"):
                return None
            p = run(["squid", "-v"], capture_output=True, text=True, timeout=3)
            out = (p.stdout or "") + "\n" + (p.stderr or "")
            m = re.search(r"\bVersion\s+(\d+)\.", out)
            if not m:
                return None
            self._squid_version_major = int(m.group(1))
            return self._squid_version_major
        except Exception:
            return None

    def _allow_legacy_directives(self) -> bool:
        v = self._get_squid_version_major()
        # If we can't detect, assume modern Squid and avoid removed directives.
        return bool(v is not None and v < 6)

    def _read_file(self, path: str) -> str:
        with open(path, 'r', encoding='utf-8') as f:
            return f.read()

    def _write_file(self, path: str, content: str) -> None:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)

    def _atomic_write_file(self, path: str, content: str) -> None:
        # Write within the destination directory so os.replace is atomic on POSIX.
        d = os.path.dirname(path) or "."
        os.makedirs(d, exist_ok=True)
        tmp_path = ""
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False, dir=d, prefix=".tmp-") as f:
                tmp_path = f.name
                f.write(content)
            os.replace(tmp_path, path)
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass

    def _generate_icap_include(self, workers: int) -> None:
        # Generates /etc/squid/conf.d/20-icap.conf.
        try:
            workers_i = int(workers)
        except Exception:
            workers_i = 1
        if workers_i < 1:
            workers_i = 1

        try:
            cicap_adblock_port = int((os.environ.get("CICAP_PORT") or "14000").strip())
        except Exception:
            cicap_adblock_port = 14000
        try:
            cicap_av_port = int((os.environ.get("CICAP_AV_PORT") or "14001").strip())
        except Exception:
            cicap_av_port = 14001
        conf_dir = Path("/etc/squid/conf.d")
        conf_dir.mkdir(parents=True, exist_ok=True)
        out_path = conf_dir / "20-icap.conf"

        req_names = []
        av_names = []
        lines = []
        for i in range(workers_i):
            lines.append(f"icap_service adblock_req_{i} reqmod_precache icap://127.0.0.1:{cicap_adblock_port}/adblockreq bypass=on")
            lines.append(f"icap_service av_resp_{i} respmod_precache icap://127.0.0.1:{cicap_av_port}/avrespmod bypass=on")
            req_names.append(f"adblock_req_{i}")
            av_names.append(f"av_resp_{i}")

        # Squid chooses a service from the set for each transaction.
        lines.append("adaptation_service_set adblock_req_set " + " ".join(req_names))
        lines.append("adaptation_service_set av_resp_set " + " ".join(av_names))
        out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _supervisor_reread_update(self) -> Tuple[bool, str]:
        try:
            p1 = run(["supervisorctl", "-c", "/etc/supervisord.conf", "reread"], capture_output=True, timeout=12)
            if p1.returncode != 0:
                return False, self._decode_completed(p1) or "supervisorctl reread failed"
            p2 = run(["supervisorctl", "-c", "/etc/supervisord.conf", "update"], capture_output=True, timeout=20)
            if p2.returncode != 0:
                return False, self._decode_completed(p2) or "supervisorctl update failed"
            return True, (self._decode_completed(p1) + "\n" + self._decode_completed(p2)).strip()
        except Exception as e:
            logger.exception("supervisorctl reread/update failed")
            return False, public_error_message(e, default="supervisorctl failed. Check server logs for details.")

    def apply_icap_scaling(self, workers: int) -> Tuple[bool, str]:
        """Update Squid ICAP service-set include.

        ICAP services are handled by c-icap instances in this container.
        Scaling updates the Squid service-set include to point at the right
        c-icap endpoints.
        """
        try:
            self._generate_icap_include(workers)
            return True, "ICAP include updated."
        except Exception as e:
            logger.exception("ICAP scaling apply failed")
            return False, public_error_message(e)

    def _replace_or_append_line(self, text: str, key: str, new_line: str) -> str:
        # Replace the first matching directive line, else append.
        pattern = re.compile(rf"^(\s*{re.escape(key)}\s+).*$", re.M)
        if pattern.search(text):
            return pattern.sub(new_line, text, count=1)
        return text.rstrip() + "\n" + new_line + "\n"

    def _replace_cache_dir_size_mb(self, text: str, size_mb: int) -> str:
        # cache_dir ufs /var/spool/squid <size_mb> 16 256
        pattern = re.compile(r"^(\s*cache_dir\s+ufs\s+\S+\s+)(\d+)(\s+\d+\s+\d+.*)$", re.M)
        if pattern.search(text):
            return pattern.sub(lambda m: f"{m.group(1)}{int(size_mb)}{m.group(3)}", text, count=1)
        return text.rstrip() + f"\ncache_dir ufs /var/spool/squid {int(size_mb)} 16 256\n"

    def get_tunable_options(self, config_text: Optional[str] = None) -> Dict[str, Any]:
        # Best-effort parse of current config for UI defaults.
        text = config_text if config_text is not None else (self.get_current_config() or "")

        def find_int(pattern: str) -> Optional[int]:
            m = re.search(pattern, text, re.M | re.I)
            return int(m.group(1)) if m else None

        def find_mb(key: str) -> Optional[int]:
            m = re.search(rf"^\s*{re.escape(key)}\s+(\d+)\s*MB\s*$", text, re.M | re.I)
            return int(m.group(1)) if m else None

        def find_on_off(key: str) -> Optional[bool]:
            m = re.search(rf"^\s*{re.escape(key)}\s+(on|off)\s*$", text, re.M | re.I)
            if not m:
                return None
            return m.group(1).lower() == "on"

        def find_time_seconds(key: str) -> Optional[int]:
            m = re.search(rf"^\s*{re.escape(key)}\s+(\d+)\s*([a-zA-Z]+)?\s*$", text, re.M)
            if not m:
                return None
            try:
                n = int(m.group(1))
            except Exception:
                return None
            unit = (m.group(2) or "").strip().lower()
            if not unit:
                return n
            if unit in ("s", "sec", "secs", "second", "seconds"):
                return n
            if unit in ("m", "min", "mins", "minute", "minutes"):
                return n * 60
            if unit in ("h", "hr", "hrs", "hour", "hours"):
                return n * 3600
            if unit in ("d", "day", "days"):
                return n * 86400
            return n

        def find_str(key: str) -> Optional[str]:
            m = re.search(rf"^\s*{re.escape(key)}\s+(.+?)\s*$", text, re.M | re.I)
            return m.group(1).strip() if m else None

        def find_kb(key: str) -> Optional[int]:
            m = re.search(rf"^\s*{re.escape(key)}\s+(\d+)\s*(KB|K|KBYTES)?\s*$", text, re.M | re.I)
            return int(m.group(1)) if m else None

        def find_pct(key: str) -> Optional[int]:
            m = re.search(rf"^\s*{re.escape(key)}\s+(\d+)\s*%?\s*$", text, re.M | re.I)
            return int(m.group(1)) if m else None

        def _size_to_bytes(value: str, unit: str) -> Optional[int]:
            try:
                n = int(value)
            except Exception:
                return None
            u = (unit or "").strip().lower()
            if u in ("", "b", "bytes"):
                return n
            if u in ("k", "kb", "kib", "kbytes"):
                return n * 1024
            if u in ("m", "mb", "mib", "mbytes"):
                return n * 1024 * 1024
            if u in ("g", "gb", "gib", "gbytes"):
                return n * 1024 * 1024 * 1024
            return None

        def find_size_kb(key: str) -> Optional[int]:
            # Accept: 64 KB, 64K, 65536 (bytes), etc.
            m = re.search(rf"^\s*{re.escape(key)}\s+(\d+)\s*([A-Za-z]+)?\s*$", text, re.M | re.I)
            if not m:
                return None
            b = _size_to_bytes(m.group(1), m.group(2) or "")
            if b is None:
                return None
            return int(b // 1024)

        def find_size_mb(key: str) -> Optional[int]:
            m = re.search(rf"^\s*{re.escape(key)}\s+(\d+)\s*([A-Za-z]+)?\s*$", text, re.M | re.I)
            if not m:
                return None
            b = _size_to_bytes(m.group(1), m.group(2) or "")
            if b is None:
                return None
            return int(b // (1024 * 1024))

        def find_pipeline_prefetch_bool() -> Optional[bool]:
            # Squid supports either legacy on/off or numeric values.
            # Squid 6 warns that "pipeline_prefetch on" is deprecated.
            m = re.search(r"^\s*pipeline_prefetch\s+(\S+)\s*$", text, re.M | re.I)
            if not m:
                return None
            v = (m.group(1) or "").strip().lower()
            if v in ("on", "true", "yes"):
                return True
            if v in ("off", "false", "no"):
                return False
            try:
                return int(v) >= 1
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
            "range_offset_limit": find_int(r"^\s*range_offset_limit\s+(-?\d+)\s*$"),

            "client_persistent_connections": find_on_off("client_persistent_connections"),
            "server_persistent_connections": find_on_off("server_persistent_connections"),

            "negative_ttl_seconds": find_time_seconds("negative_ttl"),
            "positive_dns_ttl_seconds": find_time_seconds("positive_dns_ttl"),
            "negative_dns_ttl_seconds": find_time_seconds("negative_dns_ttl"),
            "read_ahead_gap_kb": find_kb("read_ahead_gap"),

            # SMP
            "workers": find_int(r"^\s*workers\s+(\d+)\s*$"),

            # Cache effectiveness/performance
            "cache_replacement_policy": find_str("cache_replacement_policy"),
            "memory_replacement_policy": find_str("memory_replacement_policy"),
            "pipeline_prefetch": find_pipeline_prefetch_bool(),

            # Cache-first tuning (whether to continue fetching when clients abort)
            "quick_abort_min_kb": find_kb("quick_abort_min"),
            "quick_abort_max_kb": find_kb("quick_abort_max"),
            "quick_abort_pct": find_pct("quick_abort_pct"),

            # Timeouts (normalize to seconds)
            "connect_timeout_seconds": find_time_seconds("connect_timeout"),
            "request_timeout_seconds": find_time_seconds("request_timeout"),
            "read_timeout_seconds": find_time_seconds("read_timeout"),
            "forward_timeout_seconds": find_time_seconds("forward_timeout"),
            "shutdown_lifetime_seconds": find_time_seconds("shutdown_lifetime"),
            "half_closed_clients": find_on_off("half_closed_clients"),

            # Logging
            "logfile_rotate": find_int(r"^\s*logfile_rotate\s+(\d+)\s*$"),

            # Network / connection lifecycle
            "pconn_timeout_seconds": find_time_seconds("pconn_timeout"),
            "idle_pconn_timeout_seconds": find_time_seconds("idle_pconn_timeout"),
            "client_lifetime_seconds": find_time_seconds("client_lifetime"),
            "max_filedescriptors": find_int(r"^\s*max_filedescriptors\s+(\d+)\s*$"),

            # DNS / name resolution
            "dns_v4_first": find_on_off("dns_v4_first"),
            "dns_timeout_seconds": find_time_seconds("dns_timeout"),
            "dns_retransmit_seconds": find_time_seconds("dns_retransmit"),
            "dns_nameservers": find_str("dns_nameservers"),
            "hosts_file": find_str("hosts_file"),
            "ipcache_size": find_int(r"^\s*ipcache_size\s+(\d+)\s*$"),
            "fqdncache_size": find_int(r"^\s*fqdncache_size\s+(\d+)\s*$"),

            # SSL / bump helpers
            "dynamic_cert_mem_cache_size_mb": find_mb("dynamic_cert_mem_cache_size"),
            "sslcrtd_children": find_int(r"^\s*sslcrtd_children\s+(\d+)\s*$"),

            # ICAP
            "icap_enable": find_on_off("icap_enable"),
            "icap_send_client_ip": find_on_off("icap_send_client_ip"),
            "icap_send_client_port": find_on_off("icap_send_client_port"),
            "icap_send_client_username": find_on_off("icap_send_client_username"),
            "icap_preview_enable": find_on_off("icap_preview_enable"),
            "icap_preview_size_kb": find_size_kb("icap_preview_size"),
            "icap_connect_timeout_seconds": find_time_seconds("icap_connect_timeout"),
            "icap_io_timeout_seconds": find_time_seconds("icap_io_timeout"),

            # Privacy
            "forwarded_for_value": find_str("forwarded_for"),
            "via": find_on_off("via"),
            "follow_x_forwarded_for_value": find_str("follow_x_forwarded_for"),

            # Limits
            "request_header_max_size_kb": find_size_kb("request_header_max_size"),
            "reply_header_max_size_kb": find_size_kb("reply_header_max_size"),
            "request_body_max_size_mb": find_size_mb("request_body_max_size"),
            "client_request_buffer_max_size_kb": find_size_kb("client_request_buffer_max_size"),

            # Performance
            "memory_pools": find_on_off("memory_pools"),
            "memory_pools_limit_mb": find_size_mb("memory_pools_limit"),
            "store_avg_object_size_kb": find_size_kb("store_avg_object_size"),
            "store_objects_per_bucket": find_int(r"^\s*store_objects_per_bucket\s+(\d+)\s*$"),

            # HTTP / identity
            "visible_hostname": find_str("visible_hostname"),
            "httpd_suppress_version_string": find_on_off("httpd_suppress_version_string"),
        }

    def get_network_lines(self, config_text: Optional[str] = None) -> list[str]:
        text = config_text if config_text is not None else (self.get_current_config() or "")
        keys = (
            "pconn_timeout",
            "idle_pconn_timeout",
            "client_lifetime",
            "max_filedescriptors",
        )
        out: list[str] = []
        for line in (text or "").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            lower = stripped.lower()
            if any(lower.startswith(k) for k in keys):
                out.append(line)
        return out

    def get_dns_lines(self, config_text: Optional[str] = None) -> list[str]:
        text = config_text if config_text is not None else (self.get_current_config() or "")
        keys = (
            "dns_v4_first",
            "dns_timeout",
            "dns_retransmit",
            "dns_nameservers",
            "hosts_file",
            "positive_dns_ttl",
            "negative_dns_ttl",
            "ipcache_size",
            "fqdncache_size",
        )
        out: list[str] = []
        for line in (text or "").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            lower = stripped.lower()
            if any(lower.startswith(k) for k in keys):
                out.append(line)
        return out

    def get_ssl_lines(self, config_text: Optional[str] = None) -> list[str]:
        text = config_text if config_text is not None else (self.get_current_config() or "")
        keys = (
            "dynamic_cert_mem_cache_size",
            "sslcrtd_program",
            "sslcrtd_children",
            "ssl_bump",
        )
        out: list[str] = []
        for line in (text or "").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            lower = stripped.lower()
            if any(lower.startswith(k) for k in keys):
                out.append(line)
        return out

    def get_icap_lines(self, config_text: Optional[str] = None) -> list[str]:
        text = config_text if config_text is not None else (self.get_current_config() or "")
        out: list[str] = []
        for line in (text or "").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            lower = stripped.lower()
            if lower.startswith("include") and "/etc/squid/conf.d/20-icap.conf" in lower:
                out.append(line)
                continue
            if lower.startswith("icap_") or lower.startswith("adaptation_"):
                out.append(line)
        return out

    def get_privacy_lines(self, config_text: Optional[str] = None) -> list[str]:
        text = config_text if config_text is not None else (self.get_current_config() or "")
        keys = (
            "forwarded_for",
            "via",
            "follow_x_forwarded_for",
        )
        out: list[str] = []
        for line in (text or "").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            lower = stripped.lower()
            if any(lower.startswith(k) for k in keys):
                out.append(line)
        return out

    def get_limits_lines(self, config_text: Optional[str] = None) -> list[str]:
        text = config_text if config_text is not None else (self.get_current_config() or "")
        keys = (
            "request_header_max_size",
            "reply_header_max_size",
            "request_body_max_size",
            "client_request_buffer_max_size",
        )
        out: list[str] = []
        for line in (text or "").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            lower = stripped.lower()
            if any(lower.startswith(k) for k in keys):
                out.append(line)
        return out

    def get_performance_lines(self, config_text: Optional[str] = None) -> list[str]:
        text = config_text if config_text is not None else (self.get_current_config() or "")
        keys = (
            "memory_pools",
            "memory_pools_limit",
            "store_avg_object_size",
            "store_objects_per_bucket",
        )
        out: list[str] = []
        for line in (text or "").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            lower = stripped.lower()
            if any(lower.startswith(k) for k in keys):
                out.append(line)
        return out

    def get_http_lines(self, config_text: Optional[str] = None) -> list[str]:
        text = config_text if config_text is not None else (self.get_current_config() or "")
        keys = (
            "visible_hostname",
            "httpd_suppress_version_string",
        )
        out: list[str] = []
        for line in (text or "").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            lower = stripped.lower()
            if any(lower.startswith(k) for k in keys):
                out.append(line)
        return out

    def get_logging_lines(self, config_text: Optional[str] = None) -> list[str]:
        text = config_text if config_text is not None else (self.get_current_config() or "")
        keys = (
            "logformat",
            "access_log",
            "cache_log",
            "cache_store_log",
            "logfile_rotate",
        )
        out: list[str] = []
        for line in (text or "").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            lower = stripped.lower()
            if any(lower.startswith(k) for k in keys):
                out.append(line)
        return out

    def get_timeout_lines(self, config_text: Optional[str] = None) -> list[str]:
        text = config_text if config_text is not None else (self.get_current_config() or "")
        keys = (
            "connect_timeout",
            "request_timeout",
            "read_timeout",
            "forward_timeout",
            "shutdown_lifetime",
            "half_closed_clients",
        )
        out: list[str] = []
        for line in (text or "").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            lower = stripped.lower()
            if any(lower.startswith(k) for k in keys):
                out.append(line)
        return out

    def get_cache_override_options(self, config_text: Optional[str] = None) -> Dict[str, bool]:
        text = config_text if config_text is not None else self.get_current_config()

        def find_bool(name: str) -> bool:
            m = re.search(rf"^\s*#\s*{re.escape(name)}\s*=\s*([01])\s*$", text or "", re.M)
            return bool(m and m.group(1) == "1")

        return {
            "client_no_cache": find_bool("override_client_no_cache"),
            "client_no_store": find_bool("override_client_no_store"),
            "origin_private": find_bool("override_origin_private"),
            "origin_no_store": find_bool("override_origin_no_store"),
            "origin_no_cache": find_bool("override_origin_no_cache"),
            "ignore_auth": find_bool("override_ignore_auth"),
        }

    def get_caching_lines(self, config_text: Optional[str] = None) -> list[str]:
        text = config_text if config_text is not None else (self.get_current_config() or "")
        keys = (
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
        )
        out: list[str] = []
        for line in (text or "").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            lower = stripped.lower()
            if any(lower.startswith(k) for k in keys):
                out.append(line)
        return out

    def apply_cache_overrides(self, config_text: str, overrides: Dict[str, bool]) -> str:
        # Map UI override toggles to Squid refresh_pattern options.
        # NOTE: These are aggressive and can reduce privacy; keep them opt-in.
        ov = overrides or {}
        flags = []
        if bool(ov.get("client_no_cache")):
            # Best-effort: ignore client reload/no-cache requests.
            flags.append("ignore-reload")
        if bool(ov.get("origin_no_cache")):
            # Ignore origin no-cache directives.
            flags.append("ignore-no-cache")
        if bool(ov.get("origin_private")):
            flags.append("ignore-private")
        if bool(ov.get("client_no_store")) or bool(ov.get("origin_no_store")):
            flags.append("ignore-no-store")
        if bool(ov.get("ignore_auth")):
            # Allow caching of responses for requests requiring authorization.
            flags.append("ignore-auth")

        # Remove any existing managed override metadata block.
        start_marker = "# Cache overrides (managed by web UI)"
        end_marker = "# End cache overrides"
        text = (config_text or "")
        text = re.sub(
            rf"^\s*{re.escape(start_marker)}\s*$.*?^\s*{re.escape(end_marker)}\s*$\n?",
            "",
            text,
            flags=re.M | re.S,
        )

        # Normalize refresh_pattern lines by removing known override flags, then
        # re-appending the enabled ones.
        override_tokens = ("ignore-reload", "ignore-no-cache", "ignore-no-store", "ignore-private", "ignore-auth")

        def should_skip_refresh_pattern(line: str) -> bool:
            # Keep the explicit no-cache rule intact.
            if "(/cgi-bin/|\\?)" in line:
                return True
            return False

        out_lines = []
        saw_refresh = False
        for line in text.splitlines(True):
            if re.match(r"^\s*refresh_pattern\b", line):
                saw_refresh = True
                if should_skip_refresh_pattern(line):
                    out_lines.append(line)
                    continue

                # Strip any existing override tokens.
                stripped = line
                for tok in override_tokens:
                    stripped = re.sub(rf"\s+{re.escape(tok)}\b", "", stripped)

                # Append enabled flags.
                if flags:
                    # preserve trailing newline
                    nl = "\n" if stripped.endswith("\n") else ""
                    core = stripped.rstrip("\r\n")
                    core = core.rstrip()
                    stripped = core + " " + " ".join(flags) + nl
                out_lines.append(stripped)
                continue

            out_lines.append(line)

        rendered = "".join(out_lines)

        # Insert managed metadata block before the first refresh_pattern line.
        meta_block = "\n".join(
            [
                start_marker,
                f"# override_client_no_cache={'1' if bool(ov.get('client_no_cache')) else '0'}",
                f"# override_client_no_store={'1' if bool(ov.get('client_no_store')) else '0'}",
                f"# override_origin_private={'1' if bool(ov.get('origin_private')) else '0'}",
                f"# override_origin_no_store={'1' if bool(ov.get('origin_no_store')) else '0'}",
                f"# override_origin_no_cache={'1' if bool(ov.get('origin_no_cache')) else '0'}",
                f"# override_ignore_auth={'1' if bool(ov.get('ignore_auth')) else '0'}",
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
        cache_mem_mb = int(options.get("cache_mem_mb") or 256)
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
        # half_closed_clients can improve cache fill in some scenarios, but Squid
        # has had stability issues around half-closed monitoring in the past.
        # Default to off for stability; the UI can explicitly enable it.
        half_closed_clients_on = bool(options.get("half_closed_clients_on", False))

        logfile_rotate = options.get("logfile_rotate")

        pconn_timeout_seconds = options.get("pconn_timeout_seconds")
        idle_pconn_timeout_seconds = options.get("idle_pconn_timeout_seconds")
        client_lifetime_seconds = options.get("client_lifetime_seconds")
        max_filedescriptors = options.get("max_filedescriptors")

        dns_v4_first_on = bool(options.get("dns_v4_first_on", True))
        dns_timeout_seconds = options.get("dns_timeout_seconds")
        dns_retransmit_seconds = options.get("dns_retransmit_seconds")
        dns_nameservers = (options.get("dns_nameservers") or "").strip()
        hosts_file = (options.get("hosts_file") or "").strip()
        ipcache_size = options.get("ipcache_size")
        fqdncache_size = options.get("fqdncache_size")

        dynamic_cert_mem_cache_size_mb = options.get("dynamic_cert_mem_cache_size_mb")
        sslcrtd_children = options.get("sslcrtd_children")

        icap_enable_on = bool(options.get("icap_enable_on", True))
        icap_send_client_ip_on = bool(options.get("icap_send_client_ip_on", True))
        icap_send_client_port_on = bool(options.get("icap_send_client_port_on", False))
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

        visible_hostname = (options.get("visible_hostname") or "").strip()
        httpd_suppress_version_string_on = options.get("httpd_suppress_version_string_on")

        workers = int(options.get("workers") or 2)
        if workers < 1:
            workers = 1
        # Keep in sync with the web UI clamp.
        try:
            max_workers = int((os.environ.get("MAX_WORKERS") or "32").strip())
        except Exception:
            max_workers = 32
        max_workers = min(128, max(1, max_workers))
        if workers > max_workers:
            workers = max_workers

        # For cache-first deployments, defaults aim to keep filling cache even if clients abort.
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
        out = self._replace_or_append_line(out, "range_offset_limit", f"range_offset_limit {-1 if range_cache_on else 0}")

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
        out = self._replace_or_append_line(out, "half_closed_clients", f"half_closed_clients {'on' if half_closed_clients_on else 'off'}")

        if logfile_rotate is not None:
            out = self._replace_or_append_line(out, "logfile_rotate", f"logfile_rotate {int(logfile_rotate)}")

        # Network / connection lifecycle
        if pconn_timeout_seconds is not None:
            out = self._replace_or_append_line(out, "pconn_timeout", f"pconn_timeout {int(pconn_timeout_seconds)} seconds")
        if self._allow_legacy_directives() and idle_pconn_timeout_seconds is not None:
            out = self._replace_or_append_line(out, "idle_pconn_timeout", f"idle_pconn_timeout {int(idle_pconn_timeout_seconds)} seconds")
        if client_lifetime_seconds is not None:
            out = self._replace_or_append_line(out, "client_lifetime", f"client_lifetime {int(client_lifetime_seconds)} seconds")
        if max_filedescriptors is not None:
            out = self._replace_or_append_line(out, "max_filedescriptors", f"max_filedescriptors {int(max_filedescriptors)}")

        # DNS
        if self._allow_legacy_directives():
            out = self._replace_or_append_line(out, "dns_v4_first", f"dns_v4_first {'on' if dns_v4_first_on else 'off'}")
        if dns_timeout_seconds is not None:
            out = self._replace_or_append_line(out, "dns_timeout", f"dns_timeout {int(dns_timeout_seconds)} seconds")
        if self._allow_legacy_directives() and dns_retransmit_seconds is not None:
            out = self._replace_or_append_line(out, "dns_retransmit", f"dns_retransmit {int(dns_retransmit_seconds)} seconds")
        if dns_nameservers:
            out = self._replace_or_append_line(out, "dns_nameservers", f"dns_nameservers {dns_nameservers}")
        if hosts_file:
            out = self._replace_or_append_line(out, "hosts_file", f"hosts_file {hosts_file}")
        if ipcache_size is not None:
            out = self._replace_or_append_line(out, "ipcache_size", f"ipcache_size {int(ipcache_size)}")
        if fqdncache_size is not None:
            out = self._replace_or_append_line(out, "fqdncache_size", f"fqdncache_size {int(fqdncache_size)}")

        # SSL
        if self._allow_legacy_directives() and dynamic_cert_mem_cache_size_mb is not None:
            out = self._replace_or_append_line(out, "dynamic_cert_mem_cache_size", f"dynamic_cert_mem_cache_size {int(dynamic_cert_mem_cache_size_mb)}MB")
        if sslcrtd_children is not None:
            out = self._replace_or_append_line(out, "sslcrtd_children", f"sslcrtd_children {int(sslcrtd_children)}")

        # ICAP
        out = self._replace_or_append_line(out, "icap_enable", f"icap_enable {'on' if icap_enable_on else 'off'}")
        out = self._replace_or_append_line(out, "icap_send_client_ip", f"icap_send_client_ip {'on' if icap_send_client_ip_on else 'off'}")
        if self._allow_legacy_directives():
            out = self._replace_or_append_line(out, "icap_send_client_port", f"icap_send_client_port {'on' if icap_send_client_port_on else 'off'}")
        out = self._replace_or_append_line(out, "icap_send_client_username", f"icap_send_client_username {'on' if icap_send_client_username_on else 'off'}")
        out = self._replace_or_append_line(out, "icap_preview_enable", f"icap_preview_enable {'on' if icap_preview_enable_on else 'off'}")
        if icap_preview_size_kb is not None:
            out = self._replace_or_append_line(out, "icap_preview_size", f"icap_preview_size {int(icap_preview_size_kb)} KB")
        if icap_connect_timeout_seconds is not None:
            out = self._replace_or_append_line(out, "icap_connect_timeout", f"icap_connect_timeout {int(icap_connect_timeout_seconds)} seconds")
        if icap_io_timeout_seconds is not None:
            out = self._replace_or_append_line(out, "icap_io_timeout", f"icap_io_timeout {int(icap_io_timeout_seconds)} seconds")

        # Privacy
        if forwarded_for_value:
            out = self._replace_or_append_line(out, "forwarded_for", f"forwarded_for {forwarded_for_value}")
        if via_on is not None:
            out = self._replace_or_append_line(out, "via", f"via {'on' if bool(via_on) else 'off'}")
        if follow_x_forwarded_for_value:
            out = self._replace_or_append_line(out, "follow_x_forwarded_for", f"follow_x_forwarded_for {follow_x_forwarded_for_value}")

        # Limits
        if request_header_max_size_kb is not None:
            out = self._replace_or_append_line(out, "request_header_max_size", f"request_header_max_size {int(request_header_max_size_kb)} KB")
        if reply_header_max_size_kb is not None:
            out = self._replace_or_append_line(out, "reply_header_max_size", f"reply_header_max_size {int(reply_header_max_size_kb)} KB")
        if request_body_max_size_mb is not None:
            out = self._replace_or_append_line(out, "request_body_max_size", f"request_body_max_size {int(request_body_max_size_mb)} MB")
        if client_request_buffer_max_size_kb is not None:
            out = self._replace_or_append_line(out, "client_request_buffer_max_size", f"client_request_buffer_max_size {int(client_request_buffer_max_size_kb)} KB")

        # Performance
        if memory_pools_on is not None:
            out = self._replace_or_append_line(out, "memory_pools", f"memory_pools {'on' if bool(memory_pools_on) else 'off'}")
        if memory_pools_limit_mb is not None:
            out = self._replace_or_append_line(out, "memory_pools_limit", f"memory_pools_limit {int(memory_pools_limit_mb)} MB")
        if store_avg_object_size_kb is not None:
            out = self._replace_or_append_line(out, "store_avg_object_size", f"store_avg_object_size {int(store_avg_object_size_kb)} KB")
        if store_objects_per_bucket is not None:
            out = self._replace_or_append_line(out, "store_objects_per_bucket", f"store_objects_per_bucket {int(store_objects_per_bucket)}")

        # HTTP
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
        # exclusions should look like Exclusions (domains, src_nets, exclude_private_nets).
        base = self.generate_config_from_template(options)

        domains = [d.strip().lower().lstrip(".") for d in (getattr(exclusions, "domains", []) or []) if d.strip()]
        src_nets = [c.strip() for c in (getattr(exclusions, "src_nets", []) or []) if c.strip()]
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

        # Insert ssl_bump splice rules before the catch-all bump.
        insert_ssl = "\n".join(["", "# Exclusions (managed by web UI)"] + acl_lines + splice_lines) + "\n"
        base = base.replace("ssl_bump bump all", insert_ssl + "ssl_bump bump all", 1)

        # Insert cache deny rules after cache settings header if present, else append.
        deny_block = "\n".join(["", "# Exclusions (managed by web UI)"] + cache_deny_lines) + "\n"
        if "# Cache settings" in base:
            # Put deny lines after the cache settings section (before log settings) if possible.
            marker = "# Log settings"
            if marker in base:
                base = base.replace(marker, deny_block + "\n" + marker, 1)
            else:
                base = base.rstrip() + deny_block
        else:
            base = base.rstrip() + deny_block

        return base

    def validate_config_text(self, config_text: str) -> Tuple[bool, str]:
        # Validate by writing to a temp file and invoking Squid's parser.
        tmp_path = ""
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False, prefix="squid-conf-", dir="/tmp") as f:
                tmp_path = f.name
                f.write(config_text)

            p = run(["squid", "-k", "parse", "-f", tmp_path], capture_output=True, text=True, timeout=6)
            combined = (p.stdout or "") + ("\n" if p.stdout and p.stderr else "") + (p.stderr or "")
            return p.returncode == 0, combined.strip()
        except Exception as e:
            logger.exception("Squid config validation failed")
            return False, public_error_message(e)
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    def _extract_workers(self, config_text: str) -> Optional[int]:
        try:
            m = re.search(r"^\s*workers\s+(\d+)\s*$", config_text or "", re.M | re.I)
            return int(m.group(1)) if m else None
        except Exception:
            return None

    def _decode_completed(self, p: Any) -> str:
        out = getattr(p, "stdout", b"")
        err = getattr(p, "stderr", b"")
        if isinstance(out, bytes):
            out_s = out.decode("utf-8", errors="replace")
        else:
            out_s = str(out or "")
        if isinstance(err, bytes):
            err_s = err.decode("utf-8", errors="replace")
        else:
            err_s = str(err or "")
        if out_s and err_s:
            return (out_s + "\n" + err_s).strip()
        return (out_s or err_s).strip()

    def restart_squid(self) -> Tuple[bool, str]:
        # Preferred: ask supervisord to restart only Squid.
        try:
            p = run(["supervisorctl", "-c", "/etc/supervisord.conf", "restart", "squid"], capture_output=True, timeout=12)
            if p.returncode == 0:
                return True, self._decode_completed(p) or "Squid restarted."
            details = self._decode_completed(p) or "supervisorctl restart squid failed"
        except Exception as e:
            details = str(e)

        # Fallback: request Squid shutdown. supervisord should restart it (autorestart=true).
        try:
            p2 = run(["squid", "-k", "shutdown"], capture_output=True, timeout=8)
            if p2.returncode == 0:
                return True, (details + "\n" if details else "") + (self._decode_completed(p2) or "Squid shutdown requested (supervisor will restart).")
            return False, (details + "\n" if details else "") + (self._decode_completed(p2) or "Squid shutdown request failed.")
        except Exception as e2:
            return False, (details + "\n" if details else "") + str(e2)

    def _get_first_cache_dir_path(self, config_text: Optional[str] = None) -> str:
        # Best-effort: parse the first `cache_dir ufs <path> ...`.
        text = config_text if config_text is not None else self.get_current_config()
        try:
            m = re.search(r"^\s*cache_dir\s+ufs\s+(\S+)\s+\d+\s+\d+\s+\d+", text or "", re.M | re.I)
            if m:
                return (m.group(1) or "").strip()
        except Exception:
            log_exception_throttled(
                logger,
                "squidctl.parse_cache_dir",
                interval_seconds=300.0,
                message="Failed to parse cache_dir from squid config; using default",
            )
        return "/var/spool/squid"

    def clear_disk_cache(self) -> Tuple[bool, str]:
        """Clear Squid on-disk cache (cache_dir) and restart Squid.

        This deletes cached objects under the configured cache_dir, then runs
        `squid -z` to recreate the directory structure.
        """
        cache_path = self._get_first_cache_dir_path()

        # Guardrails: avoid deleting unexpected locations.
        if not cache_path.startswith("/") or cache_path in ("/", "/etc", "/bin", "/usr", "/var"):
            return False, f"Refusing to clear cache_dir at unsafe path: {cache_path}"

        details_parts = []

        # Stop Squid first (avoid corrupting swap.state).
        try:
            p_stop = run(["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "squid"], capture_output=True, timeout=20)
            details_parts.append(self._decode_completed(p_stop) or "supervisorctl stop squid")
        except Exception as e:
            details_parts.append(f"stop failed: {e}")
            try:
                run(["squid", "-k", "shutdown"], capture_output=True, timeout=10)
            except Exception:
                log_exception_throttled(
                    logger,
                    "squidctl.shutdown_fallback",
                    interval_seconds=300.0,
                    message="Squid shutdown fallback failed while clearing disk cache",
                )

        # Delete contents (but not the cache_dir itself).
        try:
            if os.path.isdir(cache_path):
                for name in os.listdir(cache_path):
                    p = os.path.join(cache_path, name)
                    try:
                        if os.path.isdir(p) and not os.path.islink(p):
                            shutil.rmtree(p, ignore_errors=True)
                        else:
                            os.unlink(p)
                    except IsADirectoryError:
                        shutil.rmtree(p, ignore_errors=True)
                    except FileNotFoundError:
                        pass
            else:
                os.makedirs(cache_path, exist_ok=True)
            details_parts.append(f"cleared: {cache_path}")
        except Exception as e:
            return False, ("\n".join(details_parts) + "\n" if details_parts else "") + f"cache delete failed: {e}"

        # Recreate cache structure.
        try:
            p_z = run(["squid", "-z", "-f", self.squid_conf_path], capture_output=True, timeout=90)
            if p_z.returncode != 0:
                details_parts.append(self._decode_completed(p_z) or "squid -z failed")
                # Attempt restart anyway.
            else:
                details_parts.append(self._decode_completed(p_z) or "squid -z OK")
        except Exception as e:
            details_parts.append(f"squid -z error: {e}")

        ok_restart, restart_details = self.restart_squid()
        details_parts.append(restart_details or ("Squid restarted." if ok_restart else "Squid restart failed."))
        return ok_restart, "\n".join([p for p in details_parts if p]).strip()

    def apply_config_text(self, config_text: str) -> Tuple[bool, str]:
        # Validate -> swap in -> reconfigure -> revert on failure.
        ok, details = self.validate_config_text(config_text)
        if not ok:
            return False, details or "Squid config validation failed."

        backup_path = self.squid_conf_path + ".bak"
        new_path = self.squid_conf_path + ".new"
        try:
            current = self.get_current_config()
            old_workers = self._extract_workers(current)
            new_workers = self._extract_workers(config_text)
            workers_changed = (new_workers is not None and new_workers != old_workers)

            old_icap_include = None
            old_icap_supervisor = None
            if workers_changed and new_workers is not None:
                try:
                    old_icap_include = Path("/etc/squid/conf.d/20-icap.conf").read_text(encoding="utf-8")
                except Exception:
                    old_icap_include = None
                try:
                    old_icap_supervisor = Path("/etc/supervisor.d/icap.conf").read_text(encoding="utf-8")
                except Exception:
                    old_icap_supervisor = None

            self._write_file(new_path, config_text)
            if current:
                self._write_file(backup_path, current)
            os.replace(new_path, self.squid_conf_path)

            if workers_changed:
                ok_scale, scale_details = self.apply_icap_scaling(new_workers or 1)
                if not ok_scale:
                    if os.path.exists(backup_path):
                        os.replace(backup_path, self.squid_conf_path)
                    try:
                        if old_icap_include is not None:
                            Path("/etc/squid/conf.d/20-icap.conf").write_text(old_icap_include, encoding="utf-8")
                    except Exception:
                        log_exception_throttled(
                            logger,
                            "squidctl.revert_icap_include",
                            interval_seconds=300.0,
                            message="Failed to revert /etc/squid/conf.d/20-icap.conf",
                        )
                    try:
                        if old_icap_supervisor is not None:
                            Path("/etc/supervisor.d/icap.conf").write_text(old_icap_supervisor, encoding="utf-8")
                    except Exception:
                        log_exception_throttled(
                            logger,
                            "squidctl.revert_icap_supervisor",
                            interval_seconds=300.0,
                            message="Failed to revert /etc/supervisor.d/icap.conf",
                        )
                    self._supervisor_reread_update()
                    self.restart_squid()
                    return False, scale_details or "Failed to scale ICAP processes."

                ok_restart, restart_details = self.restart_squid()
                if not ok_restart:
                    if os.path.exists(backup_path):
                        os.replace(backup_path, self.squid_conf_path)
                        try:
                            if old_icap_include is not None:
                                Path("/etc/squid/conf.d/20-icap.conf").write_text(old_icap_include, encoding="utf-8")
                        except Exception:
                            log_exception_throttled(
                                logger,
                                "squidctl.revert_icap_include.restart",
                                interval_seconds=300.0,
                                message="Failed to revert /etc/squid/conf.d/20-icap.conf after restart failure",
                            )
                        try:
                            if old_icap_supervisor is not None:
                                Path("/etc/supervisor.d/icap.conf").write_text(old_icap_supervisor, encoding="utf-8")
                        except Exception:
                            log_exception_throttled(
                                logger,
                                "squidctl.revert_icap_supervisor.restart",
                                interval_seconds=300.0,
                                message="Failed to revert /etc/supervisor.d/icap.conf after restart failure",
                            )
                        self._supervisor_reread_update()
                        self.restart_squid()
                    return False, restart_details or "Squid restart failed."
                # Persist only after the new config is actually active.
                try:
                    os.makedirs(os.path.dirname(self.persisted_squid_conf_path), exist_ok=True)
                    self._atomic_write_file(self.persisted_squid_conf_path, config_text)
                except Exception:
                    log_exception_throttled(
                        logger,
                        "squidctl.persist_config.workers",
                        interval_seconds=300.0,
                        message="Failed to persist squid config after workers change",
                    )

                msg = (restart_details or "Squid restarted.").strip()
                if scale_details:
                    msg = (msg + "\n" + scale_details).strip()
                return True, msg

            p = run(["squid", "-k", "reconfigure"], capture_output=True, timeout=6)
            if p.returncode != 0:
                if os.path.exists(backup_path):
                    os.replace(backup_path, self.squid_conf_path)
                    run(["squid", "-k", "reconfigure"], capture_output=True, timeout=6)
                return False, self._decode_completed(p) or "Squid reconfigure failed."

            # Persist only after the new config is actually active.
            try:
                os.makedirs(os.path.dirname(self.persisted_squid_conf_path), exist_ok=True)
                self._atomic_write_file(self.persisted_squid_conf_path, config_text)
            except Exception:
                log_exception_throttled(
                    logger,
                    "squidctl.persist_config",
                    interval_seconds=300.0,
                    message="Failed to persist squid config after reconfigure",
                )

            return True, self._decode_completed(p) or "Squid reconfigured."
        except Exception as e:
            # Best-effort revert.
            try:
                if os.path.exists(backup_path):
                    os.replace(backup_path, self.squid_conf_path)
                    run(["squid", "-k", "reconfigure"], capture_output=True, timeout=6)
            except Exception:
                log_exception_throttled(
                    logger,
                    "squidctl.revert_failed",
                    interval_seconds=300.0,
                    message="Squid config revert failed after reconfigure error",
                )
            logger.exception("Squid reconfigure failed")
            return False, public_error_message(e)
        finally:
            try:
                if os.path.exists(new_path):
                    os.unlink(new_path)
            except OSError:
                pass

    def start_squid(self):
        # Best-effort. Prefer supervisor-managed start when available.
        try:
            p = run(
                ["supervisorctl", "-c", "/etc/supervisord.conf", "start", "squid"],
                capture_output=True,
                timeout=12,
            )
            if p.returncode == 0:
                return p.stdout or b"", p.stderr or b""
        except FileNotFoundError:
            pass
        except Exception:
            log_exception_throttled(
                logger,
                "squidctl.start_squid.supervisor",
                interval_seconds=300.0,
                message="supervisorctl start squid failed",
            )

        # Fallback: attempt direct start (daemonizes by default).
        try:
            p = run(["squid", "-f", self.squid_conf_path], capture_output=True, timeout=12)
            return p.stdout or b"", p.stderr or b""
        except FileNotFoundError:
            return b"", b"squid binary not found"
        except Exception as e:
            return b"", str(e).encode("utf-8", errors="replace")

    def stop_squid(self):
        try:
            p = run(["squid", "-k", "shutdown"], capture_output=True, timeout=12)
            return p.stdout or b"", p.stderr or b""
        except FileNotFoundError:
            return b"", b"squid binary not found"
        except Exception as e:
            return b"", str(e).encode("utf-8", errors="replace")

    def reload_squid(self):
        try:
            p = run(["squid", "-k", "reconfigure"], capture_output=True, timeout=12)
            return p.stdout or b"", p.stderr or b""
        except FileNotFoundError:
            return b"", b"squid binary not found"
        except Exception as e:
            return b"", str(e).encode("utf-8", errors="replace")

    def get_status(self):
        try:
            p = run(["squid", "-k", "check"], capture_output=True, timeout=6)
            stdout = p.stdout or b""
            stderr = p.stderr or b""
            if p.returncode != 0 and not stderr:
                stderr = stdout or f"squid check failed rc={p.returncode}".encode("utf-8")
            return stdout, stderr
        except FileNotFoundError:
            return b"", b"squid binary not found"
        except Exception as e:
            return b"", str(e).encode("utf-8", errors="replace")

    def get_current_config(self):
        if os.path.exists(self.squid_conf_path):
            with open(self.squid_conf_path, 'r', encoding='utf-8') as f:
                return f.read()
        return ""

    def update_config(self, config_text: str):
        # Backwards-compatible: validate + apply with revert on failure.
        self.apply_config_text(config_text)