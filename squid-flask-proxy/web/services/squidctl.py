from __future__ import annotations

import os
import re
import tempfile
import shutil
from pathlib import Path
from subprocess import PIPE, Popen, run
from typing import Any, Dict, Optional, Tuple

try:
    from services.exclusions_store import Exclusions
except Exception:  # pragma: no cover
    Exclusions = None  # type: ignore[assignment]

class SquidController:
    def __init__(self, squid_conf_path: str = "/etc/squid/squid.conf"):
        self.squid_conf_path = squid_conf_path
        self.squid_conf_template_path = "/etc/squid/squid.conf.template"
        if (not os.path.exists(self.squid_conf_template_path)) and os.path.exists("/squid/squid.conf.template"):
            self.squid_conf_template_path = "/squid/squid.conf.template"

    def _read_file(self, path: str) -> str:
        with open(path, 'r', encoding='utf-8') as f:
            return f.read()

    def _write_file(self, path: str, content: str) -> None:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)

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
            return False, str(e)

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
            return False, str(e)

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
        text = config_text if config_text is not None else self.get_current_config()

        def find_int(pattern: str) -> Optional[int]:
            m = re.search(pattern, text, re.M | re.I)
            return int(m.group(1)) if m else None

        def find_on_off(key: str) -> Optional[bool]:
            m = re.search(rf"^\s*{re.escape(key)}\s+(on|off)\s*$", text, re.M | re.I)
            if not m:
                return None
            return m.group(1).lower() == "on"

        def find_str(key: str) -> Optional[str]:
            m = re.search(rf"^\s*{re.escape(key)}\s+(.+?)\s*$", text, re.M | re.I)
            return m.group(1).strip() if m else None

        def find_kb(key: str) -> Optional[int]:
            m = re.search(rf"^\s*{re.escape(key)}\s+(\d+)\s*(KB|K|KBYTES)?\s*$", text, re.M | re.I)
            return int(m.group(1)) if m else None

        def find_pct(key: str) -> Optional[int]:
            m = re.search(rf"^\s*{re.escape(key)}\s+(\d+)\s*%?\s*$", text, re.M | re.I)
            return int(m.group(1)) if m else None

        return {
            "cache_dir_size_mb": find_int(r"^\s*cache_dir\s+ufs\s+\S+\s+(\d+)\s+\d+\s+\d+"),
            "cache_mem_mb": find_int(r"^\s*cache_mem\s+(\d+)\s*MB\s*$"),
            "maximum_object_size_mb": find_int(r"^\s*maximum_object_size\s+(\d+)\s*MB\s*$"),
            "maximum_object_size_in_memory_kb": find_int(r"^\s*maximum_object_size_in_memory\s+(\d+)\s*KB\s*$"),
            "cache_swap_low": find_int(r"^\s*cache_swap_low\s+(\d+)\s*$"),
            "cache_swap_high": find_int(r"^\s*cache_swap_high\s+(\d+)\s*$"),
            "collapsed_forwarding": find_on_off("collapsed_forwarding"),
            "range_offset_limit": find_int(r"^\s*range_offset_limit\s+(-?\d+)\s*$"),

            # SMP
            "workers": find_int(r"^\s*workers\s+(\d+)\s*$"),

            # Cache effectiveness/performance
            "cache_replacement_policy": find_str("cache_replacement_policy"),
            "memory_replacement_policy": find_str("memory_replacement_policy"),
            "pipeline_prefetch": find_on_off("pipeline_prefetch"),

            # Cache-first tuning (whether to continue fetching when clients abort)
            "quick_abort_min_kb": find_kb("quick_abort_min"),
            "quick_abort_max_kb": find_kb("quick_abort_max"),
            "quick_abort_pct": find_pct("quick_abort_pct"),
        }

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
        }

    def apply_cache_overrides(self, config_text: str, overrides: Dict[str, bool]) -> str:
        # Map UI override toggles to Squid refresh_pattern options.
        # NOTE: These are aggressive and can reduce privacy; keep them opt-in.
        ov = overrides or {}
        flags = []
        if bool(ov.get("client_no_cache")):
            # Best-effort: ignore client reload/no-cache requests.
            flags.append("ignore-reload")
        if bool(ov.get("origin_private")):
            flags.append("ignore-private")
        if bool(ov.get("client_no_store")) or bool(ov.get("origin_no_store")):
            flags.append("ignore-no-store")

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
        override_tokens = ("ignore-reload", "ignore-no-cache", "ignore-no-store", "ignore-private")

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
        cache_swap_low = int(options.get("cache_swap_low") or 90)
        cache_swap_high = int(options.get("cache_swap_high") or 95)

        collapsed_forwarding_on = bool(options.get("collapsed_forwarding_on", True))
        range_cache_on = bool(options.get("range_cache_on", True))

        cache_replacement_policy = (options.get("cache_replacement_policy") or "heap GDSF").strip()
        memory_replacement_policy = (options.get("memory_replacement_policy") or "heap GDSF").strip()
        pipeline_prefetch_on = bool(options.get("pipeline_prefetch_on", True))

        workers = int(options.get("workers") or 2)
        if workers < 1:
            workers = 1
        if workers > 32:
            workers = 32

        # For cache-first deployments, defaults aim to keep filling cache even if clients abort.
        quick_abort_min_kb = int(options.get("quick_abort_min_kb") if options.get("quick_abort_min_kb") is not None else 0)
        quick_abort_max_kb = int(options.get("quick_abort_max_kb") if options.get("quick_abort_max_kb") is not None else 0)
        quick_abort_pct = int(options.get("quick_abort_pct") if options.get("quick_abort_pct") is not None else 100)

        out = template_text
        out = self._replace_cache_dir_size_mb(out, cache_dir_size_mb)
        out = self._replace_or_append_line(out, "cache_mem", f"cache_mem {cache_mem_mb} MB")
        out = self._replace_or_append_line(out, "maximum_object_size", f"maximum_object_size {maximum_object_size_mb} MB")
        out = self._replace_or_append_line(out, "maximum_object_size_in_memory", f"maximum_object_size_in_memory {maximum_object_size_in_memory_kb} KB")
        out = self._replace_or_append_line(out, "cache_swap_low", f"cache_swap_low {cache_swap_low}")
        out = self._replace_or_append_line(out, "cache_swap_high", f"cache_swap_high {cache_swap_high}")
        out = self._replace_or_append_line(out, "collapsed_forwarding", f"collapsed_forwarding {'on' if collapsed_forwarding_on else 'off'}")
        out = self._replace_or_append_line(out, "range_offset_limit", f"range_offset_limit {-1 if range_cache_on else 0}")

        out = self._replace_or_append_line(out, "cache_replacement_policy", f"cache_replacement_policy {cache_replacement_policy}")
        out = self._replace_or_append_line(out, "memory_replacement_policy", f"memory_replacement_policy {memory_replacement_policy}")
        out = self._replace_or_append_line(out, "pipeline_prefetch", f"pipeline_prefetch {'on' if pipeline_prefetch_on else 'off'}")

        out = self._replace_or_append_line(out, "workers", f"workers {workers}")

        out = self._replace_or_append_line(out, "quick_abort_min", f"quick_abort_min {quick_abort_min_kb} KB")
        out = self._replace_or_append_line(out, "quick_abort_max", f"quick_abort_max {quick_abort_max_kb} KB")
        out = self._replace_or_append_line(out, "quick_abort_pct", f"quick_abort_pct {quick_abort_pct}")
        return out

    def generate_config_from_template_with_exclusions(self, options: Dict[str, Any], exclusions: Any) -> str:
        # exclusions should look like Exclusions (domains, dst_nets, src_nets).
        base = self.generate_config_from_template(options)

        domains = [d.strip().lower().lstrip(".") for d in (getattr(exclusions, "domains", []) or []) if d.strip()]
        dst_nets = [c.strip() for c in (getattr(exclusions, "dst_nets", []) or []) if c.strip()]
        src_nets = [c.strip() for c in (getattr(exclusions, "src_nets", []) or []) if c.strip()]

        acl_lines = []
        splice_lines = []
        cache_deny_lines = []

        if domains:
            acl_lines.append("acl excluded_domains dstdomain " + " ".join(domains))
            splice_lines.append("ssl_bump splice excluded_domains")
            cache_deny_lines.append("cache deny excluded_domains")

        if dst_nets:
            acl_lines.append("acl excluded_dst dst " + " ".join(dst_nets))
            splice_lines.append("ssl_bump splice excluded_dst")
            cache_deny_lines.append("cache deny excluded_dst")

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
            return False, str(e)
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
            pass
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
                pass

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
                        pass
                    try:
                        if old_icap_supervisor is not None:
                            Path("/etc/supervisor.d/icap.conf").write_text(old_icap_supervisor, encoding="utf-8")
                    except Exception:
                        pass
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
                            pass
                        try:
                            if old_icap_supervisor is not None:
                                Path("/etc/supervisor.d/icap.conf").write_text(old_icap_supervisor, encoding="utf-8")
                        except Exception:
                            pass
                        self._supervisor_reread_update()
                        self.restart_squid()
                    return False, restart_details or "Squid restart failed."
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

            return True, self._decode_completed(p) or "Squid reconfigured."
        except Exception as e:
            # Best-effort revert.
            try:
                if os.path.exists(backup_path):
                    os.replace(backup_path, self.squid_conf_path)
                    run(["squid", "-k", "reconfigure"], capture_output=True, timeout=6)
            except Exception:
                pass
            return False, str(e)
        finally:
            try:
                if os.path.exists(new_path):
                    os.unlink(new_path)
            except OSError:
                pass

    def start_squid(self):
        try:
            process = Popen(['squid', '-N', '-f', self.squid_conf_path], stdout=PIPE, stderr=PIPE)
            stdout, stderr = process.communicate()
            return stdout, stderr
        except FileNotFoundError:
            return b"", b"squid binary not found"

    def stop_squid(self):
        try:
            process = Popen(['squid', '-k', 'shutdown'], stdout=PIPE, stderr=PIPE)
            stdout, stderr = process.communicate()
            return stdout, stderr
        except FileNotFoundError:
            return b"", b"squid binary not found"

    def reload_squid(self):
        try:
            process = Popen(['squid', '-k', 'reconfigure'], stdout=PIPE, stderr=PIPE)
            stdout, stderr = process.communicate()
            return stdout, stderr
        except FileNotFoundError:
            return b"", b"squid binary not found"

    def get_status(self):
        try:
            process = Popen(['squid', '-k', 'check'], stdout=PIPE, stderr=PIPE)
            stdout, stderr = process.communicate()
            return stdout, stderr
        except FileNotFoundError:
            return b"", b"squid binary not found"

    def get_current_config(self):
        if os.path.exists(self.squid_conf_path):
            with open(self.squid_conf_path, 'r', encoding='utf-8') as f:
                return f.read()
        return ""

    def update_config(self, config_text: str):
        # Backwards-compatible: validate + apply with revert on failure.
        self.apply_config_text(config_text)