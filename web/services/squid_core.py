from __future__ import annotations

import contextlib
import logging
import os
import re
import shutil
import signal
import socket
import tempfile
import time
from collections.abc import Callable
from functools import lru_cache
from pathlib import Path
from subprocess import TimeoutExpired, run
from typing import Any

from services.clamav_config_forms import (
    clamav_fail_open,
    extract_clamav_options,
    render_file_security_policy_config,
    render_virus_scan_config,
)
from services.errors import public_error_message
from services.logutil import log_exception_throttled

logger = logging.getLogger(__name__)


def _file_has_non_comment_lines(path: str) -> bool:
    try:
        with Path(path).open(encoding="utf-8", errors="replace") as handle:
            for line in handle:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    return True
    except OSError:
        return False
    return False


@lru_cache(maxsize=1)
def _cached_icap_include_path() -> Path:
    return Path(
        (
            os.environ.get("SQUID_ICAP_INCLUDE_PATH")
            or "/etc/squid/conf.d/20-icap.conf"
        ).strip()
        or "/etc/squid/conf.d/20-icap.conf",
    )


@lru_cache(maxsize=1)
def _cached_virus_scan_config_path() -> Path:
    return Path(
        (os.environ.get("VIRUS_SCAN_CONFIG_PATH") or "/etc/virus_scan.conf").strip()
        or "/etc/virus_scan.conf",
    )


CommandRunner = Callable[..., Any]


class SquidController:
    _LIVEUI_LOGFORMAT = r"logformat liveui %ts\t%tr\t%>a\t%rm\t%ru\t%Ss/%>Hs\t%st"
    _DIAGNOSTIC_LOGFORMAT = r"logformat diagnostic %ts\t%tr\t%>a\t%rm\t%ru\t%Ss/%>Hs\t%st\t%master_xaction\t%Sh\t%ssl::bump_mode\t%ssl::>sni\t%ssl::>negotiated_version\t%ssl::>negotiated_cipher\t%ssl::<negotiated_version\t%ssl::<negotiated_cipher\t%{Host}>h\t%{User-Agent}>h\t%{Referer}>h\t%{exclusion_rule}note\t%{ssl_exception}note\t%{webfilter_allow}note\t%{cache_bypass}note"
    _ICAP_OBSERVE_LOGFORMAT = r"logformat icapobserve %ts\t%master_xaction\t%>a\t%rm\t%ru\t%icap::tt\t%adapt::sum_trs\t%adapt::all_trs\t%{Host}>h\t%{User-Agent}>h\t%ssl::>sni\t%{exclusion_rule}note\t%{ssl_exception}note\t%{webfilter_allow}note\t%{cache_bypass}note"

    def __init__(
        self,
        squid_conf_path: str = "/etc/squid/squid.conf",
        *,
        cmd_run: CommandRunner = run,
    ) -> None:
        self.squid_conf_path = squid_conf_path
        self.persisted_squid_conf_path = os.environ.get(
            "PERSISTED_SQUID_CONF_PATH",
            "/var/lib/squid-flask-proxy/squid.conf",
        )
        self._run = cmd_run
        self._adblock_icap_revision_token = ""

    def _write_file(self, path: str, content: str) -> None:
        Path(path).write_text(content, encoding="utf-8")

    def _atomic_write_file(self, path: str, content: str) -> None:
        directory = Path(path).parent or "."
        Path(directory).mkdir(exist_ok=True, parents=True)
        tmp_path = ""
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                delete=False,
                dir=directory,
                prefix=".tmp-",
            ) as handle:
                tmp_path = handle.name
                handle.write(content)
            Path(tmp_path).replace(path)
        finally:
            if tmp_path and Path(tmp_path).exists():
                with contextlib.suppress(Exception):
                    Path(tmp_path).unlink()

    def _persist_good_config(self, config_text: str) -> None:
        persisted_dir = Path(self.persisted_squid_conf_path).parent
        if persisted_dir:
            Path(persisted_dir).mkdir(exist_ok=True, parents=True)
        self._atomic_write_file(
            self.persisted_squid_conf_path,
            self.normalize_config_text(config_text),
        )

    def restore_last_known_good_config(
        self,
        *,
        reason: str = "",
        fallback_config: str = "",
    ) -> tuple[bool, str]:
        """Restore the last successfully-applied Squid config and restart Squid.

        The persisted config is intentionally written only after successful applies,
        so it is the proxy container's local last-known-good copy. The optional
        fallback is the in-memory pre-change config captured during an apply.
        """
        detail_parts: list[str] = []
        if reason:
            detail_parts.append(str(reason).strip())

        source = ""
        candidate = ""
        try:
            if Path(self.persisted_squid_conf_path).exists():
                candidate = Path(self.persisted_squid_conf_path).read_text(
                    encoding="utf-8",
                )
                source = self.persisted_squid_conf_path
        except Exception as exc:
            detail_parts.append(f"Failed to read last-known-good config: {exc}")

        if not candidate.strip() and (fallback_config or "").strip():
            candidate = fallback_config
            source = "pre-change in-memory backup"

        if not candidate.strip():
            detail_parts.append(
                "No last-known-good Squid config is available to restore.",
            )
            return False, "\n".join(part for part in detail_parts if part).strip()

        normalized = self.normalize_config_text(candidate)
        valid, validation_detail = self.validate_config_text(normalized)
        if not valid:
            if "timed out" in (validation_detail or "").lower():
                detail_parts.append(
                    f"Validation of last-known-good config from {source} timed out; proceeding with restore because this file was previously applied successfully.",
                )
                if validation_detail:
                    detail_parts.append(validation_detail)
            else:
                detail_parts.append(
                    f"Last-known-good config from {source} failed validation.",
                )
                if validation_detail:
                    detail_parts.append(validation_detail)
                return False, "\n".join(part for part in detail_parts if part).strip()

        try:
            self._atomic_write_file(self.squid_conf_path, normalized)
        except Exception as exc:
            detail_parts.append(f"Failed to write restored Squid config: {exc}")
            return False, "\n".join(part for part in detail_parts if part).strip()

        ok_restart, restart_detail = self.restart_squid()
        if restart_detail:
            detail_parts.append(restart_detail)
        if not ok_restart:
            detail_parts.append(
                "Rollback config was written, but Squid did not restart cleanly.",
            )
            return False, "\n".join(part for part in detail_parts if part).strip()

        try:
            self._persist_good_config(normalized)
        except Exception:
            log_exception_throttled(
                logger,
                "squid_core.persist_config.rollback",
                interval_seconds=300.0,
                message="Failed to persist restored last-known-good Squid config",
            )

        detail_parts.append(
            f"Rolled back to last-known-good Squid config from {source}.",
        )
        return True, "\n".join(part for part in detail_parts if part).strip()

    def _replace_or_append_directive(
        self,
        text: str,
        pattern: str,
        replacement: str,
    ) -> str:
        regex = re.compile(pattern, re.MULTILINE)
        if regex.search(text):
            return regex.sub(replacement, text, count=1)
        return text.rstrip() + "\n" + replacement + "\n"

    def _ensure_line_before_first_http_access(self, text: str, line: str) -> str:
        wanted = line.strip()
        if not wanted:
            return text
        # This include is order-sensitive: if a legacy/manual config already has it
        # after a broad `http_access allow all`, webfilter denies are unreachable.
        # Normalize to one copy immediately before the first http_access directive.
        text = re.sub(rf"^\s*{re.escape(wanted)}\s*$\n?", "", text, flags=re.MULTILINE)
        match = re.search(r"^\s*http_access\s+", text, re.MULTILINE)
        if match:
            return text[: match.start()] + wanted + "\n" + text[match.start() :]
        return text.rstrip() + "\n" + wanted + "\n"

    def _ensure_icap_include_if_needed(self, text: str) -> str:
        include_line = "include /etc/squid/conf.d/20-icap.conf"
        # Historical/manual configs may carry an inline copy of the managed ICAP
        # service definitions. That copy becomes stale as soon as the runtime
        # versions the adblock service name for a new artifact revision, so migrate
        # managed inline service plumbing back to the generated include instead of
        # preserving a dead static copy. Keep unrelated/manual ICAP policy alone.
        text = re.sub(
            r"^\s*include\s+/etc/squid/conf\.d/20-icap\.conf\s*$\n?",
            "",
            text,
            flags=re.MULTILINE,
        )
        managed_patterns = (
            r"^\s*icap_service\s+(?:adblock_req(?:_[A-Za-z0-9]+)?|av_resp)\b.*$\n?",
            r"^\s*adaptation_service_set\s+(?:adblock_req_set|av_resp_set)\b.*$\n?",
            r"^\s*adaptation_access\s+adblock_req_set\s+allow\s+all\s*$\n?",
        )
        for pattern in managed_patterns:
            text = re.sub(pattern, "", text, flags=re.MULTILINE)
        match = re.search(r"^\s*adaptation_access\s+", text, re.MULTILINE)
        if match:
            return text[: match.start()] + include_line + "\n" + text[match.start() :]
        return text.rstrip() + "\n" + include_line + "\n"

    def normalize_config_text(self, config_text: str) -> str:
        text = (config_text or "").strip()
        if not text:
            return ""

        text = re.sub(
            r"^\s*access_log\s+(?:stdio:)?/var/log/squid/access\.log\b.*$",
            "",
            text,
            flags=re.MULTILINE,
        )
        text = re.sub(
            r"^\s*(?:request|reply)_body_max_size\b.*$",
            "",
            text,
            flags=re.MULTILINE,
        )
        text = self._replace_or_append_directive(
            text,
            r"^\s*logformat\s+liveui\s+.*$",
            self._LIVEUI_LOGFORMAT,
        )
        text = self._replace_or_append_directive(
            text,
            r"^\s*logformat\s+diagnostic\s+.*$",
            self._DIAGNOSTIC_LOGFORMAT,
        )
        text = self._replace_or_append_directive(
            text,
            r"^\s*logformat\s+icapobserve\s+.*$",
            self._ICAP_OBSERVE_LOGFORMAT,
        )
        text = self._replace_or_append_directive(
            text,
            r"^\s*access_log\s+(?:stdio:)?/var/log/squid/access-observe\.log\b.*$",
            "access_log stdio:/var/log/squid/access-observe.log diagnostic",
        )
        text = self._replace_or_append_directive(
            text,
            r"^\s*cache_log\s+(?:stdio:)?/var/log/squid/cache\.log\b.*$",
            "cache_log stdio:/var/log/squid/cache.log",
        )
        text = self._replace_or_append_directive(
            text,
            r"^\s*icap_log\s+(?:stdio:)?/var/log/squid/icap\.log\b.*$",
            "icap_log stdio:/var/log/squid/icap.log icapobserve",
        )
        text = self._replace_or_append_directive(
            text,
            r"^\s*cache_store_log\s+.*$",
            "cache_store_log none",
        )
        text = self._ensure_icap_include_if_needed(text)
        text = self._ensure_line_before_first_http_access(
            text,
            "include /etc/squid/conf.d/30-webfilter.conf",
        )

        note_requirements = (
            (r"^\s*acl\s+steam_sites\b", "note ssl_exception steam steam_sites"),
            (r"^\s*acl\s+has_auth\b", "note cache_bypass auth has_auth"),
            (r"^\s*acl\s+has_cookie\b", "note cache_bypass cookie has_cookie"),
        )
        for acl_pattern, note_line in note_requirements:
            if re.search(acl_pattern, text, re.MULTILINE) and note_line not in text:
                text = text.rstrip() + "\n" + note_line + "\n"

        return text if text.endswith("\n") else text + "\n"

    def _icap_include_path(self) -> Path:
        return _cached_icap_include_path()

    def _virus_scan_config_path(self) -> Path:
        return _cached_virus_scan_config_path()

    def _snapshot_runtime_file(self, path: Path) -> str | None:
        try:
            return path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        except Exception:
            return None

    def _restore_runtime_file_snapshot(self, path: Path, content: str | None) -> None:
        try:
            if content is None:
                with contextlib.suppress(FileNotFoundError):
                    path.unlink()
                return
            self._atomic_write_file(str(path), content)
        except Exception:
            log_exception_throttled(
                logger,
                f"squid_core.restore_runtime_file.{path}",
                interval_seconds=300.0,
                message=f"Failed to restore {path}",
            )

    def _write_if_changed(self, path: Path, content: str) -> bool:
        try:
            if path.exists() and path.read_text(encoding="utf-8") == content:
                return False
        except Exception:
            pass
        self._atomic_write_file(str(path), content)
        return True

    def set_adblock_icap_revision_token(self, token: object) -> None:
        raw = re.sub(r"[^A-Za-z0-9_.-]", "", str(token or ""))[:32]
        self._adblock_icap_revision_token = raw

    def _render_icap_include(self, config_text: str | None = None) -> str:
        try:
            cicap_adblock_port = int((os.environ.get("CICAP_PORT") or "14000").strip())
        except Exception:
            cicap_adblock_port = 14000
        try:
            cicap_av_port = int((os.environ.get("CICAP_AV_PORT") or "14001").strip())
        except Exception:
            cicap_av_port = 14001

        clamav_options = extract_clamav_options(config_text or "")
        av_bypass = "on" if clamav_fail_open(clamav_options) else "off"
        file_security_policy = render_file_security_policy_config(
            clamav_options,
        ).strip()
        # Version the Squid ICAP service name with the active artifact while
        # keeping the c-icap service URI stable. Squid tracks ICAP service health
        # and persistent connections by service object; changing the local service
        # name after a c-icap artifact reload prevents stale bypass/broken-service
        # state without sending c-icap an unsupported query-string service path.
        adblock_service_name = "adblock_req"
        adblock_token = (self._adblock_icap_revision_token or "").strip()
        if adblock_token:
            adblock_service_name = f"adblock_req_{adblock_token}"
        adblock_dir = (
            os.environ.get("ADBLOCK_COMPILED_DIR")
            or "/var/lib/squid-flask-proxy/adblock/compiled"
        ).strip() or "/var/lib/squid-flask-proxy/adblock/compiled"
        regex_allow_path = os.path.join(adblock_dir, "regex_allow_squid.txt")
        regex_block_path = os.path.join(adblock_dir, "regex_block_squid.txt")
        regex_allow_has_rules = _file_has_non_comment_lines(regex_allow_path)
        regex_block_has_rules = _file_has_non_comment_lines(regex_block_path)
        lines = [
            f"icap_service {adblock_service_name} reqmod_precache icap://127.0.0.1:{cicap_adblock_port}/adblockreq bypass=on",
            f"icap_service av_req reqmod_precache icap://127.0.0.1:{cicap_av_port}/avrespmod bypass={av_bypass}",
            f"icap_service av_resp respmod_precache icap://127.0.0.1:{cicap_av_port}/avrespmod bypass={av_bypass}",
            f"adaptation_service_set adblock_req_set {adblock_service_name}",
            "adaptation_service_set av_req_set av_req",
            "adaptation_service_set av_resp_set av_resp",
            "acl icap_adblockable method GET HEAD",
            "adaptation_access adblock_req_set allow icap_adblockable",
            "adaptation_access adblock_req_set deny all",
        ]
        if regex_block_has_rules:
            if regex_allow_has_rules:
                lines.append(f'acl adblock_regex_allow url_regex -i "{regex_allow_path}"')
            lines.extend(
                [
                    f'acl adblock_regex_block url_regex -i "{regex_block_path}"',
                    "deny_info ERR_ACCESS_DENIED adblock_regex_block",
                    (
                        "http_access deny adblock_regex_block !adblock_regex_allow"
                        if regex_allow_has_rules
                        else "http_access deny adblock_regex_block"
                    ),
                ],
            )
        if file_security_policy:
            lines.extend(["", file_security_policy])
        return "\n".join(lines) + "\n"

    def _generate_icap_include(
        self,
        workers: int,
        config_text: str | None = None,
    ) -> None:
        out_path = self._icap_include_path()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        self._write_if_changed(out_path, self._render_icap_include(config_text))

    def materialize_clamav_runtime_files(self, config_text: str) -> tuple[bool, str]:
        try:
            normalized = self.normalize_config_text(config_text or "")
            options = extract_clamav_options(normalized)
            policy_mode = "bypassed" if clamav_fail_open(options) else "blocked"
            logger.info(
                "ClamAV file policy applied: preset=%s fail-%s scan_downloads=%s scan_uploads=%s risky_extensions=%s archive_block=%s nested_archives=%s quarantine_metadata=%s size_caps=%s/%s",
                options.get("file_security_preset"),
                "open" if clamav_fail_open(options) else "closed",
                options.get("file_security_scan_downloads"),
                options.get("file_security_scan_uploads"),
                options.get("file_security_block_risky_extensions"),
                options.get("file_security_block_archives"),
                options.get("file_security_block_nested_archives"),
                options.get("file_security_quarantine_metadata"),
                options.get("file_security_max_upload_size"),
                options.get("file_security_max_download_size"),
            )
            logger.info("AV unavailable, %s due to policy", policy_mode)
            virus_path = self._virus_scan_config_path()
            icap_path = self._icap_include_path()
            changed = []
            if self._write_if_changed(virus_path, render_virus_scan_config(options)):
                changed.append(str(virus_path))
            if self._write_if_changed(icap_path, self._render_icap_include(normalized)):
                changed.append(str(icap_path))
            if changed:
                return True, "ClamAV runtime files updated: " + ", ".join(changed)
            return True, "ClamAV runtime files already current."
        except Exception as exc:
            logger.exception("ClamAV runtime file materialization failed")
            return False, public_error_message(exc)

    def _supervisor_reread_update(self) -> tuple[bool, str]:
        try:
            reread = self._run(
                ["supervisorctl", "-c", "/etc/supervisord.conf", "reread"],
                capture_output=True,
                timeout=12,
            )
            if reread.returncode != 0:
                return False, self._decode_completed(
                    reread,
                ) or "supervisorctl reread failed"
            update = self._run(
                ["supervisorctl", "-c", "/etc/supervisord.conf", "update"],
                capture_output=True,
                timeout=20,
            )
            if update.returncode != 0:
                return False, self._decode_completed(
                    update,
                ) or "supervisorctl update failed"
            return True, (
                self._decode_completed(reread) + "\n" + self._decode_completed(update)
            ).strip()
        except Exception as exc:
            logger.exception("supervisorctl reread/update failed")
            return False, public_error_message(
                exc,
                default="supervisorctl failed. Check server logs for details.",
            )

    def apply_icap_scaling(
        self,
        workers: int,
        config_text: str | None = None,
    ) -> tuple[bool, str]:
        try:
            self._generate_icap_include(workers, config_text)
            return True, "ICAP include updated."
        except Exception as exc:
            logger.exception("ICAP scaling apply failed")
            return False, public_error_message(exc)

    def validate_config_text(self, config_text: str) -> tuple[bool, str]:
        normalized_config = self.normalize_config_text(config_text)
        tmp_path = ""
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                delete=False,
                prefix="squid-conf-",
                dir="/tmp",
            ) as handle:
                tmp_path = handle.name
                handle.write(normalized_config)

            proc = self._run(
                ["squid", "-k", "parse", "-f", tmp_path],
                capture_output=True,
                text=True,
                timeout=15,
            )
            combined = (
                (proc.stdout or "")
                + ("\n" if proc.stdout and proc.stderr else "")
                + (proc.stderr or "")
            )
            return proc.returncode == 0, combined.strip()
        except TimeoutExpired as exc:
            detail = f"Squid config validation timed out after {exc.timeout} seconds."
            logger.warning(detail)
            return False, detail
        except Exception as exc:
            logger.exception("Squid config validation failed")
            return False, public_error_message(exc)
        finally:
            if tmp_path:
                with contextlib.suppress(OSError):
                    Path(tmp_path).unlink()

    def _extract_workers(self, config_text: str) -> int | None:
        try:
            match = re.search(
                r"^\s*workers\s+(\d+)\s*$",
                config_text or "",
                re.MULTILINE | re.IGNORECASE,
            )
            return int(match.group(1)) if match else None
        except Exception:
            return None

    def _extract_cache_dir_lines(self, config_text: str) -> tuple[str, ...]:
        lines: list[str] = []
        for line in (config_text or "").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.lower().startswith("cache_dir "):
                lines.append(stripped)
        return tuple(lines)

    def _decode_completed(self, proc: Any) -> str:
        stdout = getattr(proc, "stdout", b"")
        stderr = getattr(proc, "stderr", b"")
        out_text = (
            stdout.decode("utf-8", errors="replace")
            if isinstance(stdout, bytes)
            else str(stdout or "")
        )
        err_text = (
            stderr.decode("utf-8", errors="replace")
            if isinstance(stderr, bytes)
            else str(stderr or "")
        )
        if out_text and err_text:
            return (out_text + "\n" + err_text).strip()
        return (out_text or err_text).strip()

    def _http_listener_details(
        self,
        config_text: str | None = None,
    ) -> tuple[dict[str, object], ...]:
        text = config_text if config_text is not None else self.get_current_config()
        listeners: list[dict[str, object]] = []
        pending: list[str] = []

        def flush_pending() -> None:
            if not pending:
                return
            logical = " ".join(
                line.rstrip().rstrip("\\").strip() for line in pending
            ).strip()
            pending.clear()
            if (
                not logical
                or logical.startswith("#")
                or not logical.lower().startswith("http_port ")
            ):
                return
            parts = logical.split()
            if len(parts) < 2:
                return
            token = parts[1]
            try:
                if token.isdigit():
                    port = int(token)
                elif (token.startswith("[") and "]:" in token) or ":" in token:
                    port = int(token.rsplit(":", 1)[1])
                else:
                    return
            except Exception:
                return
            if not (1 <= port <= 65535):
                return
            modes = {part.strip().lower() for part in parts[2:]}
            if "intercept" in modes:
                mode = "intercept"
            elif "tproxy" in modes:
                mode = "tproxy"
            else:
                mode = "explicit"
            if not any(int(item.get("port") or 0) == port for item in listeners):
                listeners.append({"port": port, "mode": mode})

        for line in (text or "").splitlines():
            pending.append(line)
            if line.rstrip().endswith("\\"):
                continue
            flush_pending()
        flush_pending()
        return tuple(listeners or [{"port": 3128, "mode": "explicit"}])

    def _http_listener_ports(self, config_text: str | None = None) -> tuple[int, ...]:
        return tuple(
            int(item.get("port") or 3128)
            for item in self._http_listener_details(config_text)
        )

    def _http_listener_port(self, config_text: str | None = None) -> int:
        return self._http_listener_ports(config_text)[0]

    def _tcp_listener_accepts(self, port: int) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", int(port)), timeout=0.5):
                return True
        except OSError:
            return False

    def _wait_for_http_listener(self, *, timeout: float = 20.0) -> bool:
        pending = set(self._http_listener_ports())
        deadline = time.time() + max(0.5, timeout)
        while pending and time.time() < deadline:
            for port in tuple(pending):
                if self._tcp_listener_accepts(port):
                    pending.discard(port)
            if pending:
                time.sleep(0.5)
        return not pending

    def _wait_for_http_listener_absent(self, *, timeout: float = 20.0) -> bool:
        ports = self._http_listener_ports()
        deadline = time.time() + max(0.5, timeout)
        while time.time() < deadline:
            if not any(self._tcp_listener_accepts(port) for port in ports):
                return True
            time.sleep(0.5)
        return False

    def _listening_socket_inodes_for_ports(self, ports: tuple[int, ...]) -> set[str]:
        target_ports = {int(port) for port in ports if int(port) > 0}
        inodes: set[str] = set()
        for table_path in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                with Path(table_path).open(
                    encoding="utf-8",
                    errors="replace",
                ) as handle:
                    next(handle, None)
                    for line in handle:
                        parts = line.split()
                        if len(parts) < 10 or parts[3] != "0A":
                            continue
                        try:
                            _addr, port_hex = parts[1].rsplit(":", 1)
                            port = int(port_hex, 16)
                        except Exception:
                            continue
                        if port in target_ports:
                            inode = parts[9]
                            if inode and inode != "0":
                                inodes.add(inode)
            except FileNotFoundError:
                continue
            except Exception:
                log_exception_throttled(
                    logger,
                    "squid_core.inspect_listeners",
                    interval_seconds=300.0,
                    message=f"Failed to inspect {table_path} for Squid listener sockets",
                )
        return inodes

    def _pids_with_socket_inodes(self, inodes: set[str]) -> set[int]:
        if not inodes:
            return set()
        pids: set[int] = set()
        proc_root = Path("/proc")
        try:
            entries = list(proc_root.iterdir())
        except Exception:
            return set()
        for entry in entries:
            if not entry.name.isdigit():
                continue
            try:
                pid = int(entry.name)
            except Exception:
                continue
            if pid == os.getpid():
                continue
            fd_dir = entry / "fd"
            try:
                for fd in fd_dir.iterdir():
                    try:
                        target = Path(fd).readlink()
                    except Exception:
                        continue
                    if (
                        target.startswith("socket:[")
                        and target.endswith("]")
                        and target[8:-1] in inodes
                    ):
                        pids.add(pid)
                        break
            except Exception:
                continue
        return pids

    def _pid_looks_like_squid(self, pid: int) -> bool:
        try:
            comm = (
                Path(f"/proc/{pid}/comm")
                .read_text(encoding="utf-8", errors="replace")
                .strip()
                .lower()
            )
            if "squid" in comm:
                return True
        except Exception:
            pass
        try:
            cmdline = (
                Path(f"/proc/{pid}/cmdline")
                .read_text(encoding="utf-8", errors="replace")
                .replace("\x00", " ")
                .lower()
            )
            return "squid" in cmdline
        except Exception:
            return False

    def _terminate_orphaned_http_listener_processes(
        self,
        *,
        timeout: float = 8.0,
    ) -> str:
        ports = self._http_listener_ports()
        inodes = self._listening_socket_inodes_for_ports(ports)
        pids = {
            pid
            for pid in self._pids_with_socket_inodes(inodes)
            if self._pid_looks_like_squid(pid)
        }
        if not pids:
            return "No orphaned Squid listener processes were found."

        detail_parts = [
            f"Terminating orphaned Squid listener process(es): {', '.join(str(pid) for pid in sorted(pids))}.",
        ]
        for sig in (signal.SIGTERM, signal.SIGKILL):
            for pid in sorted(pids):
                try:
                    os.kill(pid, sig)
                except ProcessLookupError:
                    pass
                except Exception as exc:
                    detail_parts.append(
                        f"Failed to send {sig.name} to PID {pid}: {exc}",
                    )
            deadline = time.time() + max(0.5, timeout / 2)
            while time.time() < deadline:
                if self._wait_for_http_listener_absent(timeout=0.5):
                    detail_parts.append(
                        "Squid HTTP listener sockets released after orphan cleanup.",
                    )
                    return "\n".join(part for part in detail_parts if part)
                time.sleep(0.2)
        return "\n".join(part for part in detail_parts if part)

    def _remove_stale_squid_pidfile(self) -> str:
        pid_path = "/var/run/squid.pid"
        try:
            if not os.path.exists(pid_path):  # noqa: PTH110
                return ""
            raw = Path(pid_path).read_text(encoding="utf-8", errors="replace").strip()
            pid = int(raw or "0")
            if pid > 0 and Path(f"/proc/{pid}").exists():
                try:
                    comm = (
                        Path(f"/proc/{pid}/comm")
                        .read_text(encoding="utf-8", errors="replace")
                        .strip()
                        .lower()
                    )
                    if "squid" in comm:
                        return ""
                except Exception:
                    return ""
            os.unlink(pid_path)  # noqa: PTH108
            return f"Removed stale Squid PID file {pid_path}."
        except Exception as exc:
            return f"Failed to remove stale Squid PID file: {exc}"

    def _wait_for_squid_pidfile_stale_or_absent(self, *, timeout: float = 10.0) -> bool:
        pid_path = "/var/run/squid.pid"
        deadline = time.time() + max(0.5, timeout)
        while time.time() < deadline:
            try:
                if not Path(pid_path).exists():
                    return True
                raw = (
                    Path(pid_path).read_text(encoding="utf-8", errors="replace").strip()
                )
                pid = int(raw or "0")
                if pid <= 0 or not Path(f"/proc/{pid}").exists():
                    return True
                try:
                    comm = (
                        Path(f"/proc/{pid}/comm")
                        .read_text(encoding="utf-8", errors="replace")
                        .strip()
                        .lower()
                    )
                    if "squid" not in comm:
                        return True
                except Exception:
                    return False
            except Exception:
                return False
            time.sleep(0.5)
        return False

    def _supervisor_program_running(self, program_name: str) -> bool:
        try:
            proc = self._run(
                [
                    "supervisorctl",
                    "-c",
                    "/etc/supervisord.conf",
                    "status",
                    program_name,
                ],
                capture_output=True,
                timeout=8,
            )
            detail = self._decode_completed(proc)
            return proc.returncode == 0 and "RUNNING" in detail.upper()
        except Exception:
            return False

    def _accept_running_squid_restart(
        self,
        detail_parts: list[str],
        *,
        timeout: float = 20.0,
    ) -> tuple[bool, str] | None:
        """Accept supervisor auto-restart races only after Squid is serving again."""
        if self._supervisor_program_running("squid") and self._wait_for_http_listener(
            timeout=timeout,
        ):
            detail_parts.append(
                "Squid was already restarted by supervisor and its HTTP listener is accepting connections.",
            )
            return True, "\n".join(part for part in detail_parts if part).strip()
        return None

    def restart_squid(self) -> tuple[bool, str]:
        detail_parts: list[str] = []
        try:
            stop = self._run(
                ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "squid"],
                capture_output=True,
                timeout=25,
            )
            detail_parts.append(
                self._decode_completed(stop) or "supervisorctl stop squid",
            )
        except Exception as exc:
            detail_parts.append(f"supervisorctl stop squid failed: {exc}")

        if not self._wait_for_http_listener_absent(timeout=30.0):
            detail_parts.append(
                "Squid HTTP listener stayed bound after supervisor stop; requesting Squid shutdown fallback.",
            )
            try:
                shutdown = self._run(
                    ["squid", "-k", "shutdown"],
                    capture_output=True,
                    timeout=12,
                )
                detail_parts.append(
                    self._decode_completed(shutdown) or "squid shutdown requested",
                )
            except Exception as exc:
                detail_parts.append(f"squid shutdown fallback failed: {exc}")
            if not self._wait_for_http_listener_absent(timeout=10.0):
                detail_parts.append(
                    self._terminate_orphaned_http_listener_processes(timeout=8.0),
                )
            if not self._wait_for_http_listener_absent(timeout=30.0):
                return False, "\n".join(
                    part
                    for part in [
                        *detail_parts,
                        "Squid HTTP listener did not release before restart.",
                    ]
                    if part
                ).strip()

        stale_pid_detail = self._remove_stale_squid_pidfile()
        if stale_pid_detail:
            detail_parts.append(stale_pid_detail)

        accepted = self._accept_running_squid_restart(detail_parts, timeout=10.0)
        if accepted is not None:
            return accepted

        if not self._wait_for_squid_pidfile_stale_or_absent(timeout=10.0):
            accepted = self._accept_running_squid_restart(detail_parts, timeout=10.0)
            if accepted is not None:
                return accepted
            detail_parts.append(
                "Squid PID file still points to a live process after stop; requesting Squid shutdown fallback.",
            )
            try:
                shutdown = self._run(
                    ["squid", "-k", "shutdown"],
                    capture_output=True,
                    timeout=12,
                )
                detail_parts.append(
                    self._decode_completed(shutdown)
                    or "squid shutdown requested after live PID file remained",
                )
            except Exception as exc:
                detail_parts.append(
                    f"squid shutdown fallback after live PID file failed: {exc}",
                )
            self._wait_for_http_listener_absent(timeout=20.0)
            self._wait_for_squid_pidfile_stale_or_absent(timeout=10.0)
            retry_stale = self._remove_stale_squid_pidfile()
            if retry_stale:
                detail_parts.append(retry_stale)

        try:
            start = self._run(
                ["supervisorctl", "-c", "/etc/supervisord.conf", "start", "squid"],
                capture_output=True,
                timeout=25,
            )
            start_detail = self._decode_completed(start) or "supervisorctl start squid"
            detail_parts.append(start_detail)
            start_detail_lower = start_detail.lower()
            if start.returncode != 0 and "already started" not in start_detail_lower:
                accepted = self._accept_running_squid_restart(
                    detail_parts,
                    timeout=20.0,
                )
                if accepted is not None:
                    return accepted
                if "already running" in start_detail_lower:
                    if self._wait_for_http_listener(timeout=15.0):
                        detail_parts.append(
                            "Squid was already running and its HTTP listener is accepting connections.",
                        )
                        return True, "\n".join(
                            part for part in detail_parts if part
                        ).strip()
                    try:
                        shutdown = self._run(
                            ["squid", "-k", "shutdown"],
                            capture_output=True,
                            timeout=12,
                        )
                        detail_parts.append(
                            self._decode_completed(shutdown)
                            or "squid shutdown requested after already-running start failure",
                        )
                        self._wait_for_http_listener_absent(timeout=20.0)
                        self._wait_for_squid_pidfile_stale_or_absent(timeout=10.0)
                        retry_stale = self._remove_stale_squid_pidfile()
                        if retry_stale:
                            detail_parts.append(retry_stale)
                        retry = self._run(
                            [
                                "supervisorctl",
                                "-c",
                                "/etc/supervisord.conf",
                                "start",
                                "squid",
                            ],
                            capture_output=True,
                            timeout=25,
                        )
                        retry_detail = (
                            self._decode_completed(retry)
                            or "supervisorctl start squid retry"
                        )
                        detail_parts.append(retry_detail)
                        if retry.returncode == 0 and self._wait_for_http_listener(
                            timeout=45.0,
                        ):
                            detail_parts.append(
                                "Squid HTTP listener is accepting connections.",
                            )
                            return True, "\n".join(
                                part for part in detail_parts if part
                            ).strip()
                    except Exception as exc:
                        detail_parts.append(
                            f"retry after already-running start failure failed: {exc}",
                        )
                return False, "\n".join(detail_parts).strip()
            if self._wait_for_http_listener(timeout=45.0):
                detail_parts.append("Squid HTTP listener is accepting connections.")
                return True, "\n".join(part for part in detail_parts if part).strip()
            return False, "\n".join(
                part
                for part in [
                    *detail_parts,
                    "Squid process started but the HTTP listener is not accepting connections.",
                ]
                if part
            ).strip()
        except FileNotFoundError:
            pass
        except Exception as exc:
            detail_parts.append(f"supervisorctl start squid failed: {exc}")

        try:
            proc = self._run(
                ["squid", "-f", self.squid_conf_path],
                capture_output=True,
                timeout=20,
            )
            detail_parts.append(self._decode_completed(proc) or "squid start requested")
            if proc.returncode == 0 and self._wait_for_http_listener(timeout=45.0):
                return True, "\n".join(part for part in detail_parts if part).strip()
            return False, "\n".join(
                [
                    *detail_parts,
                    "Squid direct start failed or listener stayed unavailable.",
                ],
            ).strip()
        except Exception as exc:
            return False, "\n".join([*detail_parts, str(exc)]).strip()

    def _get_first_cache_dir_path(self, config_text: str | None = None) -> str:
        text = config_text if config_text is not None else self.get_current_config()
        try:
            match = re.search(
                r"^\s*cache_dir\s+\w+\s+(\S+)\b",
                text or "",
                re.MULTILINE | re.IGNORECASE,
            )
            if match:
                return (match.group(1) or "").strip()
        except Exception:
            log_exception_throttled(
                logger,
                "squid_core.parse_cache_dir",
                interval_seconds=300.0,
                message="Failed to parse cache_dir from squid config; using default",
            )
        return "/var/spool/squid"

    def clear_disk_cache(self) -> tuple[bool, str]:
        cache_path = self._get_first_cache_dir_path()
        if not cache_path.startswith("/") or cache_path in {
            "/",
            "/etc",
            "/bin",
            "/usr",
            "/var",
        }:
            return False, f"Refusing to clear cache_dir at unsafe path: {cache_path}"

        detail_parts: list[str] = []
        try:
            stop = self._run(
                ["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "squid"],
                capture_output=True,
                timeout=20,
            )
            detail_parts.append(
                self._decode_completed(stop) or "supervisorctl stop squid",
            )
            if not self._wait_for_http_listener_absent(timeout=30.0):
                detail_parts.append(
                    "Squid HTTP listener stayed bound after stop; requesting shutdown fallback.",
                )
                self._run(["squid", "-k", "shutdown"], capture_output=True, timeout=10)
                self._wait_for_http_listener_absent(timeout=30.0)
        except Exception as exc:
            detail_parts.append(f"stop failed: {exc}")
            try:
                self._run(["squid", "-k", "shutdown"], capture_output=True, timeout=10)
                self._wait_for_http_listener_absent(timeout=30.0)
            except Exception:
                log_exception_throttled(
                    logger,
                    "squid_core.shutdown_fallback",
                    interval_seconds=300.0,
                    message="Squid shutdown fallback failed while clearing disk cache",
                )

        try:
            if Path(cache_path).is_dir():
                for name in os.listdir(cache_path):
                    candidate = os.path.join(cache_path, name)
                    try:
                        if (
                            Path(candidate).is_dir()
                            and not Path(candidate).is_symlink()
                        ):
                            shutil.rmtree(candidate, ignore_errors=True)
                        else:
                            Path(candidate).unlink()
                    except IsADirectoryError:
                        shutil.rmtree(candidate, ignore_errors=True)
                    except FileNotFoundError:
                        pass
            else:
                Path(cache_path).mkdir(exist_ok=True, parents=True)
            detail_parts.append(f"cleared: {cache_path}")
        except Exception as exc:
            prefix = "\n".join(detail_parts) + "\n" if detail_parts else ""
            return False, prefix + f"cache delete failed: {exc}"

        try:
            prepare = self._run(
                ["squid", "-z", "-f", self.squid_conf_path],
                capture_output=True,
                timeout=90,
            )
            if prepare.returncode != 0:
                detail_parts.append(
                    self._decode_completed(prepare) or "squid -z failed",
                )
            else:
                detail_parts.append(self._decode_completed(prepare) or "squid -z OK")
            if self._wait_for_squid_pidfile_stale_or_absent(timeout=10.0):
                stale_pid_detail = self._remove_stale_squid_pidfile()
                if stale_pid_detail:
                    detail_parts.append(stale_pid_detail)
        except Exception as exc:
            detail_parts.append(f"squid -z error: {exc}")

        ok_restart, restart_detail = self.restart_squid()
        detail_parts.append(
            restart_detail
            or ("Squid restarted." if ok_restart else "Squid restart failed."),
        )
        return ok_restart, "\n".join(part for part in detail_parts if part).strip()

    def apply_config_text(self, config_text: str) -> tuple[bool, str]:
        normalized_config = self.normalize_config_text(config_text)
        ok, details = self.validate_config_text(normalized_config)
        if not ok:
            return False, details or "Squid config validation failed."

        backup_path = self.squid_conf_path + ".bak"
        new_path = self.squid_conf_path + ".new"
        try:
            current = self.get_current_config()
            old_workers = self._extract_workers(current)
            new_workers = self._extract_workers(normalized_config)
            workers_changed = new_workers is not None and new_workers != old_workers
            old_cache_dirs = self._extract_cache_dir_lines(current)
            new_cache_dirs = self._extract_cache_dir_lines(normalized_config)
            cache_dirs_changed = new_cache_dirs != old_cache_dirs

            icap_include_path = self._icap_include_path()
            virus_scan_config_path = self._virus_scan_config_path()
            old_icap_include = self._snapshot_runtime_file(icap_include_path)
            old_virus_scan_config = self._snapshot_runtime_file(virus_scan_config_path)
            old_icap_supervisor = None
            if workers_changed and new_workers is not None:
                try:
                    old_icap_supervisor = Path("/etc/supervisor.d/icap.conf").read_text(
                        encoding="utf-8",
                    )
                except Exception:
                    old_icap_supervisor = None

            self._write_file(new_path, normalized_config)
            if current:
                self._write_file(backup_path, current)
            Path(new_path).replace(self.squid_conf_path)

            ok_runtime, runtime_details = self.materialize_clamav_runtime_files(
                normalized_config,
            )
            if not ok_runtime:
                if Path(backup_path).exists():
                    Path(backup_path).replace(self.squid_conf_path)
                self._restore_runtime_file_snapshot(icap_include_path, old_icap_include)
                self._restore_runtime_file_snapshot(
                    virus_scan_config_path,
                    old_virus_scan_config,
                )
                _rollback_ok, rollback_detail = self.restore_last_known_good_config(
                    reason=runtime_details
                    or "Failed to materialize ClamAV runtime files.",
                    fallback_config=current,
                )
                return False, rollback_detail or (
                    runtime_details or "Failed to materialize ClamAV runtime files."
                )

            if workers_changed:
                ok_scale, scale_details = self.apply_icap_scaling(
                    new_workers or 1,
                    config_text=normalized_config,
                )
                if not ok_scale:
                    if Path(backup_path).exists():
                        Path(backup_path).replace(self.squid_conf_path)
                    try:
                        self._restore_runtime_file_snapshot(
                            icap_include_path,
                            old_icap_include,
                        )
                        self._restore_runtime_file_snapshot(
                            virus_scan_config_path,
                            old_virus_scan_config,
                        )
                    except Exception:
                        log_exception_throttled(
                            logger,
                            "squid_core.revert_icap_include",
                            interval_seconds=300.0,
                            message="Failed to revert /etc/squid/conf.d/20-icap.conf",
                        )
                    try:
                        if old_icap_supervisor is not None:
                            Path("/etc/supervisor.d/icap.conf").write_text(
                                old_icap_supervisor,
                                encoding="utf-8",
                            )
                    except Exception:
                        log_exception_throttled(
                            logger,
                            "squid_core.revert_icap_supervisor",
                            interval_seconds=300.0,
                            message="Failed to revert /etc/supervisor.d/icap.conf",
                        )
                    self._supervisor_reread_update()
                    _rollback_ok, rollback_detail = self.restore_last_known_good_config(
                        reason=scale_details or "Failed to scale ICAP processes.",
                        fallback_config=current,
                    )
                    return False, rollback_detail or (
                        scale_details or "Failed to scale ICAP processes."
                    )

                ok_restart, restart_details = self.clear_disk_cache()
                if not ok_restart:
                    if Path(backup_path).exists():
                        Path(backup_path).replace(self.squid_conf_path)
                        try:
                            self._restore_runtime_file_snapshot(
                                icap_include_path,
                                old_icap_include,
                            )
                            self._restore_runtime_file_snapshot(
                                virus_scan_config_path,
                                old_virus_scan_config,
                            )
                        except Exception:
                            log_exception_throttled(
                                logger,
                                "squid_core.revert_icap_include.restart",
                                interval_seconds=300.0,
                                message="Failed to revert /etc/squid/conf.d/20-icap.conf after restart failure",
                            )
                        try:
                            if old_icap_supervisor is not None:
                                Path("/etc/supervisor.d/icap.conf").write_text(
                                    old_icap_supervisor,
                                    encoding="utf-8",
                                )
                        except Exception:
                            log_exception_throttled(
                                logger,
                                "squid_core.revert_icap_supervisor.restart",
                                interval_seconds=300.0,
                                message="Failed to revert /etc/supervisor.d/icap.conf after restart failure",
                            )
                        self._supervisor_reread_update()
                        _rollback_ok, rollback_detail = (
                            self.restore_last_known_good_config(
                                reason=restart_details
                                or "Squid restart failed after cache reinitialization.",
                                fallback_config=current,
                            )
                        )
                        return False, rollback_detail or (
                            restart_details
                            or "Squid restart failed after cache reinitialization."
                        )

                try:
                    self._persist_good_config(normalized_config)
                except Exception:
                    log_exception_throttled(
                        logger,
                        "squid_core.persist_config.workers",
                        interval_seconds=300.0,
                        message="Failed to persist squid config after workers change",
                    )

                message = (restart_details or "Squid restarted.").strip()
                if scale_details:
                    message = (message + "\n" + scale_details).strip()
                return True, message

            if cache_dirs_changed:
                ok_restart, restart_details = self.clear_disk_cache()
                if not ok_restart:
                    if Path(backup_path).exists():
                        Path(backup_path).replace(self.squid_conf_path)
                    self._restore_runtime_file_snapshot(
                        icap_include_path,
                        old_icap_include,
                    )
                    self._restore_runtime_file_snapshot(
                        virus_scan_config_path,
                        old_virus_scan_config,
                    )
                    _rollback_ok, rollback_detail = self.restore_last_known_good_config(
                        reason=restart_details
                        or "Squid restart failed after cache reinitialization.",
                        fallback_config=current,
                    )
                    return False, rollback_detail or (
                        restart_details
                        or "Squid restart failed after cache reinitialization."
                    )

                try:
                    self._persist_good_config(normalized_config)
                except Exception:
                    log_exception_throttled(
                        logger,
                        "squid_core.persist_config.cache_dir",
                        interval_seconds=300.0,
                        message="Failed to persist squid config after cache_dir change",
                    )

                return True, (
                    restart_details
                    or "Squid restarted after cache store reinitialization."
                ).strip()

            reconfigure = self._run(
                ["squid", "-k", "reconfigure"],
                capture_output=True,
                timeout=15,
            )
            if reconfigure.returncode != 0:
                if Path(backup_path).exists():
                    Path(backup_path).replace(self.squid_conf_path)
                self._restore_runtime_file_snapshot(icap_include_path, old_icap_include)
                self._restore_runtime_file_snapshot(
                    virus_scan_config_path,
                    old_virus_scan_config,
                )
                failure_detail = (
                    self._decode_completed(reconfigure) or "Squid reconfigure failed."
                )
                _rollback_ok, rollback_detail = self.restore_last_known_good_config(
                    reason=failure_detail,
                    fallback_config=current,
                )
                return False, rollback_detail or failure_detail

            reconfigure_detail = (
                self._decode_completed(reconfigure) or "Squid reconfigured."
            )
            if not self._wait_for_http_listener(timeout=20.0):
                ok_restart, restart_details = self.restart_squid()
                if not ok_restart:
                    if Path(backup_path).exists():
                        Path(backup_path).replace(self.squid_conf_path)
                    self._restore_runtime_file_snapshot(
                        icap_include_path,
                        old_icap_include,
                    )
                    self._restore_runtime_file_snapshot(
                        virus_scan_config_path,
                        old_virus_scan_config,
                    )
                    _rollback_ok, rollback_detail = self.restore_last_known_good_config(
                        reason=restart_details
                        or "Squid HTTP listener did not recover after reconfigure.",
                        fallback_config=current,
                    )
                    return False, rollback_detail or (
                        restart_details
                        or "Squid HTTP listener did not recover after reconfigure."
                    )
                reconfigure_detail = (
                    reconfigure_detail + "\n" + restart_details
                ).strip()

            try:
                self._persist_good_config(normalized_config)
            except Exception:
                log_exception_throttled(
                    logger,
                    "squid_core.persist_config",
                    interval_seconds=300.0,
                    message="Failed to persist squid config after reconfigure",
                )

            return True, reconfigure_detail
        except Exception as exc:
            logger.exception("Squid reconfigure failed")
            if isinstance(exc, TimeoutExpired):
                failure_detail = (
                    f"Squid reconfigure timed out after {exc.timeout} seconds."
                )
            else:
                failure_detail = public_error_message(exc)
            _rollback_ok, rollback_detail = self.restore_last_known_good_config(
                reason=failure_detail,
                fallback_config=locals().get("current", ""),
            )
            return False, rollback_detail or failure_detail
        finally:
            try:
                if Path(new_path).exists():
                    Path(new_path).unlink()
            except OSError:
                pass

    def reload_squid(self):
        try:
            proc = self._run(
                ["squid", "-k", "reconfigure"],
                capture_output=True,
                timeout=15,
            )
            stdout = proc.stdout or b""
            stderr = proc.stderr or b""
            if proc.returncode != 0:
                return (
                    stdout,
                    stderr
                    or f"Squid reconfigure exited with status {proc.returncode}.".encode(
                        "utf-8",
                        errors="replace",
                    ),
                )
            if stderr:
                # Squid emits benign parser/runtime warnings on stderr even when
                # reconfigure succeeds. Preserve those warnings in the detail, but
                # do not report a failed sync unless the command or listener failed.
                stdout = (stdout + b"\n" + stderr).strip()
                stderr = b""
            if not self._wait_for_http_listener(timeout=20.0):
                ok_restart, detail = self.restart_squid()
                recovery = (
                    "Squid HTTP listener was unavailable after reconfigure; " + detail
                ).encode("utf-8", errors="replace")
                if ok_restart:
                    stdout = (stdout + b"\n" + recovery).strip()
                else:
                    stderr = (stderr + b"\n" + recovery).strip()
            return stdout, stderr
        except FileNotFoundError:
            return b"", b"squid binary not found"
        except Exception as exc:
            return b"", str(exc).encode("utf-8", errors="replace")

    def get_status(self):
        try:
            proc = self._run(["squid", "-k", "check"], capture_output=True, timeout=15)
            stdout = proc.stdout or b""
            stderr = proc.stderr or b""
            if proc.returncode == 0:
                if stdout:
                    return stdout, b""
                return b"Squid check ok.", b""
            if proc.returncode != 0 and not stderr:
                stderr = stdout or f"squid check failed rc={proc.returncode}".encode()
            return stdout, stderr
        except FileNotFoundError:
            return b"", b"squid binary not found"
        except Exception as exc:
            return b"", str(exc).encode("utf-8", errors="replace")

    def get_current_config(self):
        if Path(self.squid_conf_path).exists():
            with Path(self.squid_conf_path).open(encoding="utf-8") as handle:
                return handle.read()
        return ""
