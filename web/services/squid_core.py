from __future__ import annotations

import os
import re
import shutil
import tempfile
from pathlib import Path
from subprocess import run
from typing import Any, Callable, Optional, Tuple

import logging

from services.errors import public_error_message
from services.logutil import log_exception_throttled


logger = logging.getLogger(__name__)
CommandRunner = Callable[..., Any]


class SquidController:
    def __init__(self, squid_conf_path: str = "/etc/squid/squid.conf", *, cmd_run: CommandRunner = run):
        self.squid_conf_path = squid_conf_path
        self.persisted_squid_conf_path = os.environ.get(
            "PERSISTED_SQUID_CONF_PATH", "/var/lib/squid-flask-proxy/squid.conf"
        )
        self._run = cmd_run

    def _write_file(self, path: str, content: str) -> None:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)

    def _atomic_write_file(self, path: str, content: str) -> None:
        directory = os.path.dirname(path) or "."
        os.makedirs(directory, exist_ok=True)
        tmp_path = ""
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False, dir=directory, prefix=".tmp-") as handle:
                tmp_path = handle.name
                handle.write(content)
            os.replace(tmp_path, path)
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass

    def _render_icap_include(self) -> str:
        try:
            cicap_adblock_port = int((os.environ.get("CICAP_PORT") or "14000").strip())
        except Exception:
            cicap_adblock_port = 14000
        try:
            cicap_av_port = int((os.environ.get("CICAP_AV_PORT") or "14001").strip())
        except Exception:
            cicap_av_port = 14001

        lines = [
            f"icap_service adblock_req reqmod_precache icap://127.0.0.1:{cicap_adblock_port}/adblockreq bypass=on",
            f"icap_service av_resp respmod_precache icap://127.0.0.1:{cicap_av_port}/avrespmod bypass=on",
            "adaptation_service_set adblock_req_set adblock_req",
            "adaptation_service_set av_resp_set av_resp",
            "acl icap_identity_methods method GET HEAD",
            "request_header_access Accept-Encoding deny icap_identity_methods",
            "request_header_add Accept-Encoding identity icap_identity_methods",
        ]
        return "\n".join(lines) + "\n"

    def _generate_icap_include(self, workers: int) -> None:
        conf_dir = Path("/etc/squid/conf.d")
        conf_dir.mkdir(parents=True, exist_ok=True)
        out_path = conf_dir / "20-icap.conf"
        out_path.write_text(self._render_icap_include(), encoding="utf-8")

    def _supervisor_reread_update(self) -> Tuple[bool, str]:
        try:
            reread = self._run(["supervisorctl", "-c", "/etc/supervisord.conf", "reread"], capture_output=True, timeout=12)
            if reread.returncode != 0:
                return False, self._decode_completed(reread) or "supervisorctl reread failed"
            update = self._run(["supervisorctl", "-c", "/etc/supervisord.conf", "update"], capture_output=True, timeout=20)
            if update.returncode != 0:
                return False, self._decode_completed(update) or "supervisorctl update failed"
            return True, (self._decode_completed(reread) + "\n" + self._decode_completed(update)).strip()
        except Exception as exc:
            logger.exception("supervisorctl reread/update failed")
            return False, public_error_message(exc, default="supervisorctl failed. Check server logs for details.")

    def apply_icap_scaling(self, workers: int) -> Tuple[bool, str]:
        try:
            self._generate_icap_include(workers)
            return True, "ICAP include updated."
        except Exception as exc:
            logger.exception("ICAP scaling apply failed")
            return False, public_error_message(exc)

    def validate_config_text(self, config_text: str) -> Tuple[bool, str]:
        tmp_path = ""
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False, prefix="squid-conf-", dir="/tmp") as handle:
                tmp_path = handle.name
                handle.write(config_text)

            proc = self._run(["squid", "-k", "parse", "-f", tmp_path], capture_output=True, text=True, timeout=15)
            combined = (proc.stdout or "") + ("\n" if proc.stdout and proc.stderr else "") + (proc.stderr or "")
            return proc.returncode == 0, combined.strip()
        except Exception as exc:
            logger.exception("Squid config validation failed")
            return False, public_error_message(exc)
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    def _extract_workers(self, config_text: str) -> Optional[int]:
        try:
            match = re.search(r"^\s*workers\s+(\d+)\s*$", config_text or "", re.M | re.I)
            return int(match.group(1)) if match else None
        except Exception:
            return None

    def _decode_completed(self, proc: Any) -> str:
        stdout = getattr(proc, "stdout", b"")
        stderr = getattr(proc, "stderr", b"")
        out_text = stdout.decode("utf-8", errors="replace") if isinstance(stdout, bytes) else str(stdout or "")
        err_text = stderr.decode("utf-8", errors="replace") if isinstance(stderr, bytes) else str(stderr or "")
        if out_text and err_text:
            return (out_text + "\n" + err_text).strip()
        return (out_text or err_text).strip()

    def restart_squid(self) -> Tuple[bool, str]:
        try:
            proc = self._run(["supervisorctl", "-c", "/etc/supervisord.conf", "restart", "squid"], capture_output=True, timeout=12)
            if proc.returncode == 0:
                return True, self._decode_completed(proc) or "Squid restarted."
            details = self._decode_completed(proc) or "supervisorctl restart squid failed"
        except Exception as exc:
            details = str(exc)

        try:
            shutdown = self._run(["squid", "-k", "shutdown"], capture_output=True, timeout=8)
            if shutdown.returncode == 0:
                return True, (details + "\n" if details else "") + (self._decode_completed(shutdown) or "Squid shutdown requested (supervisor will restart).")
            return False, (details + "\n" if details else "") + (self._decode_completed(shutdown) or "Squid shutdown request failed.")
        except Exception as exc:
            return False, (details + "\n" if details else "") + str(exc)

    def _get_first_cache_dir_path(self, config_text: Optional[str] = None) -> str:
        text = config_text if config_text is not None else self.get_current_config()
        try:
            match = re.search(r"^\s*cache_dir\s+ufs\s+(\S+)\s+\d+\s+\d+\s+\d+", text or "", re.M | re.I)
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

    def clear_disk_cache(self) -> Tuple[bool, str]:
        cache_path = self._get_first_cache_dir_path()
        if not cache_path.startswith("/") or cache_path in ("/", "/etc", "/bin", "/usr", "/var"):
            return False, f"Refusing to clear cache_dir at unsafe path: {cache_path}"

        detail_parts: list[str] = []
        try:
            stop = self._run(["supervisorctl", "-c", "/etc/supervisord.conf", "stop", "squid"], capture_output=True, timeout=20)
            detail_parts.append(self._decode_completed(stop) or "supervisorctl stop squid")
        except Exception as exc:
            detail_parts.append(f"stop failed: {exc}")
            try:
                self._run(["squid", "-k", "shutdown"], capture_output=True, timeout=10)
            except Exception:
                log_exception_throttled(
                    logger,
                    "squid_core.shutdown_fallback",
                    interval_seconds=300.0,
                    message="Squid shutdown fallback failed while clearing disk cache",
                )

        try:
            if os.path.isdir(cache_path):
                for name in os.listdir(cache_path):
                    candidate = os.path.join(cache_path, name)
                    try:
                        if os.path.isdir(candidate) and not os.path.islink(candidate):
                            shutil.rmtree(candidate, ignore_errors=True)
                        else:
                            os.unlink(candidate)
                    except IsADirectoryError:
                        shutil.rmtree(candidate, ignore_errors=True)
                    except FileNotFoundError:
                        pass
            else:
                os.makedirs(cache_path, exist_ok=True)
            detail_parts.append(f"cleared: {cache_path}")
        except Exception as exc:
            prefix = "\n".join(detail_parts) + "\n" if detail_parts else ""
            return False, prefix + f"cache delete failed: {exc}"

        try:
            prepare = self._run(["squid", "-z", "-f", self.squid_conf_path], capture_output=True, timeout=90)
            if prepare.returncode != 0:
                detail_parts.append(self._decode_completed(prepare) or "squid -z failed")
            else:
                detail_parts.append(self._decode_completed(prepare) or "squid -z OK")
        except Exception as exc:
            detail_parts.append(f"squid -z error: {exc}")

        ok_restart, restart_detail = self.restart_squid()
        detail_parts.append(restart_detail or ("Squid restarted." if ok_restart else "Squid restart failed."))
        return ok_restart, "\n".join(part for part in detail_parts if part).strip()

    def apply_config_text(self, config_text: str) -> Tuple[bool, str]:
        ok, details = self.validate_config_text(config_text)
        if not ok:
            return False, details or "Squid config validation failed."

        backup_path = self.squid_conf_path + ".bak"
        new_path = self.squid_conf_path + ".new"
        try:
            current = self.get_current_config()
            old_workers = self._extract_workers(current)
            new_workers = self._extract_workers(config_text)
            workers_changed = new_workers is not None and new_workers != old_workers

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
                            "squid_core.revert_icap_include",
                            interval_seconds=300.0,
                            message="Failed to revert /etc/squid/conf.d/20-icap.conf",
                        )
                    try:
                        if old_icap_supervisor is not None:
                            Path("/etc/supervisor.d/icap.conf").write_text(old_icap_supervisor, encoding="utf-8")
                    except Exception:
                        log_exception_throttled(
                            logger,
                            "squid_core.revert_icap_supervisor",
                            interval_seconds=300.0,
                            message="Failed to revert /etc/supervisor.d/icap.conf",
                        )
                    self._supervisor_reread_update()
                    self.restart_squid()
                    return False, scale_details or "Failed to scale ICAP processes."

                ok_restart, restart_details = self.clear_disk_cache()
                if not ok_restart:
                    if os.path.exists(backup_path):
                        os.replace(backup_path, self.squid_conf_path)
                        try:
                            if old_icap_include is not None:
                                Path("/etc/squid/conf.d/20-icap.conf").write_text(old_icap_include, encoding="utf-8")
                        except Exception:
                            log_exception_throttled(
                                logger,
                                "squid_core.revert_icap_include.restart",
                                interval_seconds=300.0,
                                message="Failed to revert /etc/squid/conf.d/20-icap.conf after restart failure",
                            )
                        try:
                            if old_icap_supervisor is not None:
                                Path("/etc/supervisor.d/icap.conf").write_text(old_icap_supervisor, encoding="utf-8")
                        except Exception:
                            log_exception_throttled(
                                logger,
                                "squid_core.revert_icap_supervisor.restart",
                                interval_seconds=300.0,
                                message="Failed to revert /etc/supervisor.d/icap.conf after restart failure",
                            )
                        self._supervisor_reread_update()
                        self.restart_squid()
                        return False, restart_details or "Squid restart failed after cache reinitialization."

                try:
                    persisted_dir = os.path.dirname(self.persisted_squid_conf_path)
                    if persisted_dir:
                        os.makedirs(persisted_dir, exist_ok=True)
                    self._atomic_write_file(self.persisted_squid_conf_path, config_text)
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

            reconfigure = self._run(["squid", "-k", "reconfigure"], capture_output=True, timeout=15)
            if reconfigure.returncode != 0:
                if os.path.exists(backup_path):
                    os.replace(backup_path, self.squid_conf_path)
                    self._run(["squid", "-k", "reconfigure"], capture_output=True, timeout=15)
                return False, self._decode_completed(reconfigure) or "Squid reconfigure failed."

            try:
                persisted_dir = os.path.dirname(self.persisted_squid_conf_path)
                if persisted_dir:
                    os.makedirs(persisted_dir, exist_ok=True)
                self._atomic_write_file(self.persisted_squid_conf_path, config_text)
            except Exception:
                log_exception_throttled(
                    logger,
                    "squid_core.persist_config",
                    interval_seconds=300.0,
                    message="Failed to persist squid config after reconfigure",
                )

            return True, self._decode_completed(reconfigure) or "Squid reconfigured."
        except Exception as exc:
            try:
                if os.path.exists(backup_path):
                    os.replace(backup_path, self.squid_conf_path)
                    self._run(["squid", "-k", "reconfigure"], capture_output=True, timeout=15)
            except Exception:
                log_exception_throttled(
                    logger,
                    "squid_core.revert_failed",
                    interval_seconds=300.0,
                    message="Squid config revert failed after reconfigure error",
                )
            logger.exception("Squid reconfigure failed")
            return False, public_error_message(exc)
        finally:
            try:
                if os.path.exists(new_path):
                    os.unlink(new_path)
            except OSError:
                pass

    def reload_squid(self):
        try:
            proc = self._run(["squid", "-k", "reconfigure"], capture_output=True, timeout=15)
            return proc.stdout or b"", proc.stderr or b""
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
                stderr = stdout or f"squid check failed rc={proc.returncode}".encode("utf-8")
            return stdout, stderr
        except FileNotFoundError:
            return b"", b"squid binary not found"
        except Exception as exc:
            return b"", str(exc).encode("utf-8", errors="replace")

    def get_current_config(self):
        if os.path.exists(self.squid_conf_path):
            with open(self.squid_conf_path, "r", encoding="utf-8") as handle:
                return handle.read()
        return ""
