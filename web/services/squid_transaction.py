from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import operator
import os
import shutil
import stat
import tempfile
import time
import uuid
from dataclasses import dataclass
from itertools import starmap
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterable

_SCHEMA_VERSION = 2
_MAX_JOURNAL_BYTES = 64 * 1024
_MAX_DETAIL_CHARS = 2000
_DIRTY_STATUSES = frozenset({"in_progress", "recovering", "recovery_required"})
_TERMINAL_STATUSES = frozenset({"complete", "recovered"})
_ALLOWED_STATUSES = _DIRTY_STATUSES | _TERMINAL_STATUSES


class SquidTransactionRecoveryRequiredError(RuntimeError):
    """Raised when a previous Squid mutation has not been reconciled."""


@dataclass(frozen=True)
class SquidJournalHealth:
    ready: bool
    status: str
    detail: str
    transaction_id: str = ""
    operation: str = ""
    phase: str = ""
    recovery_status: str = ""
    updated_at: str = ""
    recovery_source: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ready,
            "ready": self.ready,
            "status": self.status,
            "detail": self.detail,
            "transaction_id": self.transaction_id,
            "operation": self.operation,
            "phase": self.phase,
            "recovery_status": self.recovery_status,
            "updated_at": self.updated_at,
            "recovery_source": self.recovery_source,
        }


class SquidTransactionJournal:
    """Single-record durable, fail-closed journal for Squid mutations.

    The record contains hashes and bounded metadata only. Config text and other
    potentially sensitive file contents are never copied into the journal.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        active_config: str | Path,
        persisted_config: str | Path,
        runtime_paths: Iterable[str | Path] = (),
    ) -> None:
        self.path = Path(path)
        self.active_config = Path(active_config)
        self.persisted_config = Path(persisted_config)
        self.runtime_paths = tuple(dict.fromkeys(Path(item) for item in runtime_paths))
        if len(self.runtime_paths) > 128:
            msg = "Too many Squid runtime paths were supplied to the journal."
            raise ValueError(msg)

    def read(self) -> dict[str, Any] | None:
        try:
            file_stat = self.path.lstat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            msg = "Squid transaction journal metadata is unreadable."
            raise SquidTransactionRecoveryRequiredError(msg) from exc
        if stat.S_ISLNK(file_stat.st_mode) or not stat.S_ISREG(file_stat.st_mode):
            msg = "Squid transaction journal path is not a regular file."
            raise SquidTransactionRecoveryRequiredError(msg)
        if file_stat.st_size > _MAX_JOURNAL_BYTES:
            msg = "Squid transaction journal exceeds the bounded size limit."
            raise SquidTransactionRecoveryRequiredError(msg)
        try:
            with self.path.open("r", encoding="utf-8") as journal_file:
                raw = journal_file.read(_MAX_JOURNAL_BYTES + 1)
            payload = json.loads(raw)
        except (OSError, UnicodeError, ValueError, TypeError) as exc:
            msg = "Squid transaction journal is unreadable or corrupt."
            raise SquidTransactionRecoveryRequiredError(msg) from exc
        self._validate_payload(payload)
        return payload

    def health(self) -> SquidJournalHealth:
        try:
            payload = self.read()
        except SquidTransactionRecoveryRequiredError as exc:
            return SquidJournalHealth(
                ready=False,
                status="unreadable",
                detail=str(exc),
                recovery_status="required",
            )
        if payload is None:
            return SquidJournalHealth(
                ready=True,
                status="absent",
                detail="No Squid transaction is pending.",
            )
        status = str(payload["status"])
        ready = status in _TERMINAL_STATUSES
        detail = (
            "Squid transaction journal is reconciled."
            if ready
            else "Squid transaction reconciliation is required before mutations may proceed."
        )
        evidence = payload.get("evidence")
        recovery_source = ""
        if isinstance(evidence, dict):
            recovery_source = str(evidence.get("recovery_source") or "")[:128]
        return SquidJournalHealth(
            ready=ready,
            status=status,
            detail=detail,
            transaction_id=str(payload.get("transaction_id") or ""),
            operation=str(payload.get("operation") or ""),
            phase=str(payload.get("phase") or ""),
            recovery_status=str(payload.get("recovery_status") or ""),
            updated_at=str(payload.get("updated_at") or ""),
            recovery_source=recovery_source,
        )

    def assert_ready_for_mutation(self) -> None:
        health = self.health()
        if not health.ready:
            transaction = health.transaction_id or "unknown"
            msg = (
                f"Squid transaction journal is {health.status} ({transaction}); "
                "startup or designated rollback recovery is required."
            )
            raise SquidTransactionRecoveryRequiredError(msg)

    def begin(
        self,
        operation: str,
        *,
        intended_phase: str,
        target_config: str = "",
    ) -> dict[str, Any]:
        self.assert_ready_for_mutation()
        now = _utc_timestamp()
        payload: dict[str, Any] = {
            "schema_version": _SCHEMA_VERSION,
            "transaction_id": str(uuid.uuid4()),
            "operation": _bounded_token(operation, "unknown"),
            "status": "in_progress",
            "phase": "prepared",
            "intended_phase": _bounded_token(intended_phase, "complete"),
            "recovery_status": "not_required",
            "started_at": now,
            "updated_at": now,
            "target_config_sha256": _sha256_text(target_config),
            "state_before": self.state_manifest(),
        }
        self._write(payload)
        return payload

    def replace_active(self, payload: dict[str, Any]) -> None:
        """Install a bounded startup/recovery record after source restoration."""
        self._validate_payload(payload)
        if str(payload.get("status")) not in _DIRTY_STATUSES:
            msg = "Replacement journal record must be active."
            raise ValueError(msg)
        self._write(payload)

    def phase(self, phase: str, **evidence: Any) -> dict[str, Any]:
        payload = self._require_active()
        payload["phase"] = _bounded_token(phase, "unknown")
        payload["updated_at"] = _utc_timestamp()
        if evidence:
            safe_evidence = payload.setdefault("evidence", {})
            if not isinstance(safe_evidence, dict):
                safe_evidence = {}
                payload["evidence"] = safe_evidence
            for key, value in evidence.items():
                if len(safe_evidence) >= 32 and key not in safe_evidence:
                    break
                safe_evidence[_bounded_token(key, "evidence")] = _bounded_scalar(value)
        payload["state_current"] = self.state_manifest()
        self._write(payload)
        return payload

    def complete(self, *, detail: str = "", recovered: bool = False) -> None:
        payload = self._require_active()
        now = _utc_timestamp()
        payload.update(
            {
                "status": "recovered" if recovered else "complete",
                "phase": "complete",
                "intended_phase": "complete",
                "recovery_status": "restored" if recovered else "not_required",
                "updated_at": now,
                "completed_at": now,
                "detail": _bounded_detail(detail),
                "state_after": self.state_manifest(),
            }
        )
        self._write(payload)

    def recovery_required(
        self, detail: str, *, phase: str = "recovery_required"
    ) -> None:
        try:
            payload = self._require_active()
        except SquidTransactionRecoveryRequiredError:
            now = _utc_timestamp()
            payload = {
                "schema_version": _SCHEMA_VERSION,
                "transaction_id": str(uuid.uuid4()),
                "operation": "unknown",
                "status": "recovery_required",
                "phase": "recovery_required",
                "intended_phase": "complete",
                "recovery_status": "required",
                "started_at": now,
                "updated_at": now,
            }
        payload.update(
            {
                "status": "recovery_required",
                "phase": _bounded_token(phase, "recovery_required"),
                "recovery_status": "required",
                "updated_at": _utc_timestamp(),
                "detail": _bounded_detail(
                    detail or "Squid transaction recovery is required."
                ),
                "state_current": self.state_manifest(),
            }
        )
        self._write(payload)

    def state_manifest(self) -> dict[str, Any]:
        paths: list[tuple[str, Path]] = [
            ("active_config", self.active_config),
            ("persisted_last_known_good", self.persisted_config),
        ]
        paths.extend(("runtime_fragment", path) for path in self.runtime_paths)
        files = list(starmap(_file_evidence, paths))
        digest = hashlib.sha256()
        for item in sorted(files, key=operator.itemgetter("role", "path")):
            digest.update(json.dumps(item, sort_keys=True).encode("utf-8"))
            digest.update(b"\n")
        return {"manifest_sha256": digest.hexdigest(), "files": files}

    def _require_active(self) -> dict[str, Any]:
        payload = self.read()
        if not payload or str(payload.get("status") or "") not in _DIRTY_STATUSES:
            msg = "No active Squid transaction journal is available."
            raise SquidTransactionRecoveryRequiredError(msg)
        return payload

    def _validate_payload(self, payload: Any) -> None:
        if (
            not isinstance(payload, dict)
            or payload.get("schema_version") != _SCHEMA_VERSION
        ):
            msg = "Squid transaction journal has an unsupported format."
            raise SquidTransactionRecoveryRequiredError(msg)
        required_strings = (
            "transaction_id",
            "operation",
            "status",
            "phase",
            "intended_phase",
            "recovery_status",
            "started_at",
            "updated_at",
        )
        if any(not isinstance(payload.get(key), str) for key in required_strings):
            msg = "Squid transaction journal schema validation failed."
            raise SquidTransactionRecoveryRequiredError(msg)
        if payload["status"] not in _ALLOWED_STATUSES:
            msg = "Squid transaction journal contains an invalid status."
            raise SquidTransactionRecoveryRequiredError(msg)
        if len(payload) > 32 or any(len(str(key)) > 64 for key in payload):
            msg = "Squid transaction journal exceeds schema bounds."
            raise SquidTransactionRecoveryRequiredError(msg)
        for key in ("state_before", "state_current", "state_after"):
            manifest = payload.get(key)
            if manifest is None:
                continue
            if not isinstance(manifest, dict) or not isinstance(
                manifest.get("files"), list
            ):
                msg = "Squid transaction journal state manifest is invalid."
                raise SquidTransactionRecoveryRequiredError(msg)
            if len(manifest["files"]) > 130:
                msg = "Squid transaction journal state manifest exceeds bounds."
                raise SquidTransactionRecoveryRequiredError(msg)

    def _write(self, payload: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            path_stat = self.path.lstat()
        except FileNotFoundError:
            path_stat = None
        if path_stat is not None and (
            stat.S_ISLNK(path_stat.st_mode) or not stat.S_ISREG(path_stat.st_mode)
        ):
            msg = "Refusing to replace a non-regular Squid transaction journal path."
            raise SquidTransactionRecoveryRequiredError(msg)
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
        if len(serialized.encode("utf-8")) > _MAX_JOURNAL_BYTES:
            msg = "Squid transaction journal record exceeds the bounded size limit."
            raise SquidTransactionRecoveryRequiredError(msg)
        tmp_path = ""
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.path.parent,
                prefix=f".{self.path.name}.",
                delete=False,
            ) as handle:
                tmp_path = handle.name
                os.fchmod(handle.fileno(), 0o600)
                if path_stat is not None:
                    with contextlib.suppress(OSError):
                        os.fchown(handle.fileno(), path_stat.st_uid, path_stat.st_gid)
                handle.write(serialized)
                handle.flush()
                os.fsync(handle.fileno())
            Path(tmp_path).replace(self.path)
            _fsync_directory(self.path.parent)
        finally:
            if tmp_path:
                try:
                    # Avoid Path.unlink here: callers may instrument config-path
                    # unlink operations independently from journal temp cleanup.
                    os.remove(tmp_path)  # noqa: PTH107
                except FileNotFoundError:
                    pass


def default_journal_path(persisted_config: str | Path) -> Path:
    configured = str(os.environ.get("SQUID_TRANSACTION_JOURNAL_PATH") or "").strip()
    if configured:
        return Path(configured)
    return Path(persisted_config).parent / "squid-transaction.json"


def lifecycle_lock_path() -> Path:
    lock_dir = (
        os.environ.get("SQUID_LIFECYCLE_LOCK_DIR")
        or os.environ.get("PROXY_RUNTIME_LOCK_DIR")
        or "/tmp/docker-proxy-runtime"  # noqa: S108 - private validated directory
    ).strip() or "/tmp/docker-proxy-runtime"  # noqa: S108
    path = Path(lock_dir)
    if not path.is_absolute():
        msg = "Squid lifecycle lock directory must be an absolute path."
        raise ValueError(msg)
    return path / "docker-proxy-squid-lifecycle.lock"


def open_lifecycle_lock() -> int:
    """Open the shared lifecycle lock by descriptor-relative, no-follow traversal."""
    lock_path = lifecycle_lock_path()
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    if (
        not nofollow
        or not directory
        or os.open not in os.supports_dir_fd
        or os.mkdir not in os.supports_dir_fd
    ):
        msg = "Secure descriptor-relative lifecycle lock opens are unavailable."
        raise ValueError(msg)

    directory_flags = os.O_RDONLY | directory | nofollow | cloexec
    current_fd = -1
    try:
        current_fd = os.open(lock_path.anchor, directory_flags)
        components = lock_path.parent.parts[1:]
        for index, component in enumerate(components):
            try:
                next_fd = os.open(component, directory_flags, dir_fd=current_fd)
            except FileNotFoundError:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=current_fd)
                except FileExistsError:
                    # A racing creator must still pass the no-follow open below.
                    pass
                next_fd = os.open(component, directory_flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd

            directory_stat = os.fstat(current_fd)
            if not stat.S_ISDIR(directory_stat.st_mode):
                msg = "Squid lifecycle lock path component is not a directory."
                raise ValueError(msg)
            is_final = index == len(components) - 1
            if is_final and (
                directory_stat.st_uid != os.geteuid() or directory_stat.st_mode & 0o077
            ):
                msg = "Squid lifecycle lock directory must be owned by this user and private."
                raise ValueError(msg)
            if not is_final:
                trusted_owner = directory_stat.st_uid in {0, os.geteuid()}
                trusted_sticky_root = (
                    directory_stat.st_uid == 0 and directory_stat.st_mode & stat.S_ISVTX
                )
                unsafe_writes = directory_stat.st_mode & 0o022
                if not trusted_owner or (unsafe_writes and not trusted_sticky_root):
                    msg = "Squid lifecycle lock parent directory is unsafe."
                    raise ValueError(msg)

        fd = os.open(
            lock_path.name,
            os.O_RDWR | os.O_CREAT | nofollow | cloexec,
            0o600,
            dir_fd=current_fd,
        )
        try:
            file_stat = os.fstat(fd)
            if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_nlink != 1:
                msg = "Squid lifecycle lock path must be one regular file."
                raise ValueError(msg)
            if file_stat.st_uid != os.geteuid() or file_stat.st_mode & 0o077:
                msg = (
                    "Squid lifecycle lock file must be owned by this user and private."
                )
                raise ValueError(msg)
            return fd
        except Exception:
            os.close(fd)
            raise
    except OSError as exc:
        msg = "Unable to safely open the Squid lifecycle lock path."
        raise ValueError(msg) from exc
    finally:
        if current_fd >= 0:
            os.close(current_fd)


def _runtime_paths_from_environment() -> list[Path]:
    paths = [
        Path(
            os.environ.get("SQUID_ICAP_INCLUDE_PATH")
            or "/etc/squid/conf.d/20-icap.conf"
        ),
        Path(os.environ.get("VIRUS_SCAN_CONFIG_PATH") or "/etc/virus_scan.conf"),
        Path("/etc/clamd_mod.conf"),
    ]
    supervisor_dir = Path(
        os.environ.get("SQUID_SUPERVISOR_INCLUDE_DIR") or "/etc/supervisor.d"
    )
    cicap_dir = Path(os.environ.get("CICAP_CONFIG_DIR") or "/etc/c-icap")
    for pattern in ("cicap_adblock_*.conf", "cicap_av_*.conf", "clamav_respmod_*.conf"):
        paths.extend(sorted(supervisor_dir.glob(pattern)))
    paths.extend(sorted(cicap_dir.glob("c-icap-av-*.conf")))
    return list(dict.fromkeys(paths))


def _startup_begin(
    active: Path, persisted: Path, bootstrap_template: Path | None
) -> int:
    journal = SquidTransactionJournal(
        default_journal_path(persisted),
        active_config=active,
        persisted_config=persisted,
        runtime_paths=_runtime_paths_from_environment(),
    )
    previous: dict[str, Any] | None = None
    previous_error = ""
    try:
        previous = journal.read()
    except SquidTransactionRecoveryRequiredError as exc:
        previous_error = str(exc)
    dirty = bool(previous and str(previous.get("status") or "") in _DIRTY_STATUSES)
    recovery_needed = dirty or bool(previous_error)
    recovery_source = ""
    operation = "startup_materialization"
    status = "in_progress"
    phase = "prepared"
    recovery_status = "not_required"

    if recovery_needed:
        if persisted.is_file():
            _atomic_copy(persisted, active)
            recovery_source = "persisted_last_known_good"
        else:
            previous_operation = str((previous or {}).get("operation") or "")
            bootstrap_recoverable = previous_operation in {
                "startup_materialization",
                "startup_reconciliation",
            }
            if not (
                bootstrap_recoverable
                and bootstrap_template
                and bootstrap_template.is_file()
            ):
                return 1
            _atomic_copy(bootstrap_template, active)
            recovery_source = "immutable_bootstrap_template"
        operation = "startup_reconciliation"
        status = "recovering"
        phase = "recovery_source_restored"
        recovery_status = "in_progress"
    elif (
        not persisted.is_file() and bootstrap_template and bootstrap_template.is_file()
    ):
        _atomic_copy(bootstrap_template, active)
        recovery_source = "immutable_bootstrap_template"

    now = _utc_timestamp()
    payload: dict[str, Any] = {
        "schema_version": _SCHEMA_VERSION,
        "transaction_id": str(uuid.uuid4()),
        "operation": operation,
        "status": status,
        "phase": phase,
        "intended_phase": "validated_generation_persisted",
        "recovery_status": recovery_status,
        "started_at": now,
        "updated_at": now,
        "previous_transaction_id": str((previous or {}).get("transaction_id") or "")[
            :64
        ],
        "previous_journal_error": _bounded_detail(previous_error),
        "state_before": journal.state_manifest(),
        "evidence": {"recovery_source": recovery_source},
    }
    journal.replace_active(payload)
    return 0


def _startup_complete(active: Path, persisted: Path) -> int:
    journal = SquidTransactionJournal(
        default_journal_path(persisted),
        active_config=active,
        persisted_config=persisted,
        runtime_paths=_runtime_paths_from_environment(),
    )
    payload = journal.read()
    if not payload or str(payload.get("status") or "") not in _DIRTY_STATUSES:
        msg = "Startup completion requires an active Squid startup transaction."
        raise SquidTransactionRecoveryRequiredError(msg)
    if not active.is_file():
        journal.recovery_required("Validated startup Squid config is missing.")
        return 1
    journal.phase("startup_generation_validated")
    _atomic_copy(active, persisted)
    journal.phase("validated_generation_persisted")
    recovered = str(payload.get("operation") or "") == "startup_reconciliation"
    journal.complete(
        detail="Startup Squid generation validated and atomically persisted.",
        recovered=recovered,
    )
    _release_inherited_startup_lock()
    return 0


def _startup_fail(active: Path, persisted: Path, detail: str) -> int:
    journal = SquidTransactionJournal(
        default_journal_path(persisted),
        active_config=active,
        persisted_config=persisted,
        runtime_paths=_runtime_paths_from_environment(),
    )
    journal.recovery_required(
        detail or "Squid startup validation or cache preparation failed.",
        phase="startup_failed",
    )
    return 1


def _release_inherited_startup_lock() -> None:
    raw_fd = str(os.environ.get("SQUID_ENTRYPOINT_LOCK_FD") or "").strip()
    if not raw_fd:
        return
    try:
        fd = int(raw_fd)
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
        os.environ.pop("SQUID_ENTRYPOINT_LOCK_FD", None)
    except (OSError, TypeError, ValueError):
        return


def _lock_exec(command: list[str]) -> int:
    if not command:
        msg = "lock-exec requires a command"
        raise SystemExit(msg)
    import fcntl

    fd = open_lifecycle_lock()
    fcntl.flock(fd, fcntl.LOCK_EX)
    os.dup2(fd, 9, inheritable=True)
    os.set_inheritable(9, True)
    env = dict(os.environ)
    env["SQUID_ENTRYPOINT_LOCK_HELD"] = "1"
    env["SQUID_ENTRYPOINT_LOCK_FD"] = "9"
    os.execvpe(command[0], command, env)  # noqa: S606 -- intentional lock-holder exec
    return 127


def _atomic_copy(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        target_stat = target.stat()
    except FileNotFoundError:
        target_stat = None
    fd, tmp = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as output, source.open("rb") as input_file:
            if target_stat is not None:
                os.fchmod(output.fileno(), stat.S_IMODE(target_stat.st_mode))
                with contextlib.suppress(OSError):
                    os.fchown(output.fileno(), target_stat.st_uid, target_stat.st_gid)
            else:
                os.fchmod(output.fileno(), 0o640)
            shutil.copyfileobj(input_file, output)
            output.flush()
            os.fsync(output.fileno())
        Path(tmp).replace(target)
        _fsync_directory(target.parent)
    finally:
        try:
            Path(tmp).unlink()
        except FileNotFoundError:
            pass


def _file_evidence(role: str, path: Path) -> dict[str, Any]:
    item: dict[str, Any] = {"role": role, "path": str(path)[:1024], "exists": False}
    try:
        file_stat = path.stat()
        if not stat.S_ISREG(file_stat.st_mode):
            return item
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
    except (FileNotFoundError, OSError):
        return item
    item.update(
        {
            "exists": True,
            "size": size,
            "mode": stat.S_IMODE(file_stat.st_mode),
            "sha256": digest.hexdigest(),
        }
    )
    return item


def _sha256_text(value: str) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def _bounded_token(value: Any, default: str) -> str:
    token = str(value or default).replace("\r", " ").replace("\n", " ").strip()
    return token[:128] or default


def _bounded_scalar(value: Any) -> str | int | float | bool | None:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value).replace("\r", " ").replace("\n", " ")[:512]


def _bounded_detail(value: Any) -> str:
    text = str(value or "").replace("\x00", "")
    return text[:_MAX_DETAIL_CHARS]


def _fsync_directory(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    lock_parser = subparsers.add_parser("lock-exec")
    lock_parser.add_argument("exec_command", nargs=argparse.REMAINDER)
    for name in ("startup-begin", "startup-complete", "startup-fail"):
        command_parser = subparsers.add_parser(name)
        command_parser.add_argument("--active", default="/etc/squid/squid.conf")
        command_parser.add_argument(
            "--persisted",
            default=os.environ.get("PERSISTED_SQUID_CONF_PATH")
            or "/var/lib/squid-flask-proxy/squid.conf",
        )
        if name == "startup-begin":
            command_parser.add_argument("--bootstrap-template", default="")
        if name == "startup-fail":
            command_parser.add_argument("--detail", default="")
    args = parser.parse_args(argv)
    if args.command == "lock-exec":
        return _lock_exec(args.exec_command)
    active = Path(args.active)
    persisted = Path(args.persisted)
    if args.command == "startup-begin":
        bootstrap_template = (
            Path(args.bootstrap_template) if args.bootstrap_template else None
        )
        return _startup_begin(active, persisted, bootstrap_template)
    if args.command == "startup-fail":
        return _startup_fail(active, persisted, args.detail)
    return _startup_complete(active, persisted)


if __name__ == "__main__":
    raise SystemExit(main())
