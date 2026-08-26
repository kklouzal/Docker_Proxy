from __future__ import annotations

import contextlib
import fcntl
import hashlib
import os
import pathlib
import stat
import tempfile
from dataclasses import dataclass
from typing import TYPE_CHECKING

from services.keyed_locks import KeyedLockRegistry
from services.runtime_helpers import fsync_parent_dir as _fsync_parent_dir

if TYPE_CHECKING:
    from collections.abc import Iterator

_RUNTIME_FILE_MODE = 0o644
_MANAGED_PATH_LOCKS = KeyedLockRegistry[str]()


def _managed_path_key(path: str) -> str:
    return os.path.abspath(path)  # noqa: PTH100 -- preserve symlink identity


def _validate_managed_path(path: str) -> None:
    """Reject links and non-directory ancestors, and non-regular targets."""
    target = pathlib.Path(
        os.path.abspath(path)  # noqa: PTH100 -- inspect rather than resolve links
    )
    for parent in reversed(target.parents):
        try:
            parent_stat = parent.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(parent_stat.st_mode) or not stat.S_ISDIR(parent_stat.st_mode):
            msg = f"Managed file path has an unsafe parent component: {path!r}"
            raise RuntimeError(msg)
    try:
        target_stat = target.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(target_stat.st_mode) or not stat.S_ISREG(target_stat.st_mode):
        msg = f"Managed file target is not a regular file: {path!r}"
        raise RuntimeError(msg)


def _interprocess_lock_path(path_key: str) -> pathlib.Path:
    target = pathlib.Path(path_key)
    digest = hashlib.sha256(path_key.encode()).hexdigest()
    return target.parent / f".materialized-lock-{digest}"


@contextlib.contextmanager
def _locked_materialized_paths(paths: list[str]) -> Iterator[None]:
    path_keys = sorted({_managed_path_key(path) for path in paths})
    lock_files: list[int] = []
    with _MANAGED_PATH_LOCKS.locked(path_keys):
        try:
            for path_key in path_keys:
                _validate_managed_path(path_key)
                lock_path = _interprocess_lock_path(path_key)
                lock_path.parent.mkdir(exist_ok=True, parents=True)
                flags = os.O_CREAT | os.O_RDWR | os.O_CLOEXEC
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                try:
                    fd = os.open(lock_path, flags, 0o600)
                    fcntl.flock(fd, fcntl.LOCK_EX)
                except OSError:
                    with contextlib.suppress(UnboundLocalError):
                        os.close(fd)
                    msg = "Unable to serialize managed file update"
                    raise RuntimeError(msg) from None
                lock_files.append(fd)
            yield
        finally:
            for fd in reversed(lock_files):
                with contextlib.suppress(OSError):
                    fcntl.flock(fd, fcntl.LOCK_UN)
                with contextlib.suppress(OSError):
                    os.close(fd)


@dataclass(frozen=True)
class _FileBackup:
    existed: bool
    content: bytes = b""
    mode: int = _RUNTIME_FILE_MODE
    owner: tuple[int, int] | None = None


class ManagedFileRollbackError(RuntimeError):
    """A managed-file publication failed and could not be fully rolled back."""

    def __init__(self, rollback_failure_count: int) -> None:
        super().__init__("Managed file publication failed and rollback was incomplete")
        self.rollback_failure_count = rollback_failure_count


def _read_regular_file_backup(path: str) -> _FileBackup:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return _FileBackup(existed=False)
    except OSError:
        msg = f"Unable to safely read managed file target: {path!r}"
        raise RuntimeError(msg) from None
    try:
        target_stat = os.fstat(fd)
        if not stat.S_ISREG(target_stat.st_mode):
            msg = f"Managed file target is not a regular file: {path!r}"
            raise RuntimeError(msg)
        with os.fdopen(fd, "rb") as existing:
            fd = -1
            return _FileBackup(
                existed=True,
                content=existing.read(),
                mode=target_stat.st_mode & 0o777,
                owner=(target_stat.st_uid, target_stat.st_gid),
            )
    finally:
        if fd >= 0:
            os.close(fd)


def _write_staged_file(
    path: str,
    content: str | bytes,
    *,
    mode: int = _RUNTIME_FILE_MODE,
    owner: tuple[int, int] | None = None,
) -> str:
    directory = pathlib.Path(path).parent or "."
    pathlib.Path(directory).mkdir(exist_ok=True, parents=True)
    binary = isinstance(content, bytes)
    handle = tempfile.NamedTemporaryFile(
        "wb" if binary else "w",
        encoding=None if binary else "utf-8",
        delete=False,
        dir=directory,
        prefix=".managed-",
    )
    temp_path = handle.name
    try:
        try:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        finally:
            handle.close()
        pathlib.Path(temp_path).chmod(mode)
        if owner is not None:
            os.chown(temp_path, owner[0], owner[1])
        _fsync_parent_dir(temp_path)
        return temp_path
    except Exception:
        unlinked = False
        with contextlib.suppress(FileNotFoundError):
            pathlib.Path(temp_path).unlink()
            unlinked = True
        if unlinked:
            _fsync_parent_dir(temp_path)
        raise


def _coalesced_managed_text_files(
    files: tuple[tuple[str, str], ...],
) -> tuple[tuple[str, str, str], ...]:
    coalesced: list[tuple[str, str, str]] = []
    by_target: dict[str, tuple[str, str]] = {}
    for path, content in files:
        target_key = _managed_path_key(path)
        existing = by_target.get(target_key)
        if existing is None:
            by_target[target_key] = (path, content)
            coalesced.append((target_key, path, content))
            continue
        existing_path, existing_content = existing
        if existing_content != content:
            msg = (
                "Managed text file target renders conflicting content: "
                f"{existing_path!r} and {path!r}"
            )
            raise ValueError(msg)
    return tuple(coalesced)


def write_managed_text_files(*files: tuple[str, str]) -> None:
    materialized_files = _coalesced_managed_text_files(files)
    temp_paths: list[str] = []
    backups: dict[str, _FileBackup] = {}
    replaced_paths: list[tuple[str, str]] = []
    try:
        with _locked_materialized_paths(
            [target_key for target_key, _path, _content in materialized_files]
        ):
            try:
                for target_key, path, _content in materialized_files:
                    _validate_managed_path(path)
                    backups[target_key] = _read_regular_file_backup(path)

                for target_key, path, content in materialized_files:
                    backup = backups[target_key]
                    temp_paths.append(
                        _write_staged_file(
                            path,
                            content,
                            mode=backup.mode,
                            owner=backup.owner,
                        )
                    )

                for (target_key, path, _content), temp_path in zip(
                    materialized_files, temp_paths, strict=False
                ):
                    _validate_managed_path(path)
                    os.replace(temp_path, path)  # noqa: PTH105
                    replaced_paths.append((target_key, path))
                    _fsync_parent_dir(path)
            except Exception as publish_error:
                rollback_errors: list[tuple[str, Exception]] = []
                for target_key, path in reversed(replaced_paths):
                    backup = backups.get(target_key, _FileBackup(existed=False))
                    try:
                        if backup.existed:
                            temp_path = _write_staged_file(
                                path,
                                backup.content,
                                mode=backup.mode,
                                owner=backup.owner,
                            )
                            temp_paths.append(temp_path)
                            os.replace(temp_path, path)  # noqa: PTH105
                            _fsync_parent_dir(path)
                        else:
                            unlinked = False
                            with contextlib.suppress(FileNotFoundError):
                                pathlib.Path(path).unlink()
                                unlinked = True
                            if unlinked:
                                _fsync_parent_dir(path)
                    except Exception as rollback_error:
                        rollback_errors.append((path, rollback_error))
                        publish_error.add_note(
                            f"Rollback failed for managed file {path!r}: "
                            f"{rollback_error!r}"
                        )
                if rollback_errors:
                    error = ManagedFileRollbackError(len(rollback_errors))
                    for path, rollback_error in rollback_errors:
                        error.add_note(
                            f"Rollback failed for managed file {path!r}: "
                            f"{rollback_error!r}"
                        )
                    raise error from publish_error
                raise
    finally:
        for temp_path in temp_paths:
            try:
                if pathlib.Path(temp_path).exists():
                    pathlib.Path(temp_path).unlink()
                    _fsync_parent_dir(temp_path)
            except Exception:
                pass
