from __future__ import annotations

import contextlib
import os
import pathlib
import tempfile
from dataclasses import dataclass

_RUNTIME_FILE_MODE = 0o644


def _fsync_parent_dir(path: str) -> None:
    """Best-effort fsync for directory entries created/replaced near path."""
    directory = pathlib.Path(path).parent or pathlib.Path()
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    fd: int | None = None
    try:
        fd = os.open(directory, flags)
        os.fsync(fd)
    except OSError:
        # Some platforms/filesystems do not support opening or fsyncing dirs.
        return
    finally:
        if fd is not None:
            with contextlib.suppress(OSError):
                os.close(fd)


@dataclass(frozen=True)
class _FileBackup:
    existed: bool
    content: bytes = b""
    mode: int = _RUNTIME_FILE_MODE
    owner: tuple[int, int] | None = None


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
            with contextlib.suppress(Exception):
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


def write_managed_text_files(*files: tuple[str, str]) -> None:
    temp_paths: list[str] = []
    backups: dict[str, _FileBackup] = {}
    replaced_paths: list[str] = []
    try:
        for path, content in files:
            temp_paths.append(_write_staged_file(path, content))

        for path, _content in files:
            try:
                stat = pathlib.Path(path).stat()
                with pathlib.Path(path).open("rb") as existing:
                    backups[path] = _FileBackup(
                        existed=True,
                        content=existing.read(),
                        mode=stat.st_mode & 0o777,
                        owner=(stat.st_uid, stat.st_gid),
                    )
            except FileNotFoundError:
                backups[path] = _FileBackup(existed=False)

        for (path, _content), temp_path in zip(files, temp_paths, strict=False):
            os.replace(temp_path, path)  # noqa: PTH105
            _fsync_parent_dir(path)
            replaced_paths.append(path)
    except Exception:
        for path in reversed(replaced_paths):
            backup = backups.get(path, _FileBackup(existed=False))
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
        raise
    finally:
        for temp_path in temp_paths:
            try:
                if pathlib.Path(temp_path).exists():
                    pathlib.Path(temp_path).unlink()
                    _fsync_parent_dir(temp_path)
            except Exception:
                pass
