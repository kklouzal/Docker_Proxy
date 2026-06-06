from __future__ import annotations

import contextlib
import os
import pathlib
import tempfile

_RUNTIME_FILE_MODE = 0o644


def _write_staged_file(path: str, content: str | bytes) -> str:
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
        pathlib.Path(temp_path).chmod(_RUNTIME_FILE_MODE)
        return temp_path
    except Exception:
        with contextlib.suppress(FileNotFoundError):
            pathlib.Path(temp_path).unlink()
        raise


def write_managed_text_files(*files: tuple[str, str]) -> None:
    temp_paths: list[str] = []
    backups: dict[str, tuple[bool, bytes]] = {}
    replaced_paths: list[str] = []
    try:
        for path, content in files:
            temp_paths.append(_write_staged_file(path, content))

        for path, _content in files:
            try:
                with pathlib.Path(path).open("rb") as existing:
                    backups[path] = (True, existing.read())
            except FileNotFoundError:
                backups[path] = (False, b"")

        for (path, _content), temp_path in zip(files, temp_paths, strict=False):
            os.replace(temp_path, path)  # noqa: PTH105
            replaced_paths.append(path)
    except Exception:
        for path in reversed(replaced_paths):
            existed, previous = backups.get(path, (False, b""))
            if existed:
                temp_path = _write_staged_file(path, previous)
                temp_paths.append(temp_path)
                os.replace(temp_path, path)  # noqa: PTH105
            else:
                with contextlib.suppress(FileNotFoundError):
                    pathlib.Path(path).unlink()
        raise
    finally:
        for temp_path in temp_paths:
            try:
                if pathlib.Path(temp_path).exists():
                    pathlib.Path(temp_path).unlink()
            except Exception:
                pass
