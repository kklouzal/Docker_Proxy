from __future__ import annotations

import contextlib
import os
import pathlib
import tempfile


def write_managed_text_files(*files: tuple[str, str]) -> None:
    temp_paths: list[str] = []
    backups: dict[str, tuple[bool, bytes]] = {}
    replaced_paths: list[str] = []
    mode = 0o644
    try:
        for path, content in files:
            directory = pathlib.Path(path).parent or "."
            pathlib.Path(directory).mkdir(exist_ok=True, parents=True)
            handle = tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                delete=False,
                dir=directory,
                prefix=".managed-",
            )
            temp_path = handle.name
            temp_paths.append(temp_path)
            try:
                handle.write(content)
                handle.flush()
            finally:
                handle.close()
            pathlib.Path(temp_path).chmod(mode)

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
                pathlib.Path(path).write_bytes(previous)
                pathlib.Path(path).chmod(mode)
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
