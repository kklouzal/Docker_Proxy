from __future__ import annotations

import os
import tempfile


def write_managed_text_files(*files: tuple[str, str]) -> None:
    temp_paths: list[str] = []
    backups: dict[str, tuple[bool, bytes]] = {}
    replaced_paths: list[str] = []
    try:
        for path, content in files:
            directory = os.path.dirname(path) or "."
            os.makedirs(directory, exist_ok=True)
            handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=directory, prefix=".managed-")
            temp_path = handle.name
            temp_paths.append(temp_path)
            try:
                handle.write(content)
                handle.flush()
            finally:
                handle.close()

        for path, _content in files:
            try:
                with open(path, "rb") as existing:
                    backups[path] = (True, existing.read())
            except FileNotFoundError:
                backups[path] = (False, b"")

        for (path, _content), temp_path in zip(files, temp_paths):
            os.replace(temp_path, path)
            replaced_paths.append(path)
    except Exception:
        for path in reversed(replaced_paths):
            existed, previous = backups.get(path, (False, b""))
            if existed:
                with open(path, "wb") as restored:
                    restored.write(previous)
            else:
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass
        raise
    finally:
        for temp_path in temp_paths:
            try:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
            except Exception:
                pass
