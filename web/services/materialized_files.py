from __future__ import annotations

import os


def write_managed_text_files(*files: tuple[str, str]) -> None:
    for path, content in files:
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)