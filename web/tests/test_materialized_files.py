from __future__ import annotations

import errno
import stat
import sys
from pathlib import Path

import pytest


def _materialized_files_module():
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))
    from services import materialized_files  # type: ignore

    return materialized_files


def test_write_managed_text_files_rolls_back_publish_on_directory_fsync_io_failure(
    tmp_path,
    monkeypatch,
) -> None:
    materialized_files = _materialized_files_module()
    target = tmp_path / "managed.conf"
    target.write_text("old\n", encoding="utf-8")
    real_fsync = materialized_files.os.fsync
    directory_fsync_count = 0

    def fail_publish_directory_fsync(fd: int) -> None:
        nonlocal directory_fsync_count
        if stat.S_ISDIR(materialized_files.os.fstat(fd).st_mode):
            directory_fsync_count += 1
            if directory_fsync_count == 2:
                raise OSError(errno.EIO, "directory fsync failed")
        real_fsync(fd)

    monkeypatch.setattr(materialized_files.os, "fsync", fail_publish_directory_fsync)

    with pytest.raises(OSError, match="directory fsync failed"):
        materialized_files.write_managed_text_files((str(target), "new\n"))

    assert target.read_text(encoding="utf-8") == "old\n"
    assert list(tmp_path.glob(".managed-*")) == []
