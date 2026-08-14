from __future__ import annotations

import errno
import multiprocessing
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


def _overlapping_writer(
    targets: tuple[str, str],
    first_replaced,
    permit_failure,
    writer_started,
    writer_done,
    failing: bool,
) -> None:
    materialized_files = _materialized_files_module()
    if failing:
        real_replace = materialized_files.os.replace
        replace_count = 0

        def fail_second_replace(source, destination) -> None:
            nonlocal replace_count
            replace_count += 1
            if replace_count == 1:
                real_replace(source, destination)
                first_replaced.set()
                assert permit_failure.wait(10)
                return
            if replace_count == 2:
                raise OSError(errno.EIO, "injected late publish failure")
            real_replace(source, destination)

        materialized_files.os.replace = fail_second_replace
        try:
            materialized_files.write_managed_text_files(
                (targets[0], "failed-a\n"), (targets[1], "failed-b\n")
            )
        except OSError:
            return
        msg = "failing writer unexpectedly succeeded"
        raise AssertionError(msg)

    writer_started.set()
    materialized_files.write_managed_text_files(
        (targets[0], "success-a\n"), (targets[1], "success-b\n")
    )
    writer_done.set()


def test_write_managed_text_files_serializes_cross_process_rollback(tmp_path) -> None:
    targets = (str(tmp_path / "a.conf"), str(tmp_path / "b.conf"))
    for target in targets:
        Path(target).write_text("old\n", encoding="utf-8")

    context = multiprocessing.get_context("fork")
    first_replaced = context.Event()
    permit_failure = context.Event()
    writer_started = context.Event()
    writer_done = context.Event()
    failing_writer = context.Process(
        target=_overlapping_writer,
        args=(
            targets,
            first_replaced,
            permit_failure,
            writer_started,
            writer_done,
            True,
        ),
    )
    successful_writer = context.Process(
        target=_overlapping_writer,
        args=(
            targets,
            first_replaced,
            permit_failure,
            writer_started,
            writer_done,
            False,
        ),
    )

    failing_writer.start()
    assert first_replaced.wait(10)
    successful_writer.start()
    assert writer_started.wait(10)
    assert not writer_done.wait(0.25)
    permit_failure.set()
    failing_writer.join(10)
    successful_writer.join(10)

    assert failing_writer.exitcode == 0
    assert successful_writer.exitcode == 0
    assert writer_done.is_set()
    assert Path(targets[0]).read_text(encoding="utf-8") == "success-a\n"
    assert Path(targets[1]).read_text(encoding="utf-8") == "success-b\n"


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


@pytest.mark.parametrize("target_kind", ["symlink", "fifo", "directory"])
def test_write_managed_text_files_rejects_nonregular_existing_target(
    tmp_path, target_kind
) -> None:
    materialized_files = _materialized_files_module()
    target = tmp_path / "managed.conf"
    external = tmp_path / "external.conf"
    external.write_text("secret\n", encoding="utf-8")
    if target_kind == "symlink":
        target.symlink_to(external)
    elif target_kind == "fifo":
        target.parent.mkdir(exist_ok=True, parents=True)
        materialized_files.os.mkfifo(target)
    else:
        target.mkdir()

    with pytest.raises(RuntimeError, match="not a regular file"):
        materialized_files.write_managed_text_files((str(target), "new\n"))

    assert external.read_text(encoding="utf-8") == "secret\n"
    assert not list(tmp_path.glob(".managed-*"))


def test_write_managed_text_files_rejects_symlink_parent(tmp_path) -> None:
    materialized_files = _materialized_files_module()
    external = tmp_path / "external"
    external.mkdir()
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(external, target_is_directory=True)

    with pytest.raises(RuntimeError, match="unsafe parent component"):
        materialized_files.write_managed_text_files(
            (str(linked_parent / "managed.conf"), "new\n")
        )

    assert not (external / "managed.conf").exists()
    assert not list(external.glob(".materialized-lock-*"))
