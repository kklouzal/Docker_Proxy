from __future__ import annotations

import threading

import pytest
from services.log_follower import LogFollower, run_batched_tail_loop  # type: ignore
from services.observability_backoff import DatabaseWriteBackoff  # type: ignore


def _drain(follower: LogFollower) -> list[str]:
    lines = []
    while (line := follower.read_line()) is not None:
        lines.append(line)
    return lines


def test_follower_starts_at_end_and_returns_only_complete_lines(tmp_path) -> None:
    path = tmp_path / "access.log"
    path.write_bytes(b"old\n")
    follower = LogFollower(str(path))
    assert follower.ensure_open()
    assert _drain(follower) == []

    with path.open("ab") as handle:
        handle.write(b"new one\r\npartial")
    assert _drain(follower) == ["new one"]
    with path.open("ab") as handle:
        handle.write(b" rest\n")
    assert _drain(follower) == ["partial rest"]
    assert follower.offset == path.stat().st_size


def test_follower_opened_mid_line_skips_the_fragment(tmp_path) -> None:
    path = tmp_path / "access.log"
    path.write_bytes(b"complete\nhalf-writ")
    follower = LogFollower(str(path))
    follower.ensure_open()
    with path.open("ab") as handle:
        handle.write(b"ten\nnext\n")
    assert _drain(follower) == ["next"]


def test_resume_offset_inside_a_line_aligns_to_next_boundary(tmp_path) -> None:
    path = tmp_path / "access.log"
    path.write_bytes(b"aaaa\nbbbb\ncccc\n")
    st = path.stat()
    follower = LogFollower(
        str(path), resume_identity=(st.st_dev, st.st_ino), resume_offset=7
    )
    follower.ensure_open()
    assert _drain(follower) == ["cccc"]


def test_resume_offset_for_another_file_identity_reads_from_start(tmp_path) -> None:
    path = tmp_path / "access.log"
    path.write_bytes(b"aaaa\nbbbb\n")
    follower = LogFollower(str(path), resume_identity=(0, 0), resume_offset=4)
    follower.ensure_open()
    assert _drain(follower) == ["aaaa", "bbbb"]


def test_at_current_end_follows_a_file_replaced_before_open_from_start(
    tmp_path,
) -> None:
    path = tmp_path / "access.log"
    path.write_bytes(b"seeded\n")
    follower = LogFollower.at_current_end(str(path))
    replacement = tmp_path / "access.log.new"
    replacement.write_bytes(b"after rotation\n")
    replacement.replace(path)
    follower.ensure_open()
    assert _drain(follower) == ["after rotation"]


def test_at_current_end_reads_a_log_truncated_before_open_from_start(
    tmp_path,
) -> None:
    path = tmp_path / "access.log"
    path.write_bytes(b"seeded line one\nseeded line two\n")
    follower = LogFollower.at_current_end(str(path))
    with path.open("r+b") as handle:
        handle.truncate(0)
    with path.open("ab") as handle:
        handle.write(b"new\n")
    follower.ensure_open()
    assert _drain(follower) == ["new"]


def test_at_current_end_tails_lines_appended_after_capture(tmp_path) -> None:
    path = tmp_path / "access.log"
    path.write_bytes(b"seeded\n")
    follower = LogFollower.at_current_end(str(path))
    # Appended while the startup seed runs, before the tail thread opens it.
    with path.open("ab") as handle:
        handle.write(b"during seed\n")
    follower.ensure_open()
    assert _drain(follower) == ["during seed"]


def test_at_current_end_reads_a_log_created_later_from_its_start(tmp_path) -> None:
    path = tmp_path / "access.log"
    follower = LogFollower.at_current_end(str(path))
    assert not follower.ensure_open()
    path.write_bytes(b"first\n")
    assert follower.ensure_open()
    assert _drain(follower) == ["first"]


def test_oversized_lines_are_discarded_whole(tmp_path) -> None:
    path = tmp_path / "access.log"
    path.write_bytes(b"")
    follower = LogFollower(str(path), max_line_bytes=8)
    follower.ensure_open()
    with path.open("ab") as handle:
        handle.write(b"short\n" + b"x" * 30)
    assert _drain(follower) == ["short"]
    with path.open("ab") as handle:
        handle.write(b"y" * 30 + b"\nafter\n")
    assert _drain(follower) == ["after"]


def test_truncation_restarts_from_start(tmp_path) -> None:
    path = tmp_path / "access.log"
    path.write_bytes(b"")
    follower = LogFollower(str(path))
    follower.ensure_open()
    path.write_bytes(b"one long line\n")
    assert _drain(follower) == ["one long line"]
    path.write_bytes(b"x\n")
    assert follower.poll_rotation() == "truncated"
    assert _drain(follower) == ["x"]


def test_copytruncate_regrowth_past_cursor_restarts_from_start(tmp_path) -> None:
    path = tmp_path / "access.log"
    path.write_bytes(b"")
    follower = LogFollower(str(path))
    follower.ensure_open()
    path.write_bytes(b"old\n")
    assert _drain(follower) == ["old"]
    assert follower.poll_rotation() is None
    path.write_bytes(b"new first\nnew second\n")
    assert _drain(follower) == ["new first", "new second"]


def test_replacement_is_followed_from_its_start(tmp_path) -> None:
    path = tmp_path / "access.log"
    path.write_bytes(b"")
    follower = LogFollower(str(path))
    follower.ensure_open()
    path.write_bytes(b"old\n")
    assert _drain(follower) == ["old"]
    path.rename(tmp_path / "access.log.1")
    path.write_bytes(b"fresh\n")
    assert follower.poll_rotation() == "replaced"
    assert follower._handle is None
    assert follower.ensure_open()
    assert _drain(follower) == ["fresh"]


class _Stop(BaseException):
    pass


def test_runner_keeps_cursor_across_loop_failures(tmp_path) -> None:
    """A failing iteration must not re-seek to the end and skip lines."""
    path = tmp_path / "access.log"
    path.write_bytes(b"")
    follower = LogFollower(str(path))
    stop = threading.Event()
    seen: list[str] = []
    waits = 0

    def accept(line: str) -> None:
        seen.append(line)

    pending: list[str] = []

    def wait(_timeout: float) -> bool:
        nonlocal waits
        waits += 1
        if waits == 1:
            path.write_bytes(b"one\ntwo\n")
        if waits >= 4:
            raise _Stop
        return False

    stop.wait = wait  # type: ignore[method-assign]
    polls = 0
    real_poll = follower.poll_rotation

    def flaky_poll() -> str | None:
        nonlocal polls
        polls += 1
        if polls == 2:
            # Lines were appended before the failure; they must survive it.
            with path.open("ab") as handle:
                handle.write(b"three\n")
            msg = "transient stat failure"
            raise OSError(msg)
        return real_poll()

    follower.poll_rotation = flaky_poll  # type: ignore[method-assign]

    with pytest.raises(_Stop):
        run_batched_tail_loop(
            follower=follower,
            stop_event=stop,
            accept_line=accept,
            pending=lambda: len(pending),
            flush=pending.clear,
            backoff=DatabaseWriteBackoff(jitter_ratio=0.0),
            commit_batch=25,
            commit_interval=1.0,
            poll_interval=0.1,
            logger=__import__("logging").getLogger("test"),
            log_key="test",
            label="Test tailer",
        )

    assert seen == ["one", "two", "three"]
    assert follower._handle is None


def test_runner_pauses_reading_at_capacity_until_flush_succeeds(tmp_path) -> None:
    path = tmp_path / "access.log"
    path.write_bytes(b"")
    follower = LogFollower(str(path))
    stop = threading.Event()
    buffered: list[str] = []
    flushed: list[list[str]] = []
    flush_ok = False
    waits = 0

    def flush() -> None:
        if not flush_ok:
            msg = "write failed"
            raise RuntimeError(msg)
        flushed.append(list(buffered))
        buffered.clear()

    def wait(_timeout: float) -> bool:
        nonlocal waits, flush_ok
        waits += 1
        if waits == 1:
            path.write_bytes(b"a\nb\nc\n")
        if waits == 3:
            assert buffered == ["a", "b"]
            flush_ok = True
        if waits >= 6:
            raise _Stop
        return False

    stop.wait = wait  # type: ignore[method-assign]

    with pytest.raises(_Stop):
        run_batched_tail_loop(
            follower=follower,
            stop_event=stop,
            accept_line=buffered.append,
            pending=lambda: len(buffered),
            flush=flush,
            backoff=DatabaseWriteBackoff(base_seconds=0.0, jitter_ratio=0.0),
            commit_batch=100,
            commit_interval=1000.0,
            poll_interval=0.1,
            logger=__import__("logging").getLogger("test"),
            log_key="test",
            label="Test tailer",
            pause_at_pending=2,
        )

    assert flushed[0] == ["a", "b"]
    assert buffered == ["c"]


def test_at_current_end_resumes_at_last_complete_line(tmp_path) -> None:
    path = tmp_path / "access.log"
    path.write_bytes(b"done\nhalf")
    follower = LogFollower.at_current_end(str(path))
    assert follower.resume_offset == len(b"done\n")
    follower.ensure_open()
    with path.open("ab") as handle:
        handle.write(b"-written\n")
    assert _drain(follower) == ["half-written"]
