"""Shared follower for the Squid observability logs tailed by background stores.

The proxy rotates ``access-observe.log``/``icap.log``/``cache.log`` by
copytruncate (see ``docker/squid_logrotate.sh``), but a replaced file is also
handled. Contracts every tailer relies on:

* Only complete newline-terminated lines are returned. An unterminated tail is
  left in place until its newline arrives, so a line racing the writer is never
  split into two garbage records.
* Lines longer than ``max_line_bytes`` are discarded whole (bounded memory).
* A start offset that is not on a line boundary skips to the next boundary.
* Truncation (size below the cursor), copytruncate regrowth past the cursor
  (the last returned line no longer matches the bytes on disk), and
  replacement (new device/inode) restart reading from the start of the file.
* The cursor survives caller exceptions: ``run_batched_tail_loop`` keeps the
  follower open across failed iterations instead of re-seeking to the end.
"""

from __future__ import annotations

import os
import pathlib
import time
from typing import TYPE_CHECKING, BinaryIO

from services.db import DATABASE_ERRORS
from services.logutil import log_database_unavailable, log_exception_throttled

if TYPE_CHECKING:
    import logging
    import threading
    from collections.abc import Callable

    from services.observability_backoff import DatabaseWriteBackoff

DEFAULT_MAX_LINE_BYTES = 1024 * 1024

FileIdentity = tuple[int, int]


class LogFollower:
    """Incrementally read complete lines from one rotating log path."""

    def __init__(
        self,
        path: str,
        *,
        resume_identity: FileIdentity | None = None,
        resume_offset: int | None = None,
        from_start: bool = False,
        max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
    ) -> None:
        self.path = path
        self.max_line_bytes = max(1, int(max_line_bytes))
        self._resume_identity = resume_identity
        self._resume_offset = resume_offset
        self._open_from_start = from_start
        self._handle: BinaryIO | None = None
        self._identity: FileIdentity | None = None
        self._offset = 0
        self._discarding = False
        self._last_line_offset: int | None = None
        self._last_line: bytes | None = None
        self._idle_version: tuple[int, int, int] | None = None

    @classmethod
    def at_current_end(
        cls, path: str, *, max_line_bytes: int = DEFAULT_MAX_LINE_BYTES
    ) -> LogFollower:
        """Return a follower that resumes at the path's last complete line.

        Capture this before reading a startup seed window that ends at
        ``resume_offset``: the seed and the tail then partition the file
        exactly, and a record still being written when captured is tailed
        whole. A missing path is read from its start once it appears:
        everything in it was written after this call.
        """
        try:
            with pathlib.Path(path).open("rb") as handle:
                st = os.fstat(handle.fileno())
                size = int(st.st_size)
                window = min(size, max_line_bytes)
                handle.seek(size - window, os.SEEK_SET)
                newline = handle.read(window).rfind(b"\n")
        except OSError:
            return cls(path, from_start=True, max_line_bytes=max_line_bytes)
        # No newline within one max-size record: the tail is oversized and is
        # skipped by the follower's alignment instead.
        offset = size if newline < 0 else size - window + newline + 1
        return cls(
            path,
            resume_identity=(int(st.st_dev), int(st.st_ino)),
            resume_offset=offset,
            max_line_bytes=max_line_bytes,
        )

    @property
    def resume_offset(self) -> int | None:
        """Offset the first open resumes at, if it is still pending."""
        return self._resume_offset

    @property
    def offset(self) -> int:
        """Byte offset just past the last complete line returned (or skipped)."""
        return self._offset

    @property
    def identity(self) -> FileIdentity | None:
        return self._identity

    def close(self) -> None:
        handle, self._handle = self._handle, None
        if handle is not None:
            handle.close()

    def ensure_open(self) -> bool:
        """Open the path if needed; return False while it does not exist."""
        if self._handle is not None:
            return True
        try:
            handle = pathlib.Path(self.path).open("rb")
        except FileNotFoundError:
            return False
        try:
            st = os.fstat(handle.fileno())
            identity = (int(st.st_dev), int(st.st_ino))
            size = int(st.st_size)
            if self._open_from_start:
                offset = 0
            elif (
                self._resume_offset is not None
                and self._resume_identity == identity
                and 0 <= int(self._resume_offset) <= size
            ):
                offset = int(self._resume_offset)
            else:
                offset = size
            self._resume_identity = None
            self._resume_offset = None
            self._open_from_start = False
            self._handle = handle
            self._identity = identity
            self._reset_cursor(handle, offset)
        except BaseException:
            self._handle = None
            handle.close()
            raise
        return True

    def _reset_cursor(self, handle: BinaryIO, offset: int) -> None:
        self._last_line_offset = None
        self._last_line = None
        self._idle_version = None
        self._discarding = False
        if offset > 0:
            handle.seek(offset - 1, os.SEEK_SET)
            # Not on a line boundary: the bytes up to the next newline belong
            # to a record that started before the cursor.
            self._discarding = handle.read(1) != b"\n"
        self._offset = offset
        handle.seek(offset, os.SEEK_SET)

    def _file_version(self) -> tuple[int, int, int] | None:
        if self._handle is None:
            return None
        st = os.fstat(self._handle.fileno())
        return (int(st.st_size), int(st.st_mtime_ns), int(st.st_ctime_ns))

    def _cursor_still_valid(self, handle: BinaryIO) -> bool:
        if self._last_line is None or self._last_line_offset is None:
            return True
        handle.seek(self._last_line_offset, os.SEEK_SET)
        on_disk = handle.read(len(self._last_line))
        handle.seek(self._offset, os.SEEK_SET)
        return on_disk == self._last_line

    def read_line(self) -> str | None:
        """Return the next complete line without its terminator, else None."""
        handle = self._handle
        if handle is None:
            return None
        if self._idle_version is not None:
            # The file changed since the last idle poll; copytruncate can regrow
            # past the cursor between polls, so size alone proves nothing.
            changed = self._file_version() != self._idle_version
            self._idle_version = None
            if changed and not self._cursor_still_valid(handle):
                self._reset_cursor(handle, 0)
        while True:
            start = self._offset
            chunk = handle.readline(self.max_line_bytes + 1)
            if not chunk:
                return None
            if not chunk.endswith(b"\n"):
                if len(chunk) <= self.max_line_bytes and not self._discarding:
                    # Unterminated tail: wait for the writer to finish it.
                    handle.seek(start, os.SEEK_SET)
                    return None
                # Oversized record (or the remainder of one): drop it whole.
                self._offset = start + len(chunk)
                self._discarding = True
                continue
            self._offset = start + len(chunk)
            if self._discarding:
                self._discarding = False
                continue
            self._last_line_offset = start
            self._last_line = chunk
            return chunk.decode("utf-8", errors="replace").rstrip("\r\n")

    def poll_rotation(self) -> str | None:
        """Check the path after reaching EOF.

        Returns ``"replaced"`` when a different file now lives at the path (the
        follower closes and the next ``ensure_open`` reads it from the start),
        ``"truncated"`` when the cursor was reset to the start, else None.
        """
        if self._handle is None:
            return None
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            # Removed without replacement yet: keep the drained handle.
            st = None
        if st is not None and (int(st.st_dev), int(st.st_ino)) != self._identity:
            self.close()
            self._open_from_start = True
            return "replaced"
        version = self._file_version()
        if version is not None and version[0] < self._offset:
            self._reset_cursor(self._handle, 0)
            return "truncated"
        self._idle_version = version
        return None


def run_batched_tail_loop(
    *,
    follower: LogFollower,
    stop_event: threading.Event,
    accept_line: Callable[[str], None],
    pending: Callable[[], int],
    flush: Callable[[], None],
    backoff: DatabaseWriteBackoff,
    commit_batch: int,
    commit_interval: float,
    poll_interval: float,
    logger: logging.Logger,
    log_key: str,
    label: str,
    pause_at_pending: int | None = None,
) -> None:
    """Tail ``follower`` until ``stop_event`` is set, flushing batched rows.

    ``accept_line`` buffers one line; ``pending`` reports buffered rows;
    ``flush`` writes them (raising on failure, leaving them buffered). Flushes
    happen at ``commit_batch`` rows, after ``commit_interval`` seconds, before
    following a replaced file, and on shutdown, gated by ``backoff`` while
    MySQL is unavailable. With ``pause_at_pending`` set, reading stops at that
    many buffered rows until a flush succeeds (lossless backpressure); without
    it the caller's ``accept_line`` owns its overflow policy.
    """
    last_commit = time.monotonic()

    def try_flush(reason: str, description: str, now: float) -> None:
        nonlocal last_commit
        try:
            flush()
        except DATABASE_ERRORS as exc:
            delay = backoff.record_failure(now)
            last_commit = now
            log_database_unavailable(
                logger,
                f"{log_key}.{reason}.db",
                f"{label} deferred {description} flush while MySQL is unavailable; retrying in about {delay:.1f}s",
                exc,
            )
        except Exception:
            last_commit = now
            log_exception_throttled(
                logger,
                f"{log_key}.{reason}",
                interval_seconds=300.0,
                message=f"{label} {description} flush failed",
            )
        else:
            backoff.record_success()
            last_commit = time.monotonic()

    try:
        while not stop_event.is_set():
            try:
                if not follower.ensure_open():
                    stop_event.wait(max(1.0, poll_interval))
                    continue
                while not stop_event.is_set():
                    if pause_at_pending is not None and pending() >= pause_at_pending:
                        now = time.monotonic()
                        if backoff.can_attempt(now):
                            try_flush("capacity_commit", "capacity", now)
                        if pending() >= pause_at_pending:
                            stop_event.wait(poll_interval)
                            continue
                    line = follower.read_line()
                    if line is not None:
                        try:
                            accept_line(line)
                        except Exception:
                            log_exception_throttled(
                                logger,
                                f"{log_key}.ingest",
                                interval_seconds=300.0,
                                message=f"{label} failed to parse a log line",
                            )
                        now = time.monotonic()
                        count = pending()
                        if (
                            count
                            and backoff.can_attempt(now)
                            and (
                                count >= commit_batch
                                or (now - last_commit) >= commit_interval
                            )
                        ):
                            try_flush("commit", "batch", now)
                        continue

                    now = time.monotonic()
                    if (
                        pending()
                        and backoff.can_attempt(now)
                        and (now - last_commit) >= commit_interval
                    ):
                        try_flush("idle_commit", "idle", now)
                    change = follower.poll_rotation()
                    if change == "replaced":
                        now = time.monotonic()
                        if pending() and backoff.can_attempt(now):
                            try_flush("rotate", "rotation", now)
                        break
                    if change == "truncated":
                        continue
                    stop_event.wait(poll_interval)
            except DATABASE_ERRORS as exc:
                log_database_unavailable(
                    logger,
                    f"{log_key}.loop.db",
                    f"{label} deferred database work while MySQL is unavailable",
                    exc,
                )
                stop_event.wait(max(5.0, poll_interval))
            except Exception:
                log_exception_throttled(
                    logger,
                    f"{log_key}.loop",
                    interval_seconds=300.0,
                    message=f"{label} loop failed",
                )
                stop_event.wait(max(1.0, poll_interval))
        if pending():
            try_flush("shutdown_flush", "shutdown", time.monotonic())
    finally:
        follower.close()
