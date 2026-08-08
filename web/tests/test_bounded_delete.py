from __future__ import annotations

import logging

import pytest
from services.bounded_delete import (
    BoundedDeleteIncompleteError,
    delete_where_in_chunks,
)


class _Result:
    def __init__(self, rowcount: int, *, row: object | None = None) -> None:
        self.rowcount = rowcount
        self.row = row

    def fetchone(self):
        return self.row


class _Conn:
    def __init__(
        self,
        owner: _Factory,
        *,
        fail: bool = False,
        fail_on_exit: bool = False,
    ) -> None:
        self.owner = owner
        self.fail = fail
        self.fail_on_exit = fail_on_exit
        self.queries: list[tuple[str, tuple[object, ...]]] = []
        self.committed = False
        self.rolled_back = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, _exc, _tb):
        if exc_type is None:
            if self.fail_on_exit:
                msg = "Lost connection to MySQL server during commit"
                raise RuntimeError(msg)
            self.committed = True
        else:
            self.rolled_back = True
        return False

    def execute(self, sql, params=()):
        normalized_sql = " ".join(str(sql).split())
        self.queries.append((normalized_sql, tuple(params or ())))
        if self.fail:
            msg = "delete failed"
            raise RuntimeError(msg)
        if normalized_sql.upper().startswith("SELECT 1 FROM"):
            return _Result(0, row=(1,) if self.owner.remaining_match else None)
        return _Result(self.owner.rowcounts.pop(0))


class _Factory:
    def __init__(
        self,
        rowcounts: list[int],
        *,
        fail_on_call: int | None = None,
        fail_on_exit_call: int | None = None,
        remaining_match: bool = False,
    ) -> None:
        self.rowcounts = rowcounts
        self.fail_on_call = fail_on_call
        self.fail_on_exit_call = fail_on_exit_call
        self.remaining_match = remaining_match
        self.calls = 0
        self.conns: list[_Conn] = []

    def __call__(self):
        self.calls += 1
        conn = _Conn(
            self,
            fail=self.fail_on_call == self.calls,
            fail_on_exit=self.fail_on_exit_call == self.calls,
        )
        self.conns.append(conn)
        return conn


def test_delete_where_in_chunks_exact_cap_without_remainder_is_not_truncated(
    caplog: pytest.LogCaptureFixture,
) -> None:
    factory = _Factory([2, 2, 1])

    with caplog.at_level(logging.WARNING, logger="services.bounded_delete"):
        result = delete_where_in_chunks(
            factory,
            table="audit_events",
            where_sql="ts < %s",
            params=(123,),
            order_by_columns=("ts", "id"),
            chunk_size=2,
            max_rows=5,
            log_key="audit.prune",
        )

    assert result.deleted_rows == 5
    assert result.iterations == 3
    assert result.truncated is False
    assert factory.calls == 3
    assert [conn.queries[0][1][-1] for conn in factory.conns] == [2, 2, 1]
    assert all(" OFFSET " not in conn.queries[0][0].upper() for conn in factory.conns)
    assert all(
        "ORDER BY `ts` ASC, `id` ASC" in conn.queries[0][0] for conn in factory.conns
    )
    assert factory.conns[2].queries[1] == (
        "SELECT 1 FROM `audit_events` WHERE ts < %s LIMIT 1",
        (123,),
    )
    assert "remaining rows will be cleaned up later" not in caplog.text


def test_delete_where_in_chunks_exact_cap_with_remainder_is_truncated(
    caplog: pytest.LogCaptureFixture,
) -> None:
    factory = _Factory([2, 2, 1], remaining_match=True)

    with caplog.at_level(logging.WARNING, logger="services.bounded_delete"):
        result = delete_where_in_chunks(
            factory,
            table="audit_events",
            where_sql="ts < %s",
            params=(123,),
            order_by_columns=("ts", "id"),
            chunk_size=2,
            max_rows=5,
            log_key="audit.prune",
            log_label="Audit prune",
        )

    assert result.deleted_rows == 5
    assert result.iterations == 3
    assert result.truncated is True
    assert factory.calls == 3
    assert len(factory.conns[2].queries) == 2
    assert "Audit prune reached max_rows=5" in caplog.text
    assert "remaining rows will be cleaned up later" in caplog.text


def test_delete_where_in_chunks_stops_on_short_chunk() -> None:
    factory = _Factory([2, 1, 99])

    result = delete_where_in_chunks(
        factory,
        table="diagnostic_requests",
        where_sql="ts < %s",
        params=(456,),
        order_by_columns=("ts", "id"),
        chunk_size=2,
        max_rows=10,
    )

    assert result.deleted_rows == 3
    assert result.iterations == 2
    assert result.truncated is False
    assert factory.calls == 2


def test_delete_where_in_chunks_reports_confirmed_progress_after_later_failure() -> (
    None
):
    factory = _Factory([2], fail_on_call=2)

    with pytest.raises(BoundedDeleteIncompleteError, match="delete failed") as raised:
        delete_where_in_chunks(
            factory,
            table="adblock_events",
            where_sql="ts < %s",
            params=(789,),
            order_by_columns=("ts", "id"),
            chunk_size=2,
            max_rows=10,
        )

    assert raised.value.deleted_rows == 2
    assert raised.value.iterations == 1
    assert raised.value.outcome_uncertain is False
    assert factory.calls == 2
    assert factory.conns[0].committed is True
    assert factory.conns[0].rolled_back is False
    assert factory.conns[1].committed is False
    assert factory.conns[1].rolled_back is True


def test_delete_where_in_chunks_reports_commit_unknown_without_replaying_chunk() -> (
    None
):
    factory = _Factory([2, 99], fail_on_exit_call=1)

    with pytest.raises(
        BoundedDeleteIncompleteError,
        match=r"Lost connection.*during commit",
    ) as raised:
        delete_where_in_chunks(
            factory,
            table="adblock_events",
            where_sql="ts < %s",
            params=(789,),
            order_by_columns=("ts", "id"),
            chunk_size=2,
            max_rows=10,
        )

    assert raised.value.deleted_rows == 0
    assert raised.value.iterations == 0
    assert raised.value.outcome_uncertain is True
    assert factory.calls == 1
    assert len(factory.conns[0].queries) == 1
