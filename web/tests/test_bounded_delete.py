from __future__ import annotations

import pytest
from services.bounded_delete import delete_where_in_chunks


class _Result:
    def __init__(self, rowcount: int) -> None:
        self.rowcount = rowcount


class _Conn:
    def __init__(self, owner: _Factory, *, fail: bool = False) -> None:
        self.owner = owner
        self.fail = fail
        self.queries: list[tuple[str, tuple[object, ...]]] = []
        self.committed = False
        self.rolled_back = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, _exc, _tb):
        if exc_type is None:
            self.committed = True
        else:
            self.rolled_back = True
        return False

    def execute(self, sql, params=()):
        self.queries.append((" ".join(str(sql).split()), tuple(params or ())))
        if self.fail:
            msg = "delete failed"
            raise RuntimeError(msg)
        return _Result(self.owner.rowcounts.pop(0))


class _Factory:
    def __init__(self, rowcounts: list[int], *, fail_on_call: int | None = None) -> None:
        self.rowcounts = rowcounts
        self.fail_on_call = fail_on_call
        self.calls = 0
        self.conns: list[_Conn] = []

    def __call__(self):
        self.calls += 1
        conn = _Conn(self, fail=self.fail_on_call == self.calls)
        self.conns.append(conn)
        return conn


def test_delete_where_in_chunks_progresses_without_offset_and_honors_max_rows() -> None:
    factory = _Factory([2, 2, 1])

    result = delete_where_in_chunks(
        factory,
        table="audit_events",
        where_sql="ts < %s",
        params=(123,),
        order_by_columns=("ts", "id"),
        chunk_size=2,
        max_rows=5,
    )

    assert result.deleted_rows == 5
    assert result.iterations == 3
    assert result.truncated is True
    assert [conn.queries[0][1][-1] for conn in factory.conns] == [2, 2, 1]
    assert all(" OFFSET " not in conn.queries[0][0].upper() for conn in factory.conns)
    assert all("ORDER BY `ts` ASC, `id` ASC" in conn.queries[0][0] for conn in factory.conns)


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


def test_delete_where_in_chunks_rolls_back_failing_chunk_and_stops() -> None:
    factory = _Factory([2], fail_on_call=2)

    with pytest.raises(RuntimeError, match="delete failed"):
        delete_where_in_chunks(
            factory,
            table="adblock_events",
            where_sql="ts < %s",
            params=(789,),
            order_by_columns=("ts", "id"),
            chunk_size=2,
            max_rows=10,
        )

    assert factory.calls == 2
    assert factory.conns[0].committed is True
    assert factory.conns[0].rolled_back is False
    assert factory.conns[1].committed is False
    assert factory.conns[1].rolled_back is True
