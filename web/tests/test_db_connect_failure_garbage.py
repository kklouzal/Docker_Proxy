from __future__ import annotations

import gc
import socket

import pytest


def _refused_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def test_failed_connect_leaves_no_cyclic_garbage() -> None:
    from services import db

    port = _refused_port()
    attempts = 10
    gc.collect()
    gc.disable()
    try:
        for _ in range(attempts):
            with pytest.raises(db.pymysql.err.OperationalError):
                db._pymysql_connect(
                    host="127.0.0.1",
                    port=port,
                    user="nobody",
                    password="unused",
                    connect_timeout=1,
                )
        unreachable = gc.collect()
    finally:
        gc.enable()

    # Without clearing the failed attempt's frames each refused connect leaves
    # a ~27-object (~0.7 MiB) cycle around the half-built Connection that only
    # the cyclic GC frees; idle retry loops then accumulate it for minutes.
    assert unreachable < 3 * attempts
