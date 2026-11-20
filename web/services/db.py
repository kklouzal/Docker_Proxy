from __future__ import annotations

import contextlib
import logging
import math
import os
import random
import re
import threading
import time
from collections import UserDict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Self
from urllib.parse import unquote, urlparse

import pymysql  # type: ignore

from services.runtime_helpers import env_float as _env_float
from services.runtime_helpers import env_int as _env_int
from services.sql_identifiers import quote_mysql_identifier

if TYPE_CHECKING:
    from collections.abc import Generator, Iterable, Iterator, Sequence

MYSQL_DEFAULT_DB = "squid_proxy"
_MYSQL_CHARSET_RE = re.compile(r"^[A-Za-z0-9_]+$")
logger = logging.getLogger(__name__)

_MYSQL_CONNECT_RETRY_CODES = {1040, 2002, 2003, 2006, 2013}
_MYSQL_TRANSACTION_RETRY_CODES = {1205, 1213}
_MYSQL_DISCONNECT_CODES = {2006, 2013}


@dataclass(frozen=True)
class DatabaseConfig:
    host: str
    port: int = 3306
    user: str = "root"
    password: str = ""
    database: str = MYSQL_DEFAULT_DB
    charset: str = "utf8mb4"
    connect_timeout: int = 10
    read_timeout: int = 15
    write_timeout: int = 15
    create_database: bool = True


class CompatRow(UserDict[str, Any]):
    def __init__(self, columns: Sequence[str], values: Sequence[Any]) -> None:
        super().__init__(zip(columns, values, strict=False))
        self._values = tuple(values)
        self._columns = tuple(columns)

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, int):
            return self._values[key]
        return super().__getitem__(key)

    def keys(self):
        return super().keys()


class CompatResult:
    def __init__(
        self,
        cursor: Any,
        *,
        on_close: Any = None,
        on_error: Any = None,
        on_close_error: Any = None,
    ) -> None:
        self._cursor = cursor
        self._on_close = on_close
        self._on_error = on_error
        self._on_close_error = on_close_error
        self._closed = False
        self._columns = tuple(
            (d[0] if d else "") for d in (getattr(cursor, "description", None) or [])
        )
        self.rowcount = int(getattr(cursor, "rowcount", -1) or 0)
        self.lastrowid = getattr(cursor, "lastrowid", None)
        if not self._columns:
            self.close()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            try:
                self._cursor.close()
            except Exception as exc:
                if self._on_close_error is not None:
                    self._on_close_error(exc)
        finally:
            if self._on_close is not None:
                self._on_close(self)

    def _is_exhausted(self) -> bool:
        rownumber = getattr(self._cursor, "rownumber", None)
        return (
            isinstance(rownumber, int)
            and self.rowcount >= 0
            and rownumber >= self.rowcount
        )

    def _convert_row(self, row: Any) -> Any:
        if row is None:
            return None
        if isinstance(row, dict):
            columns = tuple(row.keys())
            return CompatRow(columns, [row[c] for c in columns])
        if isinstance(row, (list, tuple)):
            return CompatRow(self._columns, row)
        return row

    def _handle_fetch_error(self, exc: BaseException) -> None:
        if self._on_error is not None:
            self._on_error(exc)
        self.close()

    def fetchone(self) -> Any:
        try:
            row = self._cursor.fetchone()
        except Exception as exc:
            self._handle_fetch_error(exc)
            raise
        if row is None or self._is_exhausted():
            self.close()
        return self._convert_row(row)

    def fetchall(self) -> list[Any]:
        try:
            rows = self._cursor.fetchall()
        except Exception as exc:
            self._handle_fetch_error(exc)
            raise
        try:
            return [self._convert_row(r) for r in rows]
        finally:
            self.close()

    def __iter__(self) -> Iterator[Any]:
        while not self._closed:
            row = self.fetchone()
            if row is None:
                break
            yield row


class _EmptyCursor:
    description = None
    rowcount = 0
    lastrowid = None

    def close(self) -> None:
        pass

    def fetchone(self) -> None:
        return None

    def fetchall(self) -> list[Any]:
        return []


def _is_hung_session_error(exc: BaseException) -> bool:
    """A statement that hit the socket read/write timeout on an open session."""
    return mysql_error_code(exc) == 2013 and "timed out" in str(exc).lower()


class CompatConnection:
    def __init__(
        self,
        native: Any,
        cfg: DatabaseConfig | None = None,
        *,
        circuit: _ConnectCircuit | None = None,
    ) -> None:
        self.native = native
        self._cfg = cfg
        self._circuit = circuit
        self._closed = False
        self._discard_on_close = False
        self._results: set[CompatResult] = set()

    def _mark_discard_for_error(self, exc: BaseException) -> None:
        if _should_discard_native_connection(exc):
            self._discard_on_close = True
        if self._circuit is not None and _is_hung_session_error(exc):
            # Reused pooled sessions skip the liveness ping, so a hung server
            # shows up here first; let other callers fail fast meanwhile.
            self._circuit.record_failure(exc)

    def _mark_discard_for_result_close_error(self, _exc: BaseException) -> None:
        # A cursor can fail while draining an unread server-side result.  The
        # wire protocol/session state is then uncertain regardless of the
        # exception class, so the native connection must not re-enter the pool.
        self._discard_on_close = True

    def _result(self, cursor: Any) -> CompatResult:
        result = CompatResult(
            cursor,
            on_close=self._results.discard,
            on_error=self._mark_discard_for_error,
            on_close_error=self._mark_discard_for_result_close_error,
        )
        if not result._closed:
            self._results.add(result)
        return result

    def execute(self, sql: str, params: Sequence[Any] | None = None) -> CompatResult:
        if not (sql or "").strip():
            return CompatResult(_EmptyCursor())
        try:
            cur = self.native.cursor()
        except Exception as exc:
            self._mark_discard_for_error(exc)
            raise
        try:
            cur.execute(sql, tuple(params or ()))
        except Exception as exc:
            self._mark_discard_for_error(exc)
            with contextlib.suppress(Exception):
                cur.close()
            raise
        return self._result(cur)

    def executemany(
        self,
        sql: str,
        seq_of_params: Iterable[Sequence[Any]],
    ) -> CompatResult:
        if not (sql or "").strip():
            return CompatResult(_EmptyCursor())
        try:
            cur = self.native.cursor()
        except Exception as exc:
            self._mark_discard_for_error(exc)
            raise
        try:
            cur.executemany(sql, [tuple(p) for p in seq_of_params])
        except Exception as exc:
            self._mark_discard_for_error(exc)
            with contextlib.suppress(Exception):
                cur.close()
            raise
        return self._result(cur)

    def commit(self) -> None:
        try:
            self.native.commit()
        except Exception:
            self._discard_on_close = True
            raise

    def rollback(self) -> None:
        try:
            self.native.rollback()
        except Exception:
            self._discard_on_close = True
            raise

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for result in tuple(self._results):
            with contextlib.suppress(Exception):
                result.close()
        self._results.clear()
        if self._cfg is None:
            _close_native_connection(self.native)
            return
        if self._discard_on_close:
            key = _pool_key(self._cfg)
            _close_native_connection(self.native)
            with _pool_condition:
                _release_pool_slot_locked(key)
            return
        _return_connection(self._cfg, self.native)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        try:
            if exc_type is None:
                self.commit()
            else:
                try:
                    self.rollback()
                except Exception:
                    # If the transaction body already failed because the
                    # server closed/timed out the connection, PyMySQL can also
                    # fail while issuing ROLLBACK.  Discard the connection but
                    # preserve the original exception so callers see the real
                    # operation that failed instead of a secondary rollback
                    # error.
                    self._discard_on_close = True
        finally:
            self.close()
        return False


DATABASE_ERRORS: tuple[type[BaseException], ...] = (pymysql.MySQLError,)  # type: ignore[attr-defined]
INTEGRITY_ERRORS: tuple[type[BaseException], ...] = (pymysql.IntegrityError,)  # type: ignore[attr-defined]
OPERATIONAL_ERRORS: tuple[type[BaseException], ...] = (pymysql.OperationalError,)  # type: ignore[attr-defined]

# 4 MiB keeps each append statement near 0.2 s server-side for a ~59 MB
# adblock archive on MySQL 8.4 (measured), well under long_query_time=1 and
# far below max_allowed_packet even after PyMySQL literal escaping.
STAGED_BLOB_CHUNK_BYTES = 4 * 1024 * 1024
_STAGED_BLOB_VARIABLE = "@docker_proxy_staged_blob"


@contextlib.contextmanager
def staged_blob_parameter(
    conn: Any,
    payload: bytes,
    *,
    chunk_bytes: int | None = None,
) -> Generator[str]:
    """Stage a large binary value server-side; yield the SQL expression for it.

    PyMySQL interpolates parameters client-side, so a multi-MB blob otherwise
    becomes one literal that the server lexes inside a single statement (a
    59 MB archive took ~1.5 s and wrote a ~60 MB slow-log entry).  Appending
    bounded chunks to a session user variable keeps every statement short; the
    caller's single INSERT then references the variable, so InnoDB still
    writes the row (and its redo) exactly once and the row is never stored
    with a partial value.  The staged length is verified before use because
    CONCAT yields NULL past max_allowed_packet.  The variable is cleared
    afterwards so pooled sessions do not retain the payload.

    Yields:
        The session variable expression to use in place of a ``%s`` parameter.

    """
    data = bytes(payload or b"")
    step = max(1, int(STAGED_BLOB_CHUNK_BYTES if chunk_bytes is None else chunk_bytes))
    variable = _STAGED_BLOB_VARIABLE
    completed = False
    conn.execute(f"SET {variable} = %s", (b"",))
    try:
        for offset in range(0, len(data), step):
            conn.execute(
                f"SET {variable} = CONCAT({variable}, %s)",
                (data[offset : offset + step],),
            )
        row = conn.execute(f"SELECT LENGTH({variable}) AS staged_length").fetchone()
        staged_length = None if row is None else row["staged_length"]
        if staged_length is None or int(staged_length) != len(data):
            msg = (
                f"Staged blob length {staged_length!r} does not match the "
                f"{len(data)}-byte payload (max_allowed_packet too small?)."
            )
            raise pymysql.err.DataError(msg)  # type: ignore[attr-defined]
        yield variable
        completed = True
    finally:
        if completed:
            conn.execute(f"SET {variable} = NULL")
        else:
            # Preserve the primary failure; a failed reset leaves only session
            # memory behind, which the next staging overwrites.
            try:
                conn.execute(f"SET {variable} = NULL")
            except Exception:
                logger.warning(
                    "Could not clear the staged blob session variable after a failure.",
                    exc_info=True,
                )


@dataclass
class _PoolState:
    idle: list[tuple[float, Any]] = field(default_factory=list)
    active: int = 0


_mysql_ready_keys: set[tuple[str, int, str, str, str]] = set()
_mysql_ready_lock = threading.Lock()
_pool_condition = threading.Condition()
_pooled_connections: dict[
    tuple[str, int, str, str, str, str, int, int, int],
    _PoolState,
] = {}


def _safe_mysql_charset(value: str) -> str:
    charset = (value or "utf8mb4").strip() or "utf8mb4"
    if not _MYSQL_CHARSET_RE.fullmatch(charset):
        msg = f"Unsafe MySQL charset: {value!r}"
        raise ValueError(msg)
    return charset


def mysql_error_classification(exc: BaseException) -> str:
    code = mysql_error_code(exc)
    if isinstance(exc, pymysql.IntegrityError):
        return "integrity"
    if code == 1205:
        return "lock_wait_timeout"
    if code == 1213:
        return "deadlock"
    if isinstance(exc, pymysql.InterfaceError) and code in {None, 0}:
        return "connection_lost"
    if code in _MYSQL_DISCONNECT_CODES:
        return "connection_lost"
    if code in {2002, 2003}:
        return "connectivity"
    if code == 1040:
        return "pool_or_server_exhausted"
    if isinstance(exc, pymysql.MySQLError):
        return "mysql_error"
    return "non_mysql_error"


# Availability failures that a later retry can clear without operator action.
TRANSIENT_MYSQL_CLASSIFICATIONS = frozenset(
    {
        "connectivity",
        "connection_lost",
        "pool_or_server_exhausted",
        "lock_wait_timeout",
        "deadlock",
    },
)


def transient_mysql_cause(
    exc: BaseException,
    *,
    also: tuple[type[BaseException], ...] = (),
) -> BaseException | None:
    """Return the first transient MySQL failure (or ``also`` instance) in exc's cause chain."""
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, DATABASE_ERRORS):
            if mysql_error_classification(current) in TRANSIENT_MYSQL_CLASSIFICATIONS:
                return current
        elif also and isinstance(current, also):
            return current
        current = current.__cause__ or current.__context__
    return None


def _is_retryable_mysql_connect_error(exc: BaseException) -> bool:
    if not isinstance(exc, pymysql.MySQLError) or isinstance(
        exc, MySQLUnreachableError
    ):
        return False
    if isinstance(exc, pymysql.InterfaceError) and mysql_error_code(exc) in {None, 0}:
        return True
    return mysql_error_code(exc) in _MYSQL_CONNECT_RETRY_CODES


def _is_retryable_mysql_transaction_error(exc: BaseException) -> bool:
    if not isinstance(exc, pymysql.MySQLError):
        return False
    code = mysql_error_code(exc)
    return code in _MYSQL_TRANSACTION_RETRY_CODES


def is_mysql_lock_contention_error(exc: BaseException) -> bool:
    """Return whether MySQL unambiguously rejected work for lock contention."""
    return _is_retryable_mysql_transaction_error(exc)


def _should_discard_native_connection(exc: BaseException) -> bool:
    if isinstance(exc, pymysql.InterfaceError):
        return True
    if isinstance(exc, pymysql.OperationalError):
        return mysql_error_code(exc) in {2002, 2003, 2006, 2013}
    return False


def mysql_error_code(exc: BaseException) -> int | None:
    args = getattr(exc, "args", ())
    if not args:
        return None
    try:
        return int(args[0])
    except TypeError, ValueError:
        return None


def _mysql_connect_retries() -> int:
    return _env_int("MYSQL_CONNECT_RETRIES", 4, minimum=1, maximum=10)


def _mysql_connect_retry_delay_seconds() -> float:
    return _env_float(
        "MYSQL_CONNECT_RETRY_DELAY_SECONDS", 0.2, minimum=0.05, maximum=5.0
    )


def _mysql_retry_jitter_seconds() -> float:
    return _env_float("MYSQL_RETRY_JITTER_SECONDS", 0.05, minimum=0.0, maximum=1.0)


def _pool_acquire_timeout_seconds() -> float:
    return _env_float(
        "DB_POOL_ACQUIRE_TIMEOUT_SECONDS", 30.0, minimum=1.0, maximum=600.0
    )


def _retry_delay_seconds(attempt: int, base_delay: float) -> float:
    delay = min(5.0, float(base_delay) * (2 ** int(attempt)))
    jitter = _mysql_retry_jitter_seconds()
    if jitter > 0:
        delay = min(5.0, delay + random.uniform(0.0, jitter))  # ruff: ignore[suspicious-non-cryptographic-random-usage]
    return delay


def _retry_mysql_operation(
    operation,
    *,
    retry_predicate=_is_retryable_mysql_connect_error,
    operation_name: str = "mysql operation",
):
    attempts = _mysql_connect_retries()
    base_delay = _mysql_connect_retry_delay_seconds()
    last_exc: BaseException | None = None
    for attempt in range(attempts):
        try:
            return operation()
        except Exception as exc:
            last_exc = exc
            if not retry_predicate(exc) or attempt >= attempts - 1:
                raise
            delay = _retry_delay_seconds(attempt, base_delay)
            with contextlib.suppress(Exception):
                logger.warning(
                    "Retrying %s after transient MySQL %s (attempt %s/%s, delay %.3fs): %s",
                    operation_name,
                    mysql_error_classification(exc),
                    attempt + 1,
                    attempts,
                    delay,
                    exc,
                )
            time.sleep(delay)
    if last_exc is not None:
        raise last_exc
    msg = "MySQL operation failed"
    raise RuntimeError(msg)


def run_mysql_operation_with_retry(
    operation, *, operation_name: str = "mysql operation"
):
    """Retry a whole MySQL transaction only for unambiguous contention errors.

    This helper is only for explicitly idempotent operations that open a fresh
    connection/transaction and are safe to replay after MySQL reports
    ER_LOCK_WAIT_TIMEOUT (1205) or ER_LOCK_DEADLOCK (1213) before COMMIT. It
    intentionally does not retry lost connections (2006/2013/InterfaceError) or
    connection-acquisition failures (1040/2002/2003): callers that reached the
    transaction body may have partially executed or committed, and callers that
    could not obtain a connection should fail loudly instead of causing
    operation-level replay without proof that no transaction started.
    """
    return _retry_mysql_operation(
        operation,
        retry_predicate=_is_retryable_mysql_transaction_error,
        operation_name=operation_name,
    )


def run_mysql_lock_contention_with_retry(
    operation,
    *,
    attempts: int,
    base_delay_seconds: float,
    max_delay_seconds: float,
    operation_name: str = "mysql transaction",
    sleep_fn=None,
):
    """Replay a proven-safe operation only after MySQL 1205/1213 failures.

    Callers choose their bounded attempt/backoff policy. Disconnect, connection
    acquisition, and other operational errors are raised without replay.
    """
    attempt_count = max(1, int(attempts))
    sleeper = time.sleep if sleep_fn is None else sleep_fn
    for attempt in range(attempt_count):
        try:
            return operation()
        except Exception as exc:
            if not is_mysql_lock_contention_error(exc) or attempt >= attempt_count - 1:
                raise
            delay = min(
                max(0.0, float(max_delay_seconds)),
                max(0.0, float(base_delay_seconds)) * (2**attempt),
            )
            with contextlib.suppress(Exception):
                logger.warning(
                    "Retrying %s after transient MySQL %s (attempt %s/%s, delay %.3fs): %s",
                    operation_name,
                    mysql_error_classification(exc),
                    attempt + 1,
                    attempt_count,
                    delay,
                    exc,
                )
            sleeper(delay)
    msg = "unreachable MySQL lock-contention retry state"
    raise RuntimeError(msg)


def mysql_schema_lock_timeout_seconds(default: int = 30) -> int:
    return _env_int(
        "MYSQL_SCHEMA_LOCK_TIMEOUT_SECONDS",
        int(default),
        minimum=1,
        maximum=300,
    )


_NAMED_LOCK_READ_TIMEOUT_MARGIN_SECONDS = 2


def _named_lock_wait_slice_seconds(conn: Any, timeout_seconds: int) -> int:
    """Return a GET_LOCK wait slice that completes inside the client read timeout.

    GET_LOCK blocks server-side without sending bytes, so a single wait longer
    than the session's socket read timeout surfaces as 2013 "Lost connection
    (timed out)" instead of a lock timeout, discards the session, and is read
    by the connect circuit as a hung server. Connections without a known read
    timeout keep the single full-length wait.
    """
    read_timeout = getattr(getattr(conn, "native", None), "_read_timeout", None)
    try:
        read_timeout_seconds = int(read_timeout or 0)
    except TypeError, ValueError:
        read_timeout_seconds = 0
    if read_timeout_seconds <= 0:
        return timeout_seconds
    return max(
        1,
        min(
            timeout_seconds,
            read_timeout_seconds - _NAMED_LOCK_READ_TIMEOUT_MARGIN_SECONDS,
        ),
    )


def _lock_row_acquired(row: Any) -> int | None:
    """GET_LOCK result: 1 acquired, 0 timed out, None for an error or no row."""
    if row is None:
        return None
    try:
        value = row["acquired"]
    except IndexError, KeyError, TypeError:
        try:
            value = row[0]
        except IndexError, KeyError, TypeError:
            return None
    try:
        return None if value is None else int(value)
    except TypeError, ValueError:
        return None


def acquire_mysql_named_lock(conn: Any, name: str, timeout_seconds: int) -> bool:
    """Wait up to ``timeout_seconds`` for MySQL named lock ``name`` on ``conn``.

    The wait is issued as GET_LOCK slices that each finish inside the session's
    socket read timeout, so contention reports a lock timeout (False) rather
    than a lost connection. A GET_LOCK error result (NULL) stops at once.
    """
    timeout = max(0, int(timeout_seconds))
    poll_seconds = _named_lock_wait_slice_seconds(conn, timeout)
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        wait = max(0, min(poll_seconds, math.ceil(remaining)))
        acquired = _lock_row_acquired(
            conn.execute(
                "SELECT GET_LOCK(%s, %s) AS acquired", (name, wait)
            ).fetchone(),
        )
        if acquired == 1:
            return True
        if acquired is None or time.monotonic() >= deadline:
            return False


def release_mysql_named_lock(conn: Any, name: str) -> None:
    """Release named lock ``name`` held by ``conn`` without masking the caller.

    Named locks are session-scoped and survive COMMIT/ROLLBACK. When the
    release fails its outcome is unknown, so the session is marked for discard
    instead of returning to the pool still holding the lock; closing the
    physical connection then releases it server-side.
    """
    try:
        conn.execute("DO RELEASE_LOCK(%s)", (name,))
    except Exception:
        if hasattr(conn, "_discard_on_close"):
            conn._discard_on_close = True


@contextlib.contextmanager
def mysql_advisory_lock(
    conn: CompatConnection,
    name: str,
    timeout_seconds: int = 30,
):
    lock_name = str(name or "docker_proxy:schema")[:64]
    timeout = max(1, int(timeout_seconds or 30))
    if not acquire_mysql_named_lock(conn, lock_name, timeout):
        msg = f"Timed out waiting for MySQL advisory lock {lock_name!r}"
        raise TimeoutError(msg)
    try:
        yield
    finally:
        release_mysql_named_lock(conn, lock_name)


def _session_wait_timeout_seconds() -> int:
    return _env_int(
        "MYSQL_SESSION_WAIT_TIMEOUT",
        300,
        minimum=30,
        maximum=86400,
    )


def _configure_native_connection(native: Any, cfg: DatabaseConfig) -> None:
    """Apply defensive session settings once per physical connection.

    These guardrails keep application sessions from waiting indefinitely behind
    a stale transaction/metadata lock and make every connection deterministic.
    Session variables persist for the life of the physical connection, and no
    caller changes them, so pooled reuse does not re-apply them; pooled
    sessions never reconnect implicitly (a dead one is replaced by a new,
    freshly configured connection).
    """
    statements: list[tuple[str, tuple[Any, ...]]] = []
    lock_wait_timeout = _env_int("MYSQL_LOCK_WAIT_TIMEOUT", 10, minimum=1, maximum=300)
    innodb_lock_wait_timeout = _env_int(
        "MYSQL_INNODB_LOCK_WAIT_TIMEOUT",
        lock_wait_timeout,
        minimum=1,
        maximum=300,
    )
    wait_timeout = _session_wait_timeout_seconds()
    isolation = (
        (os.environ.get("MYSQL_TRANSACTION_ISOLATION") or "READ COMMITTED")
        .strip()
        .upper()
    )
    if isolation not in {
        "READ UNCOMMITTED",
        "READ COMMITTED",
        "REPEATABLE READ",
        "SERIALIZABLE",
    }:
        isolation = "READ COMMITTED"
    statements.extend(
        [
            ("SET SESSION innodb_lock_wait_timeout=%s", (innodb_lock_wait_timeout,)),
            ("SET SESSION lock_wait_timeout=%s", (lock_wait_timeout,)),
            ("SET SESSION wait_timeout=%s", (wait_timeout,)),
            (f"SET SESSION TRANSACTION ISOLATION LEVEL {isolation}", ()),
        ],
    )
    cur = native.cursor()
    try:
        for sql, params in statements:
            try:
                cur.execute(sql, params)
            except Exception:
                # Some MySQL/MariaDB variants may not support every setting.  The
                # connection is still usable; unsupported guardrails should not
                # prevent startup.
                pass
    finally:
        with contextlib.suppress(Exception):
            cur.close()
    # A failed rollback means the transaction/session state is unknown.  Never
    # hand that native connection to an application or return it to the pool.
    native.rollback()


def _rollback_native_connection(native: Any) -> bool:
    try:
        native.rollback()
        return True
    except Exception:
        return False


def _pool_key(
    cfg: DatabaseConfig,
) -> tuple[str, int, str, str, str, str, int, int, int]:
    return (
        cfg.host,
        int(cfg.port),
        cfg.user,
        cfg.password,
        cfg.database,
        cfg.charset,
        int(cfg.connect_timeout),
        int(cfg.read_timeout),
        int(cfg.write_timeout),
    )


def _mysql_ready_key(cfg: DatabaseConfig) -> tuple[str, int, str, str, str]:
    return (
        cfg.host,
        int(cfg.port),
        cfg.user,
        cfg.database,
        cfg.charset,
    )


def _pool_maxsize() -> int:
    raw = os.environ.get("DB_POOL_SIZE")
    if raw is not None and raw.strip():
        try:
            return max(0, min(32, int(raw.strip())))
        except Exception:
            return 1
    threads = _env_int("WEB_THREADS", 2, minimum=1, maximum=64)
    return max(4, min(16, threads + 4))


_POOL_IDLE_WAIT_TIMEOUT_MARGIN_SECONDS = 30.0


def _pool_max_idle_seconds() -> float:
    """Idle lifetime of a pooled connection (DB_POOL_MAX_IDLE_SECONDS, default 240).

    Always kept MYSQL_SESSION_WAIT_TIMEOUT minus a 30 s margin or lower, so the
    server never closes an idle pooled session before the pool retires it.
    """
    configured = _env_float("DB_POOL_MAX_IDLE_SECONDS", 240.0)
    server_bound = (
        float(_session_wait_timeout_seconds()) - _POOL_IDLE_WAIT_TIMEOUT_MARGIN_SECONDS
    )
    return max(1.0, min(configured, server_bound))


def _open_native_connection(cfg: DatabaseConfig) -> Any:
    return pymysql.connect(  # type: ignore[call-arg]
        host=cfg.host,
        port=int(cfg.port),
        user=cfg.user,
        password=cfg.password,
        database=cfg.database,
        charset=cfg.charset,
        autocommit=False,
        connect_timeout=int(cfg.connect_timeout),
        read_timeout=int(cfg.read_timeout),
        write_timeout=int(cfg.write_timeout),
    )


_TIMEOUT_EVIDENCE_FRACTION = 0.9


def _timed_out(started_mono: float, timeout_seconds: float) -> bool:
    return time.monotonic() - started_mono >= _TIMEOUT_EVIDENCE_FRACTION * float(
        timeout_seconds
    )


def _open_native_connection_with_retries(
    cfg: DatabaseConfig,
    *,
    caller_opened_circuit: bool = False,
) -> Any:
    """Open a connection with the bounded in-call retries, through the circuit.

    An attempt that fails only after (nearly) the whole connect timeout is
    evidence of a hung or black-holed server: it opens the circuit at once, so
    every other caller fails fast instead of each waiting MYSQL_CONNECT_TIMEOUT
    again. The caller that observed it keeps its own in-call retries, so a
    genuinely transient stall still recovers within the same call.
    """
    opened_here = caller_opened_circuit

    def attempt() -> Any:
        nonlocal opened_here
        circuit = _connect_circuit(cfg)
        if not opened_here:
            circuit.check()
        started = time.monotonic()
        try:
            return _open_native_connection(cfg)
        except Exception as exc:
            if _timed_out(started, cfg.connect_timeout) and circuit.record_failure(exc):
                opened_here = True
            raise

    return _retry_mysql_operation(attempt)


def _close_native_connection(native: Any) -> None:
    with contextlib.suppress(Exception):
        native.close()


def _clear_pooled_connections() -> None:
    with _pool_condition:
        buckets = list(_pooled_connections.values())
        _pooled_connections.clear()
    for bucket in buckets:
        for _ts, native in bucket.idle:
            _close_native_connection(native)


def _reap_pool_locked(now: float | None = None) -> None:
    current = time.monotonic() if now is None else float(now)
    max_idle = _pool_max_idle_seconds()
    stale_keys: list[tuple[str, int, str, str, str, str, int, int, int]] = []
    for key, state in _pooled_connections.items():
        keep: list[tuple[float, Any]] = []
        for last_used, native in state.idle:
            if (current - float(last_used)) > max_idle:
                _close_native_connection(native)
            else:
                keep.append((last_used, native))
        if keep:
            state.idle = keep[-_pool_maxsize() :]
        elif state.active <= 0:
            stale_keys.append(key)
    for key in stale_keys:
        _pooled_connections.pop(key, None)


def _release_pool_slot_locked(
    key: tuple[str, int, str, str, str, str, int, int, int],
) -> None:
    state = _pooled_connections.get(key)
    if state is not None:
        state.active = max(0, state.active - 1)
        if state.active <= 0 and not state.idle:
            _pooled_connections.pop(key, None)
    _pool_condition.notify_all()


_POOLED_PING_AFTER_IDLE_SECONDS = 5.0


def _checkout_connection(cfg: DatabaseConfig) -> Any:
    key = _pool_key(cfg)
    maxsize = _pool_maxsize()
    if maxsize <= 0:
        native = _open_native_connection_with_retries(cfg)
        try:
            _configure_native_connection(native, cfg)
            return native
        except Exception:
            _close_native_connection(native)
            raise

    deadline = time.monotonic() + _pool_acquire_timeout_seconds()
    opened_by_caller = False
    while True:
        source = ""
        native = None
        last_used = 0.0
        with _pool_condition:
            _reap_pool_locked()
            state = _pooled_connections.setdefault(key, _PoolState())
            while True:
                if state.idle:
                    last_used, native = state.idle.pop()
                    state.active += 1
                    source = "idle"
                    break
                if state.active < maxsize:
                    state.active += 1
                    source = "new"
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise pymysql.OperationalError(1040, "Database pool exhausted")
                _pool_condition.wait(timeout=min(remaining, 0.25))
                _reap_pool_locked()
                state = _pooled_connections.setdefault(key, _PoolState())

        if source == "idle":
            # Pooled sessions were rolled back successfully when returned
            # (_return_connection discards them otherwise) and keep their
            # once-per-connection session settings, so reuse needs neither a
            # ROLLBACK nor SETs. Only a session idle long enough to have been
            # dropped (server restart, network, NAT) is pinged first; a failure
            # after that on a just-used session surfaces to the caller as
            # connection_lost and the session is discarded.
            if time.monotonic() - last_used < _POOLED_PING_AFTER_IDLE_SECONDS:
                return native
            ping_started = time.monotonic()
            try:
                # No implicit reconnect: a dead pooled session is discarded and
                # replaced through the circuit-gated open below.
                native.ping(reconnect=False)
                return native
            except Exception as exc:
                if _timed_out(ping_started, cfg.read_timeout):
                    opened_by_caller = (
                        _connect_circuit(cfg).record_failure(exc) or opened_by_caller
                    )
                _close_native_connection(native)
                with _pool_condition:
                    _release_pool_slot_locked(key)
                continue

        try:
            native = _open_native_connection_with_retries(
                cfg,
                caller_opened_circuit=opened_by_caller,
            )
            _configure_native_connection(native, cfg)
            return native
        except Exception:
            if native is not None:
                _close_native_connection(native)
            with _pool_condition:
                _release_pool_slot_locked(key)
            raise


def _return_connection(cfg: DatabaseConfig, native: Any) -> None:
    maxsize = _pool_maxsize()
    if maxsize <= 0:
        _close_native_connection(native)
        return
    key = _pool_key(cfg)
    if not _rollback_native_connection(native):
        _close_native_connection(native)
        with _pool_condition:
            _release_pool_slot_locked(key)
        return
    with _pool_condition:
        state = _pooled_connections.setdefault(key, _PoolState())
        state.active = max(0, state.active - 1)
        if len(state.idle) < maxsize:
            state.idle.append((time.monotonic(), native))
        else:
            _close_native_connection(native)
        if state.active <= 0 and not state.idle:
            _pooled_connections.pop(key, None)
        _pool_condition.notify_all()


def _env_bool(name: str, default: str = "0") -> bool:
    v = (os.environ.get(name, default) or "").strip().lower()
    return v in {"1", "true", "yes", "on"}


def _parse_mysql_env_int(
    name: str,
    default: int,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    raw = (os.environ.get(name) or str(default)).strip() or str(default)
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        msg = f"Invalid {name} for MySQL configuration: {raw!r}"
        raise ValueError(msg) from exc
    if minimum is not None and value < minimum:
        msg = f"Invalid {name} for MySQL configuration: {value} < {minimum}"
        raise ValueError(msg)
    if maximum is not None and value > maximum:
        msg = f"Invalid {name} for MySQL configuration: {value} > {maximum}"
        raise ValueError(msg)
    return value


def _database_config_timeouts() -> dict[str, int]:
    return {
        "connect_timeout": _parse_mysql_env_int(
            "MYSQL_CONNECT_TIMEOUT",
            10,
            minimum=1,
        ),
        "read_timeout": _parse_mysql_env_int("MYSQL_READ_TIMEOUT", 15, minimum=1),
        "write_timeout": _parse_mysql_env_int("MYSQL_WRITE_TIMEOUT", 15, minimum=1),
    }


def _parse_database_url(url: str) -> DatabaseConfig:
    try:
        parsed = urlparse(url)
    except ValueError as exc:
        msg = "Invalid DATABASE_URL for MySQL configuration."
        raise ValueError(msg) from exc
    scheme = (parsed.scheme or "").lower()
    if not scheme.startswith("mysql"):
        msg = f"Unsupported DATABASE_URL scheme: {scheme}"
        raise ValueError(msg)

    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        msg = "Invalid DATABASE_URL for MySQL configuration."
        raise ValueError(msg) from exc

    db_name = (
        (parsed.path or "").lstrip("/")
        or os.environ.get("MYSQL_DATABASE")
        or MYSQL_DEFAULT_DB
    )
    return DatabaseConfig(
        host=hostname or os.environ.get("MYSQL_HOST") or "127.0.0.1",
        port=port
        if port is not None
        else _parse_mysql_env_int("MYSQL_PORT", 3306, minimum=1, maximum=65535),
        user=unquote(parsed.username or os.environ.get("MYSQL_USER") or "root"),
        password=unquote(parsed.password or os.environ.get("MYSQL_PASSWORD") or ""),
        database=db_name,
        charset=(os.environ.get("MYSQL_CHARSET") or "utf8mb4").strip() or "utf8mb4",
        **_database_config_timeouts(),
        create_database=_env_bool("MYSQL_CREATE_DATABASE", "1"),
    )


def resolve_database_config() -> DatabaseConfig:
    url = (os.environ.get("DATABASE_URL") or "").strip()
    if url:
        return _parse_database_url(url)

    mysql_host = (os.environ.get("MYSQL_HOST") or "").strip()
    mysql_db = (os.environ.get("MYSQL_DATABASE") or "").strip()
    mysql_user = (os.environ.get("MYSQL_USER") or "").strip()
    if not mysql_host and not mysql_db and not mysql_user:
        msg = "MySQL configuration is required. Set DATABASE_URL or MYSQL_HOST/MYSQL_DATABASE."
        raise RuntimeError(msg)

    return DatabaseConfig(
        host=mysql_host or "127.0.0.1",
        port=_parse_mysql_env_int("MYSQL_PORT", 3306, minimum=1, maximum=65535),
        user=mysql_user or "root",
        password=os.environ.get("MYSQL_PASSWORD") or "",
        database=mysql_db or MYSQL_DEFAULT_DB,
        charset=(os.environ.get("MYSQL_CHARSET") or "utf8mb4").strip() or "utf8mb4",
        **_database_config_timeouts(),
        create_database=_env_bool("MYSQL_CREATE_DATABASE", "1"),
    )


_CIRCUIT_TRIP_CLASSIFICATIONS = frozenset({"connectivity", "connection_lost"})


class MySQLUnreachableError(pymysql.OperationalError):  # type: ignore[misc,name-defined]
    """Raised without a network attempt while the connect circuit is open.

    Carries code 2003 so callers classify it as ``connectivity`` like any other
    unreachable-server error; in-call connect retries never replay it.
    """


class _ConnectCircuit:
    """Process-local MySQL reachability gate for one server/database target.

    Closed: connections are established normally, including the bounded
    in-call connect retries for transient blips. When establishment still fails
    with a connectivity-class error (2002/2003/2006/2013, InterfaceError 0) the
    circuit opens: further connect attempts in this process fail immediately
    with ``OperationalError(2003)`` instead of each paying
    ``MYSQL_CONNECT_RETRIES x MYSQL_CONNECT_TIMEOUT``. One daemon prober thread
    retries a single bounded connection with exponential backoff and jitter;
    the first successful probe closes the circuit and runs the registered
    recovery listeners so owners can resynchronize immediately.

    Local pool exhaustion (1040) and SQL/privilege errors never open it.
    """

    def __init__(self, cfg: DatabaseConfig) -> None:
        self.cfg = cfg
        self.lock = threading.Lock()
        self.open = False
        self.opened_mono = 0.0
        self.failures = 0
        self.stop = threading.Event()

    def check(self) -> None:
        with self.lock:
            if not self.open:
                return
            elapsed = time.monotonic() - self.opened_mono
        msg = (
            f"MySQL {self.cfg.host}:{self.cfg.port} is unreachable; new connection "
            f"attempts are paused while a background probe retries (down {elapsed:.0f}s)"
        )
        raise MySQLUnreachableError(2003, msg)

    def record_failure(self, exc: BaseException) -> bool:
        """Open the circuit for a connectivity failure; True if this call opened it."""
        if mysql_error_classification(exc) not in _CIRCUIT_TRIP_CLASSIFICATIONS:
            return False
        with self.lock:
            if self.open:
                return False
            self.open = True
            self.opened_mono = time.monotonic()
            self.failures = 1
            # Each outage gets its own stop event so a prober from an earlier
            # outage can never be revived by a later reopen.
            self.stop = threading.Event()
            prober = threading.Thread(
                target=self._probe_loop,
                args=(self.stop,),
                name="mysql-connect-probe",
                daemon=True,
            )
        with contextlib.suppress(Exception):
            logger.warning(
                "MySQL %s:%s unreachable (%s); pausing new connection attempts and "
                "probing in the background with backoff up to %.0fs",
                self.cfg.host,
                self.cfg.port,
                mysql_error_classification(exc),
                _circuit_backoff_max_seconds(),
            )
        try:
            prober.start()
        except Exception:
            # Without a prober nothing could ever close the circuit; stay on
            # the normal per-call retry path instead.
            with self.lock:
                self.open = False
                self.stop.set()
            logger.exception("Failed to start the MySQL reconnect probe")
            return False
        return True

    def record_success(self) -> None:
        with self.lock:
            if not self.open:
                return
        self._close()

    def _close(self) -> None:
        with self.lock:
            if not self.open:
                return
            self.open = False
            down = time.monotonic() - self.opened_mono
            self.failures = 0
            self.stop.set()
        with contextlib.suppress(Exception):
            logger.warning(
                "MySQL %s:%s reachable again after %.1fs; connections resumed",
                self.cfg.host,
                self.cfg.port,
                down,
            )
        _notify_mysql_recovery_listeners()

    def _probe_delay(self) -> float:
        base = _circuit_backoff_initial_seconds()
        cap = max(base, _circuit_backoff_max_seconds())
        delay = min(cap, base * (2 ** max(0, min(self.failures - 1, 30))))
        return max(0.05, delay * random.uniform(0.8, 1.2))  # ruff: ignore[suspicious-non-cryptographic-random-usage]

    def _probe_once(self) -> bool:
        try:
            native = _open_native_connection(self.cfg)
        except Exception as exc:
            # A reachable server rejecting the session (unknown database,
            # privileges, too many connections) is not a connectivity outage;
            # callers must see that error themselves.
            return mysql_error_classification(exc) not in _CIRCUIT_TRIP_CLASSIFICATIONS
        _close_native_connection(native)
        return True

    def _probe_loop(self, stop: threading.Event) -> None:
        while not stop.wait(self._probe_delay()):
            if self._probe_once():
                self._close()
                return
            with self.lock:
                if not self.open:
                    return
                self.failures += 1


def _circuit_backoff_initial_seconds() -> float:
    return _env_float(
        "MYSQL_CONNECT_CIRCUIT_BACKOFF_INITIAL_SECONDS",
        1.0,
        minimum=0.1,
        maximum=60.0,
    )


def _circuit_backoff_max_seconds() -> float:
    return _env_float(
        "MYSQL_CONNECT_CIRCUIT_BACKOFF_MAX_SECONDS",
        10.0,
        minimum=0.1,
        maximum=300.0,
    )


_connect_circuits: dict[tuple[str, int, str, str, str], _ConnectCircuit] = {}
_connect_circuits_lock = threading.Lock()
_mysql_recovery_listeners: list[Any] = []


def _connect_circuit(cfg: DatabaseConfig) -> _ConnectCircuit:
    key = _mysql_ready_key(cfg)
    with _connect_circuits_lock:
        circuit = _connect_circuits.get(key)
        if circuit is None:
            circuit = _ConnectCircuit(cfg)
            _connect_circuits[key] = circuit
        return circuit


def add_mysql_recovery_listener(callback) -> None:
    """Register a callback for MySQL becoming reachable again.

    ``callback()`` runs on the probe thread whenever this process observed MySQL
    unreachable and connectivity returns. Callbacks must be fast and
    non-blocking (for example, set an Event); exceptions are logged.
    """
    with _connect_circuits_lock:
        if callback not in _mysql_recovery_listeners:
            _mysql_recovery_listeners.append(callback)


def _notify_mysql_recovery_listeners() -> None:
    with _connect_circuits_lock:
        listeners = list(_mysql_recovery_listeners)
    for callback in listeners:
        try:
            callback()
        except Exception:
            logger.exception("MySQL recovery listener failed")


def _reset_connect_circuits() -> None:
    with _connect_circuits_lock:
        circuits = list(_connect_circuits.values())
        _connect_circuits.clear()
    for circuit in circuits:
        circuit.stop.set()


def _reinitialize_connect_circuits_after_fork() -> None:
    # A forked child inherits the parent's circuit state (and possibly a held
    # lock) but not its probe thread; start the child from a clean closed state.
    global _connect_circuits_lock
    _connect_circuits_lock = threading.Lock()
    _connect_circuits.clear()


os.register_at_fork(after_in_child=_reinitialize_connect_circuits_after_fork)


def _establish(cfg: DatabaseConfig, opener):
    circuit = _connect_circuit(cfg)
    circuit.check()
    try:
        _ensure_mysql_database(cfg)
        native = opener()
    except Exception as exc:
        circuit.record_failure(exc)
        raise
    circuit.record_success()
    return native


def connect(config: DatabaseConfig | None = None) -> CompatConnection:
    cfg = config or resolve_database_config()
    native = _establish(cfg, lambda: _checkout_connection(cfg))
    return CompatConnection(native, cfg=cfg, circuit=_connect_circuit(cfg))


def _open_configured_unpooled(cfg: DatabaseConfig) -> Any:
    native = _open_native_connection_with_retries(cfg)
    try:
        _configure_native_connection(native, cfg)
    except Exception:
        _close_native_connection(native)
        raise
    return native


def connect_unpooled(config: DatabaseConfig | None = None) -> CompatConnection:
    cfg = config or resolve_database_config()
    native = _establish(cfg, lambda: _open_configured_unpooled(cfg))
    return CompatConnection(native, cfg=None, circuit=_connect_circuit(cfg))


def _ensure_mysql_database(cfg: DatabaseConfig) -> None:
    ready_key = _mysql_ready_key(cfg)
    if (ready_key in _mysql_ready_keys) or not cfg.create_database:
        return
    with _mysql_ready_lock:
        if (ready_key in _mysql_ready_keys) or not cfg.create_database:
            return

        def _create_database() -> None:
            native = pymysql.connect(  # type: ignore[call-arg]
                host=cfg.host,
                port=int(cfg.port),
                user=cfg.user,
                password=cfg.password,
                charset=cfg.charset,
                autocommit=True,
                connect_timeout=int(cfg.connect_timeout),
                read_timeout=int(cfg.read_timeout),
                write_timeout=int(cfg.write_timeout),
            )
            cur = None
            try:
                cur = native.cursor()
                database = quote_mysql_identifier(cfg.database)
                charset = _safe_mysql_charset(cfg.charset)
                collation = _safe_mysql_charset(f"{charset}_unicode_ci")
                cur.execute(
                    f"CREATE DATABASE IF NOT EXISTS {database} CHARACTER SET {charset} COLLATE {collation}",
                )
            finally:
                if cur is not None:
                    with contextlib.suppress(Exception):
                        cur.close()
                native.close()

        _retry_mysql_operation(_create_database)
        _mysql_ready_keys.add(ready_key)


def table_exists(conn: CompatConnection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = %s LIMIT 1",
        (table_name,),
    ).fetchone()
    return row is not None


def reset_mysql_ready_for_tests() -> None:
    with _mysql_ready_lock:
        _mysql_ready_keys.clear()
    _clear_pooled_connections()
    _reset_connect_circuits()
