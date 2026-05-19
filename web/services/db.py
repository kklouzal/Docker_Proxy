from __future__ import annotations

import contextlib
import os
import threading
import time
from collections import UserDict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Self
from urllib.parse import unquote, urlparse

import pymysql  # type: ignore

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

MYSQL_DEFAULT_DB = "squid_proxy"


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
    def __init__(self, cursor: Any) -> None:
        self._cursor = cursor
        self._columns = tuple(
            (d[0] if d else "") for d in (getattr(cursor, "description", None) or [])
        )
        self.rowcount = int(getattr(cursor, "rowcount", -1) or 0)
        self.lastrowid = getattr(cursor, "lastrowid", None)

    def _convert_row(self, row: Any) -> Any:
        if row is None:
            return None
        if isinstance(row, dict):
            columns = tuple(row.keys())
            return CompatRow(columns, [row[c] for c in columns])
        if isinstance(row, (list, tuple)):
            return CompatRow(self._columns, row)
        return row

    def fetchone(self) -> Any:
        return self._convert_row(self._cursor.fetchone())

    def fetchall(self) -> list[Any]:
        return [self._convert_row(r) for r in self._cursor.fetchall()]


class _EmptyCursor:
    description = None
    rowcount = 0
    lastrowid = None

    def fetchone(self) -> None:
        return None

    def fetchall(self) -> list[Any]:
        return []


class CompatConnection:
    def __init__(self, native: Any, cfg: DatabaseConfig | None = None) -> None:
        self.native = native
        self._cfg = cfg
        self._closed = False
        self._discard_on_close = False

    def execute(self, sql: str, params: Sequence[Any] | None = None) -> CompatResult:
        if not (sql or "").strip():
            return CompatResult(_EmptyCursor())
        cur = self.native.cursor()
        cur.execute(sql, tuple(params or ()))
        return CompatResult(cur)

    def executemany(
        self,
        sql: str,
        seq_of_params: Iterable[Sequence[Any]],
    ) -> CompatResult:
        if not (sql or "").strip():
            return CompatResult(_EmptyCursor())
        cur = self.native.cursor()
        cur.executemany(sql, [tuple(p) for p in seq_of_params])
        return CompatResult(cur)

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
        if self._discard_on_close or self._cfg is None:
            _close_native_connection(self.native)
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


@dataclass
class _PoolState:
    idle: list[tuple[float, Any]] = field(default_factory=list)
    active: int = 0


_mysql_ready = False
_mysql_ready_lock = threading.Lock()
_pool_condition = threading.Condition()
_pooled_connections: dict[
    tuple[str, int, str, str, str, str, int, int, int],
    _PoolState,
] = {}


def _env_int(
    name: str,
    default: int,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    try:
        value = int((os.environ.get(name) or str(default)).strip() or str(default))
    except Exception:
        value = int(default)
    if minimum is not None:
        value = max(int(minimum), value)
    if maximum is not None:
        value = min(int(maximum), value)
    return value


def _is_retryable_mysql_error(exc: BaseException) -> bool:
    if not isinstance(exc, pymysql.MySQLError):
        return False
    code = None
    try:
        if getattr(exc, "args", None):
            code = int(exc.args[0])
    except Exception:
        code = None
    return code in {1040, 2002, 2003, 2006, 2013, 1205, 1213}


def _mysql_connect_retries() -> int:
    return _env_int("MYSQL_CONNECT_RETRIES", 4, minimum=1, maximum=10)


def _mysql_connect_retry_delay_seconds() -> float:
    try:
        return max(
            0.05,
            min(
                5.0,
                float(
                    (
                        os.environ.get("MYSQL_CONNECT_RETRY_DELAY_SECONDS") or "0.2"
                    ).strip()
                    or "0.2",
                ),
            ),
        )
    except Exception:
        return 0.2


def _pool_acquire_timeout_seconds() -> float:
    try:
        return max(
            1.0,
            min(
                600.0,
                float(
                    (os.environ.get("DB_POOL_ACQUIRE_TIMEOUT_SECONDS") or "30").strip()
                    or "30",
                ),
            ),
        )
    except Exception:
        return 30.0


def _retry_mysql_operation(operation):
    attempts = _mysql_connect_retries()
    base_delay = _mysql_connect_retry_delay_seconds()
    last_exc: BaseException | None = None
    for attempt in range(attempts):
        try:
            return operation()
        except Exception as exc:
            last_exc = exc
            if not _is_retryable_mysql_error(exc) or attempt >= attempts - 1:
                raise
            time.sleep(min(5.0, base_delay * (2**attempt)))
    if last_exc is not None:
        raise last_exc
    msg = "MySQL operation failed"
    raise RuntimeError(msg)


def _configure_native_connection(native: Any, cfg: DatabaseConfig) -> None:
    """Apply defensive per-session settings to every checked-out connection.

    These guardrails keep application sessions from waiting indefinitely behind
    a stale transaction/metadata lock and make pooled connections deterministic
    after reconnects.
    """
    statements: list[tuple[str, tuple[Any, ...]]] = []
    lock_wait_timeout = _env_int("MYSQL_LOCK_WAIT_TIMEOUT", 10, minimum=1, maximum=300)
    innodb_lock_wait_timeout = _env_int(
        "MYSQL_INNODB_LOCK_WAIT_TIMEOUT",
        lock_wait_timeout,
        minimum=1,
        maximum=300,
    )
    wait_timeout = _env_int(
        "MYSQL_SESSION_WAIT_TIMEOUT",
        300,
        minimum=30,
        maximum=86400,
    )
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
    for sql, params in statements:
        try:
            cur.execute(sql, params)
        except Exception:
            # Some MySQL/MariaDB variants may not support every setting.  The
            # connection is still usable; unsupported guardrails should not
            # prevent startup.
            pass
    with contextlib.suppress(Exception):
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


def _pool_maxsize() -> int:
    try:
        return max(
            0,
            min(16, int((os.environ.get("DB_POOL_SIZE") or "1").strip() or "1")),
        )
    except Exception:
        return 1


def _pool_max_idle_seconds() -> float:
    try:
        return max(
            1.0,
            min(
                300.0,
                float(
                    (os.environ.get("DB_POOL_MAX_IDLE_SECONDS") or "30").strip()
                    or "30",
                ),
            ),
        )
    except Exception:
        return 30.0


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
        else:
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


def _checkout_connection(cfg: DatabaseConfig) -> Any:
    key = _pool_key(cfg)
    maxsize = _pool_maxsize()
    if maxsize <= 0:
        native = _retry_mysql_operation(lambda: _open_native_connection(cfg))
        _configure_native_connection(native, cfg)
        return native

    deadline = time.monotonic() + _pool_acquire_timeout_seconds()
    while True:
        source = ""
        native = None
        with _pool_condition:
            _reap_pool_locked()
            state = _pooled_connections.setdefault(key, _PoolState())
            while True:
                if state.idle:
                    _last_used, native = state.idle.pop()
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
            try:
                native.ping(reconnect=True)
                _configure_native_connection(native, cfg)
                return native
            except Exception:
                _close_native_connection(native)
                with _pool_condition:
                    _release_pool_slot_locked(key)
                continue

        try:
            native = _retry_mysql_operation(lambda: _open_native_connection(cfg))
            _configure_native_connection(native, cfg)
            return native
        except Exception:
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


def _parse_database_url(url: str) -> DatabaseConfig:
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if not scheme.startswith("mysql"):
        msg = f"Unsupported DATABASE_URL scheme: {scheme}"
        raise ValueError(msg)

    db_name = (
        (parsed.path or "").lstrip("/")
        or os.environ.get("MYSQL_DATABASE")
        or MYSQL_DEFAULT_DB
    )
    return DatabaseConfig(
        host=parsed.hostname or os.environ.get("MYSQL_HOST") or "127.0.0.1",
        port=int(parsed.port or int(os.environ.get("MYSQL_PORT") or 3306)),
        user=unquote(parsed.username or os.environ.get("MYSQL_USER") or "root"),
        password=unquote(parsed.password or os.environ.get("MYSQL_PASSWORD") or ""),
        database=db_name,
        charset=(os.environ.get("MYSQL_CHARSET") or "utf8mb4").strip() or "utf8mb4",
        connect_timeout=int(
            (os.environ.get("MYSQL_CONNECT_TIMEOUT") or "10").strip() or "10",
        ),
        read_timeout=int(
            (os.environ.get("MYSQL_READ_TIMEOUT") or "15").strip() or "15",
        ),
        write_timeout=int(
            (os.environ.get("MYSQL_WRITE_TIMEOUT") or "15").strip() or "15",
        ),
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
        port=int((os.environ.get("MYSQL_PORT") or "3306").strip() or "3306"),
        user=mysql_user or "root",
        password=os.environ.get("MYSQL_PASSWORD") or "",
        database=mysql_db or MYSQL_DEFAULT_DB,
        charset=(os.environ.get("MYSQL_CHARSET") or "utf8mb4").strip() or "utf8mb4",
        connect_timeout=int(
            (os.environ.get("MYSQL_CONNECT_TIMEOUT") or "10").strip() or "10",
        ),
        read_timeout=int(
            (os.environ.get("MYSQL_READ_TIMEOUT") or "15").strip() or "15",
        ),
        write_timeout=int(
            (os.environ.get("MYSQL_WRITE_TIMEOUT") or "15").strip() or "15",
        ),
        create_database=_env_bool("MYSQL_CREATE_DATABASE", "1"),
    )


def connect(config: DatabaseConfig | None = None) -> CompatConnection:
    cfg = config or resolve_database_config()
    _ensure_mysql_database(cfg)
    native = _checkout_connection(cfg)
    return CompatConnection(native, cfg=cfg)


def _ensure_mysql_database(cfg: DatabaseConfig) -> None:
    global _mysql_ready
    if _mysql_ready or not cfg.create_database:
        return
    with _mysql_ready_lock:
        if _mysql_ready or not cfg.create_database:
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
            try:
                cur = native.cursor()
                cur.execute(
                    f"CREATE DATABASE IF NOT EXISTS `{cfg.database}` CHARACTER SET {cfg.charset} COLLATE {cfg.charset}_unicode_ci",
                )
            finally:
                native.close()

        _retry_mysql_operation(_create_database)
        _mysql_ready = True


def table_exists(conn: CompatConnection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = %s LIMIT 1",
        (table_name,),
    ).fetchone()
    return row is not None


def reset_mysql_ready_for_tests() -> None:
    global _mysql_ready
    with _mysql_ready_lock:
        _mysql_ready = False
    _clear_pooled_connections()
