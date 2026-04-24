from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Iterable, Sequence
from urllib.parse import unquote, urlparse

import pymysql  # type: ignore


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
    create_database: bool = True


class CompatRow(dict[str, Any]):
    def __init__(self, columns: Sequence[str], values: Sequence[Any]):
        super().__init__(zip(columns, values))
        self._values = tuple(values)
        self._columns = tuple(columns)

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, int):
            return self._values[key]
        return super().__getitem__(key)

    def keys(self):
        return super().keys()


class CompatResult:
    def __init__(self, cursor: Any):
        self._cursor = cursor
        self._columns = tuple((d[0] if d else "") for d in (getattr(cursor, "description", None) or []))
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
    def __init__(self, native: Any, cfg: DatabaseConfig | None = None):
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

    def executemany(self, sql: str, seq_of_params: Iterable[Sequence[Any]]) -> CompatResult:
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

    def __enter__(self) -> "CompatConnection":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        try:
            if exc_type is None:
                self.commit()
            else:
                self.rollback()
        finally:
            self.close()
        return False


DATABASE_ERRORS: tuple[type[BaseException], ...] = (pymysql.MySQLError,)  # type: ignore[attr-defined]
INTEGRITY_ERRORS: tuple[type[BaseException], ...] = (pymysql.IntegrityError,)  # type: ignore[attr-defined]
OPERATIONAL_ERRORS: tuple[type[BaseException], ...] = (pymysql.OperationalError,)  # type: ignore[attr-defined]


_mysql_ready = False
_mysql_ready_lock = threading.Lock()
_pool_lock = threading.Lock()
_pooled_connections: dict[tuple[str, int, str, str, str, str, int], list[tuple[float, Any]]] = {}


def _pool_key(cfg: DatabaseConfig) -> tuple[str, int, str, str, str, str, int]:
    return (
        cfg.host,
        int(cfg.port),
        cfg.user,
        cfg.password,
        cfg.database,
        cfg.charset,
        int(cfg.connect_timeout),
    )


def _pool_maxsize() -> int:
    try:
        return max(0, min(16, int((os.environ.get("DB_POOL_SIZE") or "2").strip() or "2")))
    except Exception:
        return 2


def _pool_max_idle_seconds() -> float:
    try:
        return max(1.0, min(300.0, float((os.environ.get("DB_POOL_MAX_IDLE_SECONDS") or "30").strip() or "30")))
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
    )


def _close_native_connection(native: Any) -> None:
    try:
        native.close()
    except Exception:
        pass


def _clear_pooled_connections() -> None:
    with _pool_lock:
        buckets = list(_pooled_connections.values())
        _pooled_connections.clear()
    for bucket in buckets:
        for _ts, native in bucket:
            _close_native_connection(native)


def _reap_pool_locked(now: float | None = None) -> None:
    current = time.monotonic() if now is None else float(now)
    max_idle = _pool_max_idle_seconds()
    stale_keys: list[tuple[str, int, str, str, str, str, int]] = []
    for key, bucket in _pooled_connections.items():
        keep: list[tuple[float, Any]] = []
        for last_used, native in bucket:
            if (current - float(last_used)) > max_idle:
                _close_native_connection(native)
            else:
                keep.append((last_used, native))
        if keep:
            _pooled_connections[key] = keep[-_pool_maxsize():]
        else:
            stale_keys.append(key)
    for key in stale_keys:
        _pooled_connections.pop(key, None)


def _checkout_connection(cfg: DatabaseConfig) -> Any:
    key = _pool_key(cfg)
    with _pool_lock:
        _reap_pool_locked()
        bucket = _pooled_connections.get(key) or []
        while bucket:
            _last_used, native = bucket.pop()
            _pooled_connections[key] = bucket
            try:
                native.ping(reconnect=True)
                return native
            except Exception:
                _close_native_connection(native)
        if not bucket:
            _pooled_connections.pop(key, None)
    return _open_native_connection(cfg)


def _return_connection(cfg: DatabaseConfig, native: Any) -> None:
    maxsize = _pool_maxsize()
    if maxsize <= 0:
        _close_native_connection(native)
        return
    key = _pool_key(cfg)
    with _pool_lock:
        _reap_pool_locked()
        bucket = _pooled_connections.setdefault(key, [])
        bucket.append((time.monotonic(), native))
        while len(bucket) > maxsize:
            _ts, old = bucket.pop(0)
            _close_native_connection(old)


def _env_bool(name: str, default: str = "0") -> bool:
    v = (os.environ.get(name, default) or "").strip().lower()
    return v in ("1", "true", "yes", "on")


def _parse_database_url(url: str) -> DatabaseConfig:
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if not scheme.startswith("mysql"):
        raise ValueError(f"Unsupported DATABASE_URL scheme: {scheme}")

    db_name = (parsed.path or "").lstrip("/") or os.environ.get("MYSQL_DATABASE") or MYSQL_DEFAULT_DB
    return DatabaseConfig(
        host=parsed.hostname or os.environ.get("MYSQL_HOST") or "127.0.0.1",
        port=int(parsed.port or int(os.environ.get("MYSQL_PORT") or 3306)),
        user=unquote(parsed.username or os.environ.get("MYSQL_USER") or "root"),
        password=unquote(parsed.password or os.environ.get("MYSQL_PASSWORD") or ""),
        database=db_name,
        charset=(os.environ.get("MYSQL_CHARSET") or "utf8mb4").strip() or "utf8mb4",
        connect_timeout=int((os.environ.get("MYSQL_CONNECT_TIMEOUT") or "10").strip() or "10"),
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
        raise RuntimeError("MySQL configuration is required. Set DATABASE_URL or MYSQL_HOST/MYSQL_DATABASE.")

    return DatabaseConfig(
        host=mysql_host or "127.0.0.1",
        port=int((os.environ.get("MYSQL_PORT") or "3306").strip() or "3306"),
        user=mysql_user or "root",
        password=os.environ.get("MYSQL_PASSWORD") or "",
        database=mysql_db or MYSQL_DEFAULT_DB,
        charset=(os.environ.get("MYSQL_CHARSET") or "utf8mb4").strip() or "utf8mb4",
        connect_timeout=int((os.environ.get("MYSQL_CONNECT_TIMEOUT") or "10").strip() or "10"),
        create_database=_env_bool("MYSQL_CREATE_DATABASE", "1"),
    )


def connect() -> CompatConnection:
    cfg = resolve_database_config()
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
        native = pymysql.connect(  # type: ignore[call-arg]
            host=cfg.host,
            port=int(cfg.port),
            user=cfg.user,
            password=cfg.password,
            charset=cfg.charset,
            autocommit=True,
            connect_timeout=int(cfg.connect_timeout),
        )
        try:
            cur = native.cursor()
            cur.execute(
                f"CREATE DATABASE IF NOT EXISTS `{cfg.database}` CHARACTER SET {cfg.charset} COLLATE {cfg.charset}_unicode_ci"
            )
        finally:
            native.close()
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
