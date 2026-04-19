from __future__ import annotations

import os
import re
import threading
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
    def __init__(self, native: Any):
        self.native = native

    def execute(self, sql: str, params: Sequence[Any] | None = None) -> CompatResult:
        translated = translate_sql(sql)
        if not translated.strip():
            return CompatResult(_EmptyCursor())
        cur = self.native.cursor()
        cur.execute(translated, tuple(params or ()))
        return CompatResult(cur)

    def executemany(self, sql: str, seq_of_params: Iterable[Sequence[Any]]) -> CompatResult:
        translated = translate_sql(sql)
        if not translated.strip():
            return CompatResult(_EmptyCursor())
        cur = self.native.cursor()
        cur.executemany(translated, [tuple(p) for p in seq_of_params])
        return CompatResult(cur)

    def commit(self) -> None:
        self.native.commit()

    def rollback(self) -> None:
        self.native.rollback()

    def close(self) -> None:
        self.native.close()

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
    native = pymysql.connect(  # type: ignore[call-arg]
        host=cfg.host,
        port=int(cfg.port),
        user=cfg.user,
        password=cfg.password,
        database=cfg.database,
        charset=cfg.charset,
        autocommit=False,
        connect_timeout=int(cfg.connect_timeout),
    )
    return CompatConnection(native)


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


def translate_sql(sql: str) -> str:
    s = sql or ""

    if re.match(r"^\s*PRAGMA\b", s, flags=re.I):
        return ""

    s = re.sub(r"\bINSERT\s+OR\s+IGNORE\s+INTO\b", "INSERT IGNORE INTO", s, flags=re.I)
    s = re.sub(r"\bINSERT\s+OR\s+REPLACE\s+INTO\b", "REPLACE INTO", s, flags=re.I)
    s = s.replace("AUTOINCREMENT", "AUTO_INCREMENT")

    m = re.search(r"ON\s+CONFLICT\s*\([^)]+\)\s*DO\s+UPDATE\s+SET\s*(.+?)(;?\s*)$", s, flags=re.I | re.S)
    if m:
        update_clause = m.group(1)
        update_clause = re.sub(r"excluded\.([A-Za-z0-9_]+)", r"VALUES(\1)", update_clause, flags=re.I)
        update_clause = re.sub(r"\bMIN\(", "LEAST(", update_clause, flags=re.I)
        update_clause = re.sub(r"\bMAX\(", "GREATEST(", update_clause, flags=re.I)
        s = s[: m.start()] + "ON DUPLICATE KEY UPDATE " + update_clause + m.group(2)

    return s.replace("?", "%s")


def table_exists(conn: CompatConnection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ? LIMIT 1",
        (table_name,),
    ).fetchone()
    return row is not None


def column_exists(conn: CompatConnection, table_name: str, column_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ? LIMIT 1",
        (table_name, column_name),
    ).fetchone()
    return row is not None


def index_exists(conn: CompatConnection, index_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND index_name = ? LIMIT 1",
        (index_name,),
    ).fetchone()
    return row is not None


def create_index_if_not_exists(
    conn: CompatConnection,
    *,
    table_name: str,
    index_name: str,
    columns_sql: str,
    unique: bool = False,
) -> None:
    if index_exists(conn, index_name):
        return
    unique_sql = "UNIQUE " if unique else ""
    conn.execute(f"CREATE {unique_sql}INDEX {index_name} ON {table_name}({columns_sql})")


def reset_mysql_ready_for_tests() -> None:
    global _mysql_ready
    with _mysql_ready_lock:
        _mysql_ready = False
