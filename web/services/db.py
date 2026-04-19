from __future__ import annotations

import os
import re
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence
from urllib.parse import unquote, urlparse

try:
    import pymysql  # type: ignore
except Exception:  # pragma: no cover - import tested indirectly at runtime
    pymysql = None  # type: ignore[assignment]


MYSQL_DEFAULT_DB = "squid_proxy"


@dataclass(frozen=True)
class DatabaseConfig:
    backend: str
    sqlite_path: Optional[str] = None
    host: str = ""
    port: int = 3306
    user: str = ""
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
        return self._columns


class CompatResult:
    def __init__(self, cursor: Any):
        self._cursor = cursor
        self._columns = tuple((d[0] if d else "") for d in (getattr(cursor, "description", None) or []))
        self.rowcount = int(getattr(cursor, "rowcount", -1) or 0)
        self.lastrowid = getattr(cursor, "lastrowid", None)

    def _convert_row(self, row: Any) -> Any:
        if row is None:
            return None
        if isinstance(row, sqlite3.Row):
            columns = tuple(row.keys())
            return CompatRow(columns, [row[c] for c in columns])
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
    def __init__(self, native: Any, backend: str):
        self.native = native
        self.backend = backend

    @property
    def is_mysql(self) -> bool:
        return self.backend == "mysql"

    @property
    def is_sqlite(self) -> bool:
        return self.backend == "sqlite"

    def execute(self, sql: str, params: Sequence[Any] | None = None) -> CompatResult:
        translated = translate_sql(sql, self.backend)
        if not translated.strip():
            return CompatResult(_EmptyCursor())
        params = tuple(params or ())
        if self.is_mysql:
            cur = self.native.cursor()
            cur.execute(translated, params)
            return CompatResult(cur)
        cur = self.native.execute(translated, params)
        return CompatResult(cur)

    def executemany(self, sql: str, seq_of_params: Iterable[Sequence[Any]]) -> CompatResult:
        translated = translate_sql(sql, self.backend)
        if not translated.strip():
            return CompatResult(_EmptyCursor())
        if self.is_mysql:
            cur = self.native.cursor()
            cur.executemany(translated, [tuple(p) for p in seq_of_params])
            return CompatResult(cur)
        cur = self.native.executemany(translated, [tuple(p) for p in seq_of_params])
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


_DATABASE_ERRORS: tuple[type[BaseException], ...] = (sqlite3.DatabaseError,)
_INTEGRITY_ERRORS: tuple[type[BaseException], ...] = (sqlite3.IntegrityError,)
_OPERATIONAL_ERRORS: tuple[type[BaseException], ...] = (sqlite3.OperationalError,)
if pymysql is not None:
    _DATABASE_ERRORS = _DATABASE_ERRORS + (pymysql.MySQLError,)  # type: ignore[attr-defined]
    _INTEGRITY_ERRORS = _INTEGRITY_ERRORS + (pymysql.IntegrityError,)  # type: ignore[attr-defined]
    _OPERATIONAL_ERRORS = _OPERATIONAL_ERRORS + (pymysql.OperationalError,)  # type: ignore[attr-defined]

DATABASE_ERRORS = _DATABASE_ERRORS
INTEGRITY_ERRORS = _INTEGRITY_ERRORS
OPERATIONAL_ERRORS = _OPERATIONAL_ERRORS


_mysql_ready = False
_mysql_ready_lock = threading.Lock()


def _env_bool(name: str, default: str = "0") -> bool:
    v = (os.environ.get(name, default) or "").strip().lower()
    return v in ("1", "true", "yes", "on")


def _parse_database_url(url: str) -> DatabaseConfig:
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme.startswith("sqlite"):
        raw_path = parsed.path or ""
        if raw_path.startswith("///"):
            raw_path = raw_path[1:]
        path = unquote(raw_path)
        if os.name == "nt" and path.startswith("/") and len(path) > 2 and path[2] == ":":
            path = path[1:]
        return DatabaseConfig(backend="sqlite", sqlite_path=path)

    if not scheme.startswith("mysql"):
        raise ValueError(f"Unsupported DATABASE_URL scheme: {scheme}")

    db_name = (parsed.path or "").lstrip("/") or os.environ.get("MYSQL_DATABASE") or MYSQL_DEFAULT_DB
    return DatabaseConfig(
        backend="mysql",
        host=parsed.hostname or os.environ.get("MYSQL_HOST") or "127.0.0.1",
        port=int(parsed.port or int(os.environ.get("MYSQL_PORT") or 3306)),
        user=unquote(parsed.username or os.environ.get("MYSQL_USER") or "root"),
        password=unquote(parsed.password or os.environ.get("MYSQL_PASSWORD") or ""),
        database=db_name,
        charset=(os.environ.get("MYSQL_CHARSET") or "utf8mb4").strip() or "utf8mb4",
        connect_timeout=int((os.environ.get("MYSQL_CONNECT_TIMEOUT") or "10").strip() or "10"),
        create_database=_env_bool("MYSQL_CREATE_DATABASE", "1"),
    )


def resolve_database_config(default_sqlite_path: Optional[str] = None) -> DatabaseConfig:
    url = (os.environ.get("DATABASE_URL") or "").strip()
    if url:
        return _parse_database_url(url)

    mysql_host = (os.environ.get("MYSQL_HOST") or "").strip()
    mysql_db = (os.environ.get("MYSQL_DATABASE") or os.environ.get("MYSQL_DB") or "").strip()
    if mysql_host or mysql_db:
        return DatabaseConfig(
            backend="mysql",
            host=mysql_host or "127.0.0.1",
            port=int((os.environ.get("MYSQL_PORT") or "3306").strip() or "3306"),
            user=(os.environ.get("MYSQL_USER") or "root").strip() or "root",
            password=os.environ.get("MYSQL_PASSWORD") or "",
            database=mysql_db or MYSQL_DEFAULT_DB,
            charset=(os.environ.get("MYSQL_CHARSET") or "utf8mb4").strip() or "utf8mb4",
            connect_timeout=int((os.environ.get("MYSQL_CONNECT_TIMEOUT") or "10").strip() or "10"),
            create_database=_env_bool("MYSQL_CREATE_DATABASE", "1"),
        )

    return DatabaseConfig(backend="sqlite", sqlite_path=default_sqlite_path or ":memory:")


def using_mysql(default_sqlite_path: Optional[str] = None) -> bool:
    return resolve_database_config(default_sqlite_path=default_sqlite_path).backend == "mysql"


def connect(default_sqlite_path: Optional[str] = None) -> CompatConnection:
    cfg = resolve_database_config(default_sqlite_path=default_sqlite_path)
    if cfg.backend == "sqlite":
        path = cfg.sqlite_path or ":memory:"
        path_obj = Path(path)
        db_dir = path_obj.parent if str(path_obj.parent) not in ("", ".") else None
        if db_dir is not None:
            db_dir.mkdir(parents=True, exist_ok=True)
        native = sqlite3.connect(path, timeout=30, check_same_thread=False)
        native.row_factory = sqlite3.Row
        native.execute("PRAGMA journal_mode=WAL")
        native.execute("PRAGMA synchronous=NORMAL")
        native.execute("PRAGMA busy_timeout=30000")
        native.execute("PRAGMA foreign_keys=ON")
        return CompatConnection(native, "sqlite")

    if pymysql is None:  # pragma: no cover - depends on runtime package availability
        raise RuntimeError("PyMySQL is not installed but MySQL configuration was requested.")

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
    return CompatConnection(native, "mysql")


def _ensure_mysql_database(cfg: DatabaseConfig) -> None:
    global _mysql_ready
    if _mysql_ready or not cfg.create_database:
        return
    with _mysql_ready_lock:
        if _mysql_ready or not cfg.create_database:
            return
        if pymysql is None:  # pragma: no cover
            raise RuntimeError("PyMySQL is not installed but MySQL configuration was requested.")
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


def translate_sql(sql: str, backend: str) -> str:
    s = sql or ""
    if backend != "mysql":
        return s

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

    s = s.replace("?", "%s")
    return s


def table_exists(conn: CompatConnection, table_name: str) -> bool:
    if conn.is_sqlite:
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,),
        ).fetchone()
        return row is not None
    row = conn.execute(
        "SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = %s LIMIT 1",
        (table_name,),
    ).fetchone()
    return row is not None


def column_exists(conn: CompatConnection, table_name: str, column_name: str) -> bool:
    if conn.is_sqlite:
        rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        return any(str(r[1]) == column_name for r in rows)
    row = conn.execute(
        "SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = %s AND column_name = %s LIMIT 1",
        (table_name, column_name),
    ).fetchone()
    return row is not None


def index_exists(conn: CompatConnection, index_name: str) -> bool:
    if conn.is_sqlite:
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name=?",
            (index_name,),
        ).fetchone()
        return row is not None
    row = conn.execute(
        "SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND index_name = %s LIMIT 1",
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
