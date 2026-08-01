import logging
import os
import pathlib
import re
import secrets
import tempfile
import threading
import time
from dataclasses import dataclass

from werkzeug.security import check_password_hash, generate_password_hash

from services.db import INTEGRITY_ERRORS, connect
from services.logutil import log_exception_throttled

logger = logging.getLogger(__name__)


DEFAULT_SECRET_PATH = "/var/lib/squid-flask-proxy/flask_secret.key"


def _fsync_parent_dir(path: pathlib.Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    fd: int | None = None
    try:
        fd = os.open(path.parent, flags)
        os.fsync(fd)
    except OSError:
        return
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


@dataclass(frozen=True)
class UserRow:
    username: str
    created_ts: int
    updated_ts: int


class AuthStore:
    def __init__(self, secret_path: str | None = None) -> None:
        self.secret_path = (
            secret_path or os.environ.get("FLASK_SECRET_PATH") or DEFAULT_SECRET_PATH
        )
        self._schema_ready = False
        self._schema_lock = threading.Lock()
        self._secret_lock = threading.Lock()

    def _connect(self):
        return connect()

    def ensure_schema(self) -> None:
        if self._schema_ready:
            return
        with self._schema_lock:
            if self._schema_ready:
                return
            with self._connect() as conn:
                try:
                    from services.schema_lifecycle import (
                        runtime_schema_ready_for_lazy_store,
                    )

                    if runtime_schema_ready_for_lazy_store(conn):
                        self._schema_ready = True
                        return
                except Exception:
                    pass
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        username VARCHAR(64) PRIMARY KEY,
                        password_hash TEXT NOT NULL,
                        created_ts BIGINT NOT NULL,
                        updated_ts BIGINT NOT NULL
                    )
                    """,
                )
            self._schema_ready = True

    def ensure_default_admin(self) -> None:
        self.ensure_schema()
        if self.any_users():
            return
        # Default credentials requested by user: admin/admin
        self.add_user("admin", "admin")

    def get_or_create_secret_key(self) -> str:
        with self._secret_lock:
            secret_path = pathlib.Path(self.secret_path)
            secret_dir = secret_path.parent
            if secret_dir:
                secret_dir.mkdir(exist_ok=True, parents=True)
            try:
                with secret_path.open(encoding="utf-8") as f:
                    val = f.read().strip()
                    if val:
                        self._chmod_secret_file(secret_path)
                        return val
            except FileNotFoundError:
                pass

            secret = secrets.token_urlsafe(48)
            tmp_path: pathlib.Path | None = None
            replaced = False
            try:
                fd, raw_tmp_path = tempfile.mkstemp(
                    dir=secret_dir,
                    prefix=f".{secret_path.name}.",
                    suffix=".tmp",
                    text=True,
                )
                tmp_path = pathlib.Path(raw_tmp_path)
                tmp_path.chmod(0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(secret)
                    f.write("\n")
                    f.flush()
                    os.fsync(f.fileno())
                tmp_path.replace(secret_path)
                _fsync_parent_dir(secret_path)
                replaced = True
                self._chmod_secret_file(secret_path)
            finally:
                if tmp_path is not None and not replaced:
                    try:
                        tmp_path.unlink(missing_ok=True)
                    except Exception:
                        log_exception_throttled(
                            logger,
                            "auth_store.secret_tmp_cleanup",
                            interval_seconds=300.0,
                            message="Failed to clean up temporary Flask secret key file",
                        )
            return secret

    @staticmethod
    def _chmod_secret_file(secret_path: pathlib.Path) -> None:
        try:
            secret_path.chmod(0o600)
        except Exception:
            log_exception_throttled(
                logger,
                "auth_store.secret_chmod",
                interval_seconds=300.0,
                message="Failed to chmod Flask secret key file",
            )

    def any_users(self) -> bool:
        self.ensure_schema()
        with self._connect() as conn:
            row = conn.execute("SELECT 1 FROM users LIMIT 1").fetchone()
            return row is not None

    def list_users(self) -> list[UserRow]:
        self.ensure_schema()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT username, created_ts, updated_ts FROM users ORDER BY username ASC",
            ).fetchall()
        return [
            UserRow(username=r[0], created_ts=int(r[1]), updated_ts=int(r[2]))
            for r in rows
        ]

    def verify_user(self, username: str, password: str) -> bool:
        self.ensure_schema()
        u = (username or "").strip()
        if not u:
            return False
        with self._connect() as conn:
            row = conn.execute(
                "SELECT password_hash FROM users WHERE username = %s",
                (u,),
            ).fetchone()
        if not row:
            return False
        return bool(check_password_hash(row[0], password or ""))

    def add_user(self, username: str, password: str) -> None:
        self.ensure_schema()
        u = (username or "").strip()
        if not u:
            msg = "Username is required."
            raise ValueError(msg)
        if len(u) > 64:
            msg = "Username too long."
            raise ValueError(msg)
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", u):
            msg = "Username may only include letters, numbers, underscore, dash, dot."
            raise ValueError(msg)
        if password is None or password == "":
            msg = "Password is required."
            raise ValueError(msg)
        if len(password) < 4:
            msg = "Password must be at least 4 characters."
            raise ValueError(msg)

        now = int(time.time())
        pw_hash = generate_password_hash(password)
        with self._connect() as conn:
            try:
                conn.execute(
                    "INSERT INTO users(username, password_hash, created_ts, updated_ts) VALUES (%s,%s,%s,%s)",
                    (u, pw_hash, now, now),
                )
            except INTEGRITY_ERRORS as exc:
                msg = "User already exists."
                raise ValueError(msg) from exc

    def set_password(self, username: str, new_password: str) -> None:
        self.ensure_schema()
        u = (username or "").strip()
        if not u:
            msg = "Username is required."
            raise ValueError(msg)
        if new_password is None or new_password == "":
            msg = "Password is required."
            raise ValueError(msg)
        if len(new_password) < 4:
            msg = "Password must be at least 4 characters."
            raise ValueError(msg)

        now = int(time.time())
        pw_hash = generate_password_hash(new_password)
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE users SET password_hash = %s, updated_ts = %s WHERE username = %s",
                (pw_hash, now, u),
            )
            if cur.rowcount < 1:
                msg = "User not found."
                raise ValueError(msg)

    def delete_user(self, username: str) -> None:
        self.ensure_schema()
        u = (username or "").strip()
        if not u:
            msg = "Username is required."
            raise ValueError(msg)
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM users WHERE username = %s", (u,))
            if cur.rowcount < 1:
                msg = "User not found."
                raise ValueError(msg)


_auth_store: AuthStore | None = None
_auth_store_lock = threading.Lock()


def get_auth_store() -> AuthStore:
    global _auth_store
    if _auth_store is not None:
        return _auth_store
    with _auth_store_lock:
        if _auth_store is None:
            _auth_store = AuthStore()
        return _auth_store
