import os
import re
import secrets
import threading
import time
import logging
from dataclasses import dataclass
from typing import Optional

from werkzeug.security import check_password_hash, generate_password_hash

from services.db import INTEGRITY_ERRORS, connect
from services.logutil import log_exception_throttled


logger = logging.getLogger(__name__)


DEFAULT_AUTH_DB = "/var/lib/squid-flask-proxy/auth.db"
DEFAULT_SECRET_PATH = "/var/lib/squid-flask-proxy/flask_secret.key"


@dataclass(frozen=True)
class UserRow:
    username: str
    created_ts: int
    updated_ts: int


class AuthStore:
    def __init__(
        self,
        db_path: Optional[str] = None,
        secret_path: Optional[str] = None,
    ):
        self.db_path = db_path or os.environ.get("AUTH_DB") or DEFAULT_AUTH_DB
        self.secret_path = secret_path or os.environ.get("FLASK_SECRET_PATH") or DEFAULT_SECRET_PATH

    def _connect(self):
        return connect(default_sqlite_path=self.db_path)

    def ensure_schema(self) -> None:
        with self._connect() as conn:
            if conn.is_mysql:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        username VARCHAR(64) PRIMARY KEY,
                        password_hash TEXT NOT NULL,
                        created_ts BIGINT NOT NULL,
                        updated_ts BIGINT NOT NULL
                    )
                    """
                )
            else:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        username TEXT PRIMARY KEY,
                        password_hash TEXT NOT NULL,
                        created_ts INTEGER NOT NULL,
                        updated_ts INTEGER NOT NULL
                    )
                    """
                )

    def ensure_default_admin(self) -> None:
        self.ensure_schema()
        if self.any_users():
            return
        # Default credentials requested by user: admin/admin
        self.add_user("admin", "admin")

    def get_or_create_secret_key(self) -> str:
        secret_dir = os.path.dirname(self.secret_path)
        if secret_dir:
            os.makedirs(secret_dir, exist_ok=True)
        try:
            with open(self.secret_path, "r", encoding="utf-8") as f:
                val = f.read().strip()
                if val:
                    return val
        except FileNotFoundError:
            pass

        secret = secrets.token_urlsafe(48)
        tmp_path = self.secret_path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(secret)
            f.write("\n")
        os.replace(tmp_path, self.secret_path)
        try:
            os.chmod(self.secret_path, 0o600)
        except Exception:
            log_exception_throttled(
                logger,
                "auth_store.secret_chmod",
                interval_seconds=300.0,
                message="Failed to chmod Flask secret key file",
            )
        return secret

    def any_users(self) -> bool:
        self.ensure_schema()
        with self._connect() as conn:
            row = conn.execute("SELECT 1 FROM users LIMIT 1").fetchone()
            return row is not None

    def list_users(self) -> list[UserRow]:
        self.ensure_schema()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT username, created_ts, updated_ts FROM users ORDER BY username ASC"
            ).fetchall()
        return [UserRow(username=r[0], created_ts=int(r[1]), updated_ts=int(r[2])) for r in rows]

    def verify_user(self, username: str, password: str) -> bool:
        self.ensure_schema()
        u = (username or "").strip()
        if not u:
            return False
        with self._connect() as conn:
            row = conn.execute(
                "SELECT password_hash FROM users WHERE username = ?",
                (u,),
            ).fetchone()
        if not row:
            return False
        return bool(check_password_hash(row[0], password or ""))

    def add_user(self, username: str, password: str) -> None:
        self.ensure_schema()
        u = (username or "").strip()
        if not u:
            raise ValueError("Username is required.")
        if len(u) > 64:
            raise ValueError("Username too long.")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", u):
            raise ValueError("Username may only include letters, numbers, underscore, dash, dot.")
        if password is None or password == "":
            raise ValueError("Password is required.")
        if len(password) < 4:
            raise ValueError("Password must be at least 4 characters.")

        now = int(time.time())
        pw_hash = generate_password_hash(password)
        with self._connect() as conn:
            try:
                conn.execute(
                    "INSERT INTO users(username, password_hash, created_ts, updated_ts) VALUES (?,?,?,?)",
                    (u, pw_hash, now, now),
                )
            except INTEGRITY_ERRORS:
                raise ValueError("User already exists.")

    def set_password(self, username: str, new_password: str) -> None:
        self.ensure_schema()
        u = (username or "").strip()
        if not u:
            raise ValueError("Username is required.")
        if new_password is None or new_password == "":
            raise ValueError("Password is required.")
        if len(new_password) < 4:
            raise ValueError("Password must be at least 4 characters.")

        now = int(time.time())
        pw_hash = generate_password_hash(new_password)
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE users SET password_hash = ?, updated_ts = ? WHERE username = ?",
                (pw_hash, now, u),
            )
            if cur.rowcount < 1:
                raise ValueError("User not found.")

    def delete_user(self, username: str) -> None:
        self.ensure_schema()
        u = (username or "").strip()
        if not u:
            raise ValueError("Username is required.")
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM users WHERE username = ?", (u,))
            if cur.rowcount < 1:
                raise ValueError("User not found.")


_auth_store: Optional[AuthStore] = None
_auth_store_lock = threading.Lock()


def get_auth_store() -> AuthStore:
    global _auth_store
    if _auth_store is not None:
        return _auth_store
    with _auth_store_lock:
        if _auth_store is None:
            _auth_store = AuthStore()
        return _auth_store
