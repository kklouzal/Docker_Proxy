from __future__ import annotations

import fnmatch
import json
import re
import sqlite3
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any

from services.adblock_hosts import (
    adblock_host_suffix_candidates as _host_suffix_candidates,
)
from services.adblock_hosts import normalize_adblock_host as _normalize_host
from services.adblock_hosts import safe_adblock_urlsplit as _safe_urlsplit

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_.-]{2,}", re.IGNORECASE)
_DEFAULT_SQLITE_CACHE_KIB = 32768
_DEFAULT_SQLITE_MMAP_BYTES = 256 * 1024 * 1024
_DEFAULT_RULE_CACHE_MAX = 50000
_SQLITE_IN_CHUNK_SIZE = 500
_DEFAULT_CLOSE_TIMEOUT_SECONDS = 5.0

# Version of the request lookup database the compiler writes
# (tools/adblock_compile.py) and this reader requires. Readers reject any other
# version instead of guessing at its tables; the Admin UI rebuilds artifacts
# whose report names another version.
LOOKUP_SCHEMA_VERSION = "4"


def lookup_schema_error(conn: sqlite3.Connection) -> str:
    """Return why ``conn`` is not a supported lookup database, else ""."""
    try:
        row = conn.execute(
            "SELECT value FROM metadata WHERE key='schema_version'"
        ).fetchone()
    except sqlite3.DatabaseError:
        row = None
    version = str(row[0]) if row else ""
    if version == LOOKUP_SCHEMA_VERSION:
        return ""
    return (
        f"adblock request lookup schema version {version or '(missing)'} is not "
        f"supported (expected {LOOKUP_SCHEMA_VERSION}); rebuild the adblock artifact."
    )


class AdblockLookupSchemaError(RuntimeError):
    pass


class AdblockLookupClosedError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("adblock lookup index is closed")


class AdblockLookupCloseTimeoutError(TimeoutError):
    def __init__(self, active_connections: int) -> None:
        super().__init__(
            "timed out closing adblock lookup index "
            f"with {active_connections} active connection(s)"
        )


class _RegexCandidate:
    __slots__ = ("regex", "rule_id")

    def __init__(self, rule_id: str, pattern: str) -> None:
        self.rule_id = rule_id
        self.regex: re.Pattern[str] | None
        try:
            self.regex = re.compile(pattern, re.IGNORECASE)
        except re.error:
            self.regex = None


class _HostPatternCandidate:
    __slots__ = ("host_pattern", "pattern_kind", "rule_id")

    def __init__(self, host_pattern: str, pattern_kind: str, rule_id: str) -> None:
        self.host_pattern = host_pattern
        self.pattern_kind = pattern_kind
        self.rule_id = rule_id


def _url_literal_tokens(url: str) -> list[str]:
    tokens: set[str] = set()
    for token in _TOKEN_RE.findall(url or ""):
        normalized = token.lower()
        tokens.add(normalized)
        if "." in normalized:
            labels = [part for part in normalized.split(".") if part]
            tokens.update(
                ".".join(labels[index:])
                for index in range(1, max(len(labels) - 1, 1))
                if len(".".join(labels[index:])) >= 3
            )
        tokens.update(part for part in re.split(r"[./]", normalized) if len(part) >= 3)
    return sorted(tokens)


def _row_to_rule(row: sqlite3.Row) -> dict[str, Any]:
    rule = {
        "rule_id": row["rule_id"],
        "list_key": row["list_key"],
        "action": row["action"],
        "exception": bool(row["exception"]),
        "pattern_kind": row["pattern_kind"],
        "raw": row["raw"],
        "pattern": row["pattern"],
        "options": json.loads(row["options_json"] or "{}"),
        "resource_types": json.loads(row["resource_types_json"] or "[]"),
        "excluded_resource_types": json.loads(
            row["excluded_resource_types_json"] or "[]"
        ),
        "third_party": row["third_party"],
        "behavior_options": json.loads(row["behavior_options_json"] or "[]"),
        "value_options": json.loads(row["value_options_json"] or "{}"),
    }
    # payload_json carries the matcher fields that have no column of their own.
    rule.update(json.loads(row["payload_json"] or "{}"))
    rule["rule_id"] = row["rule_id"]
    return rule


def _configure_read_connection(conn: sqlite3.Connection) -> None:
    conn.row_factory = sqlite3.Row
    pragmas: tuple[tuple[str, int | str], ...] = (
        ("query_only", 1),
        ("temp_store", "MEMORY"),
        ("cache_size", -_DEFAULT_SQLITE_CACHE_KIB),
        ("mmap_size", _DEFAULT_SQLITE_MMAP_BYTES),
    )
    for key, value in pragmas:
        try:
            conn.execute(f"PRAGMA {key}={value}")
        except sqlite3.DatabaseError:
            pass


class AdblockLookupIndex:
    """Fast candidate lookup for compiled adblock request indexes.

    This deliberately returns candidate rules, not a full ABP decision. Callers
    still apply final URL/resource/domain-scope semantics after using the
    indexed tables to avoid scanning every parsed rule.
    """

    def __init__(
        self,
        db_path: str | Path,
        *,
        rule_cache_max: int = _DEFAULT_RULE_CACHE_MAX,
        close_timeout_seconds: float = _DEFAULT_CLOSE_TIMEOUT_SECONDS,
    ) -> None:
        self.db_path = Path(db_path)
        self.rule_cache_max = max(0, int(rule_cache_max or 0))
        self.close_timeout_seconds = max(0.0, float(close_timeout_seconds))
        self._local = threading.local()
        self._connections_condition = threading.Condition()
        self._connections: set[sqlite3.Connection] = set()
        self._connection_users: dict[sqlite3.Connection, int] = {}
        self._closed = False
        self._rule_cache: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._rule_cache_lock = threading.Lock()
        self._host_patterns: dict[str, _HostPatternCandidate] | None = None
        self._host_patterns_lock = threading.Lock()
        self._host_pattern_token_fallback_ids: set[str] | None = None
        self._regex_candidates: dict[str, _RegexCandidate] | None = None
        self._regex_candidates_lock = threading.Lock()
        self._regex_token_fallback_ids: set[str] | None = None

    def check_schema(self) -> None:
        """Raise ``AdblockLookupSchemaError`` unless the database is supported."""
        conn = self._acquire_thread_connection()
        try:
            error = lookup_schema_error(conn)
        finally:
            self._release_thread_connection(conn)
        if error:
            raise AdblockLookupSchemaError(error)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        _configure_read_connection(conn)
        return conn

    def _acquire_thread_connection(self) -> sqlite3.Connection:
        with self._connections_condition:
            if self._closed:
                raise AdblockLookupClosedError
            conn = getattr(self._local, "conn", None)
            if conn is None:
                conn = sqlite3.connect(
                    f"file:{self.db_path}?mode=ro",
                    uri=True,
                    check_same_thread=False,
                )
                _configure_read_connection(conn)
                self._local.conn = conn
                self._connections.add(conn)
            self._connection_users[conn] = self._connection_users.get(conn, 0) + 1
            return conn

    def _release_thread_connection(self, conn: sqlite3.Connection) -> None:
        close_connection = False
        with self._connections_condition:
            users = self._connection_users.get(conn, 0)
            if users <= 1:
                self._connection_users.pop(conn, None)
                if self._closed and conn in self._connections:
                    self._connections.remove(conn)
                    close_connection = True
                self._connections_condition.notify_all()
            else:
                self._connection_users[conn] = users - 1
        if close_connection:
            conn.close()

    def _wait_until_idle(self, conn: sqlite3.Connection) -> bool:
        deadline = time.monotonic() + self.close_timeout_seconds
        while self._connection_users.get(conn, 0):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            self._connections_condition.wait(timeout=remaining)
        return True

    def close_thread_connection(self) -> None:
        """Close this thread's connection, interrupting and bounding active use."""
        conn = getattr(self._local, "conn", None)
        if conn is None:
            return
        del self._local.conn
        with self._connections_condition:
            if self._connection_users.get(conn, 0):
                conn.interrupt()
            if not self._wait_until_idle(conn):
                self._local.conn = conn
                raise AdblockLookupCloseTimeoutError(1)
            should_close = conn in self._connections
            self._connections.discard(conn)
        if should_close:
            conn.close()

    def close(self) -> None:
        """Stop acquisitions, interrupt active SQL, and close within a deadline."""
        with self._connections_condition:
            self._closed = True
            for conn in self._connection_users:
                conn.interrupt()
            deadline = time.monotonic() + self.close_timeout_seconds
            while self._connection_users:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AdblockLookupCloseTimeoutError(len(self._connection_users))
                self._connections_condition.wait(timeout=remaining)
            connections = list(self._connections)
            self._connections.clear()
            local_conn = getattr(self._local, "conn", None)
            if local_conn in connections:
                del self._local.conn
        for conn in connections:
            conn.close()

    def candidate_rules(
        self,
        url: str,
        *,
        resource_type: str = "",
    ) -> list[dict[str, Any]]:
        conn = self._acquire_thread_connection()
        try:
            return self._rules_by_ids(
                conn,
                self._candidate_rule_ids(
                    conn,
                    url,
                    resource_type=resource_type,
                ),
            )
        finally:
            self._release_thread_connection(conn)

    def _rules_by_ids(
        self,
        conn: sqlite3.Connection,
        rule_ids: set[str],
    ) -> list[dict[str, Any]]:
        if not rule_ids:
            return []
        cached: dict[str, dict[str, Any]] = {}
        missing: set[str] = set()
        with self._rule_cache_lock:
            for rule_id in rule_ids:
                rule = self._rule_cache.get(rule_id)
                if rule is None:
                    missing.add(rule_id)
                else:
                    self._rule_cache.move_to_end(rule_id)
                    cached[rule_id] = rule

        loaded: dict[str, dict[str, Any]] = {}
        for row in _rules_by_ids(conn, missing):
            rule = _row_to_rule(row)
            loaded[str(rule["rule_id"])] = rule

        if loaded and self.rule_cache_max:
            with self._rule_cache_lock:
                for rule_id, rule in loaded.items():
                    self._rule_cache[rule_id] = rule
                    self._rule_cache.move_to_end(rule_id)
                while len(self._rule_cache) > self.rule_cache_max:
                    self._rule_cache.popitem(last=False)

        rules = list(cached.values()) + list(loaded.values())
        return sorted(
            rules,
            key=lambda rule: (
                0 if rule.get("action") == "allow" else 1,
                str(rule.get("pattern_kind") or ""),
                str(rule.get("raw") or ""),
            ),
        )

    def _candidate_rule_ids(
        self,
        conn: sqlite3.Connection,
        url: str,
        *,
        resource_type: str = "",
    ) -> set[str]:
        parsed = _safe_urlsplit(url)
        if parsed is None:
            return set()
        host = _normalize_host(parsed.hostname or "")
        rule_ids: set[str] = set()

        host_suffixes = _host_suffix_candidates(host)
        rule_ids.update(
            str(row["rule_id"])
            for row in _query_by_values(
                conn,
                "SELECT rule_id FROM domain_index WHERE host IN ",
                host_suffixes,
            )
        )

        if host:
            rule_ids.update(
                str(row["rule_id"])
                for row in conn.execute(
                    "SELECT rule_id FROM host_index WHERE host=? AND pattern_kind='absolute_url'",
                    (host,),
                )
            )
            rule_ids.update(
                str(row["rule_id"])
                for row in _query_by_values(
                    conn,
                    "SELECT rule_id FROM host_index WHERE pattern_kind='host_anchored' AND host IN ",
                    host_suffixes,
                )
            )
            rule_ids.update(
                self._matching_host_pattern_ids(conn, host, host_suffixes),
            )

        rule_ids.update(self._matching_regex_ids(conn, url))

        literal_tokens = _url_literal_tokens(url)
        rule_ids.update(
            str(row["rule_id"])
            for row in _query_by_values(
                conn,
                "SELECT rule_id FROM generic_index WHERE literal_key IN ",
                literal_tokens,
            )
        )
        rule_ids.update(
            str(row["rule_id"])
            for row in conn.execute(
                "SELECT rule_id FROM generic_index WHERE literal_key=''",
            )
        )

        return _filter_by_resource_type(conn, rule_ids, resource_type)

    def _matching_host_pattern_ids(
        self,
        conn: sqlite3.Connection,
        host: str,
        host_suffixes: list[str],
    ) -> set[str]:
        candidates_by_id = self._load_host_patterns(conn)
        if not candidates_by_id:
            return set()
        candidate_ids = self._host_pattern_candidate_ids(
            conn,
            host,
            candidates_by_id,
        )
        return {
            rule_id
            for rule_id in candidate_ids
            if rule_id in candidates_by_id
            and _host_pattern_matches_candidate(
                host, host_suffixes, candidates_by_id[rule_id]
            )
        }

    def _host_pattern_candidate_ids(
        self,
        conn: sqlite3.Connection,
        host: str,
        candidates_by_id: dict[str, _HostPatternCandidate],
    ) -> set[str]:
        literal_tokens = _url_literal_tokens(host)
        rule_ids = {
            str(row["rule_id"])
            for row in _query_by_values(
                conn,
                "SELECT rule_id FROM host_pattern_token_index WHERE literal_key IN ",
                literal_tokens,
            )
        }
        rule_ids.update(
            str(row["rule_id"])
            for row in conn.execute(
                "SELECT rule_id FROM host_pattern_token_index WHERE literal_key=''",
            )
        )
        if self._host_pattern_token_fallback_ids is None:
            keys_by_id = _token_keys_by_rule_id(conn, "host_pattern_token_index")
            self._host_pattern_token_fallback_ids = {
                rule_id
                for rule_id, candidate in candidates_by_id.items()
                if not _single_token_key_is_safe(
                    keys_by_id.get(rule_id, []),
                    lambda key: _host_pattern_token_key_is_safe(
                        candidate.host_pattern,
                        key,
                    ),
                )
            }
        rule_ids.update(self._host_pattern_token_fallback_ids)
        return rule_ids

    def _load_host_patterns(
        self,
        conn: sqlite3.Connection,
    ) -> dict[str, _HostPatternCandidate]:
        if self._host_patterns is not None:
            return self._host_patterns
        with self._host_patterns_lock:
            if self._host_patterns is not None:
                return self._host_patterns
            self._host_patterns = {
                str(row["rule_id"] or ""): _HostPatternCandidate(
                    str(row["host_pattern"] or ""),
                    str(row["pattern_kind"] or ""),
                    str(row["rule_id"] or ""),
                )
                for row in conn.execute(
                    "SELECT host_pattern, pattern_kind, rule_id FROM host_pattern_index"
                )
                if row["host_pattern"] and row["rule_id"]
            }
            return self._host_patterns

    def _matching_regex_ids(
        self,
        conn: sqlite3.Connection,
        url: str,
    ) -> set[str]:
        candidates_by_id = self._load_regex_candidates(conn)
        if not candidates_by_id:
            return set()
        candidate_ids = self._regex_candidate_ids(conn, url, candidates_by_id)
        candidates = (
            candidates_by_id[rule_id]
            for rule_id in candidate_ids
            if rule_id in candidates_by_id
        )
        return {
            candidate.rule_id
            for candidate in candidates
            if candidate.regex is not None and candidate.regex.search(url or "")
        }

    def _regex_candidate_ids(
        self,
        conn: sqlite3.Connection,
        url: str,
        candidates_by_id: dict[str, _RegexCandidate],
    ) -> set[str]:
        literal_tokens = _url_literal_tokens(url)
        rule_ids = {
            str(row["rule_id"])
            for row in _query_by_values(
                conn,
                "SELECT rule_id FROM regex_token_index WHERE literal_key IN ",
                literal_tokens,
            )
        }
        rule_ids.update(
            str(row["rule_id"])
            for row in conn.execute(
                "SELECT rule_id FROM regex_token_index WHERE literal_key=''",
            )
        )
        if self._regex_token_fallback_ids is None:
            keys_by_id = _token_keys_by_rule_id(conn, "regex_token_index")
            self._regex_token_fallback_ids = {
                rule_id
                for rule_id, candidate in candidates_by_id.items()
                if not _single_token_key_is_safe(
                    keys_by_id.get(rule_id, []),
                    lambda key: _regex_token_key_is_safe(
                        candidate.regex.pattern if candidate.regex is not None else "",
                        key,
                    ),
                )
            }
        rule_ids.update(self._regex_token_fallback_ids)
        return rule_ids

    def _load_regex_candidates(
        self,
        conn: sqlite3.Connection,
    ) -> dict[str, _RegexCandidate]:
        if self._regex_candidates is not None:
            return self._regex_candidates
        with self._regex_candidates_lock:
            if self._regex_candidates is not None:
                return self._regex_candidates
            self._regex_candidates = {
                str(row["rule_id"] or ""): _RegexCandidate(
                    str(row["rule_id"] or ""),
                    str(row["regex"] or ""),
                )
                for row in conn.execute("SELECT rule_id, regex FROM regex_index")
                if row["rule_id"] and row["regex"]
            }
            return self._regex_candidates


def _query_by_values(
    conn: sqlite3.Connection,
    sql_prefix: str,
    values: list[str],
) -> list[sqlite3.Row]:
    filtered = [value for value in values if value]
    if not filtered:
        return []
    rows: list[sqlite3.Row] = []
    chunk_size = max(1, int(_SQLITE_IN_CHUNK_SIZE))
    for index in range(0, len(filtered), chunk_size):
        chunk = filtered[index : index + chunk_size]
        placeholders = ",".join("?" for _ in chunk)
        rows.extend(conn.execute(sql_prefix + "(" + placeholders + ")", tuple(chunk)))
    return rows


def _token_keys_by_rule_id(
    conn: sqlite3.Connection,
    table_name: str,
) -> dict[str, list[str]]:
    keys_by_id: dict[str, list[str]] = {}
    if table_name == "host_pattern_token_index":
        rows = conn.execute(
            "SELECT literal_key, rule_id FROM host_pattern_token_index",
        )
    elif table_name == "regex_token_index":
        rows = conn.execute("SELECT literal_key, rule_id FROM regex_token_index")
    else:
        raise ValueError(table_name)
    for row in rows:
        rule_id = str(row["rule_id"] or "")
        if rule_id:
            keys_by_id.setdefault(rule_id, []).append(str(row["literal_key"] or ""))
    return keys_by_id


def _single_token_key_is_safe(
    keys: list[str],
    is_safe: Any,
) -> bool:
    return len(keys) == 1 and bool(is_safe(keys[0]))


def _indexed_literal_key(pattern: str) -> str:
    tokens = [
        token.strip(".")
        for token in _TOKEN_RE.findall(pattern or "")
        if token.strip(".")
    ]
    if not tokens:
        return ""
    return max((token.lower() for token in tokens), key=lambda item: (len(item), item))


def _host_pattern_token_key_is_safe(host_pattern: str, key: str) -> bool:
    pattern = (host_pattern or "").lower()
    if key != _indexed_literal_key(pattern):
        return False
    if not key:
        return True
    start = 0
    while True:
        start = pattern.find(key, start)
        if start < 0:
            return False
        end = start + len(key)
        starts_at_label_boundary = start == 0 or pattern[start - 1] == "."
        ends_at_label_boundary = end == len(pattern) or pattern[end] == "."
        if starts_at_label_boundary and (
            ("." not in key and ends_at_label_boundary) or end == len(pattern)
        ):
            return True
        start += 1


def _regex_token_key_is_safe(pattern: str, key: str) -> bool:
    expected_key = (
        ""
        if any(marker in (pattern or "") for marker in ("|", "?"))
        or "{0" in (pattern or "")
        else _indexed_literal_key(pattern)
    )
    if key != expected_key:
        return False
    # A non-empty regex literal can match within a larger URL token (for
    # example, /tracker.*/ matches "trackerxyz"), so equality against the URL
    # token set is not a sound prefilter. Empty keys are unconditional and safe.
    return not key


def _host_pattern_matches_candidate(
    host: str,
    host_suffixes: list[str],
    candidate: _HostPatternCandidate,
) -> bool:
    if candidate.pattern_kind == "absolute_url_pattern":
        return fnmatch.fnmatchcase(host, candidate.host_pattern)
    # host_anchored_pattern: the pattern may match any parent domain.
    return any(
        fnmatch.fnmatchcase(host_suffix, candidate.host_pattern)
        for host_suffix in host_suffixes
    )


def _rules_by_ids(conn: sqlite3.Connection, rule_ids: set[str]) -> list[sqlite3.Row]:
    if not rule_ids:
        return []
    ordered_ids = sorted(rule_ids)
    rows = _query_by_values(
        conn,
        "SELECT * FROM rules WHERE rule_id IN ",
        ordered_ids,
    )
    return sorted(
        rows,
        key=lambda row: (
            0 if row["action"] == "allow" else 1,
            str(row["pattern_kind"] or ""),
            str(row["raw"] or ""),
        ),
    )


def _filter_by_resource_type(
    conn: sqlite3.Connection,
    rule_ids: set[str],
    resource_type: str,
) -> set[str]:
    normalized_type = (resource_type or "").strip().lower()
    if not rule_ids or not normalized_type:
        return rule_ids
    rows = _query_by_values(
        conn,
        """
        SELECT rule_id, resource_type, negated
        FROM resource_type_index
        WHERE rule_id IN
        """,
        sorted(rule_ids),
    )
    positive: dict[str, set[str]] = {}
    excluded: set[str] = set()
    for row in rows:
        rule_id = str(row["rule_id"] or "")
        indexed_type = str(row["resource_type"] or "").lower()
        if not rule_id:
            continue
        if int(row["negated"] or 0):
            if indexed_type == normalized_type:
                excluded.add(rule_id)
            continue
        positive.setdefault(rule_id, set()).add(indexed_type)

    return {
        rule_id
        for rule_id in rule_ids
        if rule_id not in excluded
        and (rule_id not in positive or normalized_type in positive[rule_id])
    }
