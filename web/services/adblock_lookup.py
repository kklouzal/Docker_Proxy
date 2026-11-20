from __future__ import annotations

import fnmatch
import json
import re
import sqlite3
import threading
import time
from collections import OrderedDict
from operator import itemgetter
from pathlib import Path
from typing import TYPE_CHECKING, Any

from services.adblock_hosts import (
    adblock_host_suffix_candidates as _host_suffix_candidates,
)
from services.adblock_hosts import normalize_adblock_host as _normalize_host
from services.adblock_hosts import safe_adblock_urlsplit as _safe_urlsplit

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_.-]{2,}", re.IGNORECASE)
_DEFAULT_SQLITE_CACHE_KIB = 32768
_DEFAULT_SQLITE_MMAP_BYTES = 256 * 1024 * 1024
_DEFAULT_RULE_CACHE_MAX = 50000
_DEFAULT_HOST_CACHE_MAX = 8192
_SQLITE_IN_CHUNK_SIZE = 500
_DEFAULT_CLOSE_TIMEOUT_SECONDS = 5.0

# Candidate decision order of a rule (see _rule_order).
_OrderKey = tuple[int, str, str, str, str]

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


class AdblockArtifactCorruptError(RuntimeError):
    """A compiled rule's stored payload is unreadable or belongs to another rule.

    Evaluating such a rule from its index columns alone would drop payload
    constraints and over-match, so the lookup fails instead (the ICAP service
    failure policy then applies) rather than answering from corrupt data.
    """


def _verified_row_payload(raw_payload: str, rule_id: str) -> dict[str, Any]:
    """Return the rule's embedded payload or raise AdblockArtifactCorruptError.

    Supported lookup schemas always embed the rule id in ``payload_json``; an
    unreadable, non-object, id-less, or foreign payload is corrupt.
    """
    try:
        payload = json.loads(raw_payload)
    except ValueError as exc:
        msg = f"Adblock rule {rule_id!r} has an unreadable payload_json."
        raise AdblockArtifactCorruptError(msg) from exc
    if not isinstance(payload, dict):
        msg = f"Adblock rule {rule_id!r} payload_json is not an object."
        raise AdblockArtifactCorruptError(msg)
    payload_id = str(payload.get("id") or payload.get("rule_id") or "")
    if payload_id != rule_id:
        msg = f"Adblock rule {rule_id!r} payload_json describes rule {payload_id!r}."
        raise AdblockArtifactCorruptError(msg)
    return payload


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
    rule.update(
        _verified_row_payload(row["payload_json"] or "", str(row["rule_id"] or ""))
    )
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
        host_cache_max: int = _DEFAULT_HOST_CACHE_MAX,
        close_timeout_seconds: float = _DEFAULT_CLOSE_TIMEOUT_SECONDS,
        prepare_rule: Callable[[dict[str, Any]], Any] | None = None,
    ) -> None:
        """Open a read-only lookup over the compiled artifact at ``db_path``.

        ``prepare_rule`` converts each decoded rule dict once, before it enters
        the bounded rule cache; ``candidate_rules`` then returns the prepared
        values (the rule dicts themselves by default).
        """
        self.db_path = Path(db_path)
        self.rule_cache_max = max(0, int(rule_cache_max or 0))
        self.host_cache_max = max(0, int(host_cache_max or 0))
        self._prepare_rule = prepare_rule
        self.close_timeout_seconds = max(0.0, float(close_timeout_seconds))
        self._local = threading.local()
        self._connections_condition = threading.Condition()
        self._connections: set[sqlite3.Connection] = set()
        self._connection_users: dict[sqlite3.Connection, int] = {}
        self._closed = False
        # rule_id -> (candidate order key, prepared rule)
        self._rule_cache: OrderedDict[str, tuple[_OrderKey, Any]] = OrderedDict()
        self._rule_cache_lock = threading.Lock()
        # normalized request host -> ids of the rules indexed by that host
        self._host_cache: OrderedDict[str, frozenset[str]] = OrderedDict()
        self._host_cache_lock = threading.Lock()
        self._indexes: _MemoryIndexes | None = None
        self._indexes_lock = threading.Lock()

    def check_schema(self) -> None:
        """Raise ``AdblockLookupSchemaError`` unless the database is supported."""
        conn = self._acquire_thread_connection()
        try:
            error = lookup_schema_error(conn)
        finally:
            self._release_thread_connection(conn)
        if error:
            raise AdblockLookupSchemaError(error)

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

    def load_indexes(self) -> None:
        """Load the in-memory candidate indexes now instead of on first lookup."""
        conn = self._acquire_thread_connection()
        try:
            self._memory_indexes(conn)
        finally:
            self._release_thread_connection(conn)

    def candidate_rules(
        self,
        url: str,
        *,
        resource_type: str = "",
    ) -> list[Any]:
        """Return the candidate rules for ``url`` in decision order."""
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
    ) -> list[Any]:
        if not rule_ids:
            return []
        entries: list[tuple[_OrderKey, Any]] = []
        missing: list[str] = []
        with self._rule_cache_lock:
            for rule_id in rule_ids:
                entry = self._rule_cache.get(rule_id)
                if entry is None:
                    missing.append(rule_id)
                else:
                    self._rule_cache.move_to_end(rule_id)
                    entries.append(entry)

        prepare = self._prepare_rule
        loaded: list[tuple[str, tuple[_OrderKey, Any]]] = []
        for row in _rules_by_ids(conn, missing):
            rule = _row_to_rule(row)
            loaded.append(
                (
                    str(rule["rule_id"]),
                    (_rule_order(rule), rule if prepare is None else prepare(rule)),
                )
            )

        if loaded and self.rule_cache_max:
            with self._rule_cache_lock:
                for rule_id, entry in loaded:
                    self._rule_cache[rule_id] = entry
                    self._rule_cache.move_to_end(rule_id)
                while len(self._rule_cache) > self.rule_cache_max:
                    self._rule_cache.popitem(last=False)

        entries.extend(entry for _rule_id, entry in loaded)
        entries.sort(key=itemgetter(0))
        return [prepared for _order, prepared in entries]

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
        indexes = self._memory_indexes(conn)
        host = _normalize_host(parsed.hostname or "")
        rule_ids = set(self._host_rule_ids(conn, indexes, host))
        url_tokens = _url_literal_tokens(url)
        rule_ids.update(indexes.matching_regex_ids(url, url_tokens))
        generic_by_key = indexes.generic_by_key
        rule_ids.update(generic_by_key.get("", ()))
        for token in url_tokens:
            rule_ids.update(generic_by_key.get(token, ()))

        return indexes.filter_by_resource_type(rule_ids, resource_type)

    def _host_rule_ids(
        self,
        conn: sqlite3.Connection,
        indexes: _MemoryIndexes,
        host: str,
    ) -> frozenset[str]:
        """Return the ids of every rule indexed by ``host`` or its parents.

        A page load repeats a few hosts many times, so the result (a pure
        function of the host and the immutable artifact) is kept in a bounded
        LRU cache.
        """
        if self.host_cache_max:
            with self._host_cache_lock:
                cached = self._host_cache.get(host)
                if cached is not None:
                    self._host_cache.move_to_end(host)
                    return cached
        host_suffixes = _host_suffix_candidates(host)
        # domain_index holds most of the artifact's rules, so it stays in
        # SQLite; every smaller index is answered from memory.
        rule_ids = {
            row[0]
            for row in _query_by_values(
                conn,
                "SELECT rule_id FROM domain_index WHERE host IN ",
                host_suffixes,
            )
        }
        if host:
            rule_ids.update(indexes.absolute_url_by_host.get(host, ()))
            for suffix in host_suffixes:
                rule_ids.update(indexes.host_anchored_by_host.get(suffix, ()))
            rule_ids.update(indexes.matching_host_pattern_ids(host, host_suffixes))
        result = frozenset(rule_ids)
        if self.host_cache_max:
            with self._host_cache_lock:
                self._host_cache[host] = result
                self._host_cache.move_to_end(host)
                while len(self._host_cache) > self.host_cache_max:
                    self._host_cache.popitem(last=False)
        return result

    def _memory_indexes(self, conn: sqlite3.Connection) -> _MemoryIndexes:
        indexes = self._indexes
        if indexes is not None:
            return indexes
        with self._indexes_lock:
            if self._indexes is None:
                self._indexes = _MemoryIndexes.load(conn)
            return self._indexes


def _ids_by_key(rows: Iterable[tuple[str, str]]) -> dict[str, tuple[str, ...]]:
    grouped: dict[str, list[str]] = {}
    for key, rule_id in rows:
        if rule_id:
            grouped.setdefault(str(key or ""), []).append(str(rule_id))
    return {key: tuple(ids) for key, ids in grouped.items()}


class _MemoryIndexes:
    """Immutable in-memory copy of an artifact's small candidate indexes.

    The lookup database is a published, read-only artifact: the helper is
    restarted when another artifact is applied, so these tables are loaded once
    per index lifetime, like the decoded rule cache. Candidate sets are exactly
    those the equivalent SQL lookups return.
    """

    __slots__ = (
        "absolute_url_by_host",
        "generic_by_key",
        "host_anchored_by_host",
        "host_pattern_fallback_ids",
        "host_pattern_ids_by_key",
        "host_patterns",
        "regex_candidates",
        "regex_fallback_ids",
        "regex_ids_by_key",
        "resource_types_by_id",
    )

    def __init__(self) -> None:
        self.absolute_url_by_host: dict[str, tuple[str, ...]] = {}
        self.host_anchored_by_host: dict[str, tuple[str, ...]] = {}
        self.generic_by_key: dict[str, tuple[str, ...]] = {}
        self.host_patterns: dict[str, _HostPatternCandidate] = {}
        self.host_pattern_ids_by_key: dict[str, tuple[str, ...]] = {}
        self.host_pattern_fallback_ids: frozenset[str] = frozenset()
        self.regex_candidates: dict[str, _RegexCandidate] = {}
        self.regex_ids_by_key: dict[str, tuple[str, ...]] = {}
        self.regex_fallback_ids: frozenset[str] = frozenset()
        # rule_id -> (positive resource types, negated resource types)
        self.resource_types_by_id: dict[str, tuple[frozenset[str], frozenset[str]]] = {}

    @classmethod
    def load(cls, conn: sqlite3.Connection) -> _MemoryIndexes:
        indexes = cls()
        indexes.absolute_url_by_host = _ids_by_key(
            conn.execute(
                "SELECT host, rule_id FROM host_index WHERE pattern_kind='absolute_url'"
            )
        )
        indexes.host_anchored_by_host = _ids_by_key(
            conn.execute(
                "SELECT host, rule_id FROM host_index WHERE pattern_kind='host_anchored'"
            )
        )
        indexes.generic_by_key = _ids_by_key(
            conn.execute("SELECT literal_key, rule_id FROM generic_index")
        )

        indexes.host_patterns = {
            str(row[2] or ""): _HostPatternCandidate(
                str(row[0] or ""),
                str(row[1] or ""),
                str(row[2] or ""),
            )
            for row in conn.execute(
                "SELECT host_pattern, pattern_kind, rule_id FROM host_pattern_index"
            )
            if row[0] and row[2]
        }
        host_pattern_keys = _token_keys_by_rule_id(conn, "host_pattern_token_index")
        indexes.host_pattern_ids_by_key = _ids_by_key(
            (key, rule_id)
            for rule_id, keys in host_pattern_keys.items()
            for key in keys
        )
        indexes.host_pattern_fallback_ids = frozenset(
            rule_id
            for rule_id, candidate in indexes.host_patterns.items()
            if not _single_token_key_is_safe(
                host_pattern_keys.get(rule_id, []),
                lambda key, candidate=candidate: _host_pattern_token_key_is_safe(
                    candidate.host_pattern,
                    key,
                ),
            )
        )

        indexes.regex_candidates = {
            str(row[0] or ""): _RegexCandidate(str(row[0] or ""), str(row[1] or ""))
            for row in conn.execute("SELECT rule_id, regex FROM regex_index")
            if row[0] and row[1]
        }
        regex_keys = _token_keys_by_rule_id(conn, "regex_token_index")
        indexes.regex_ids_by_key = _ids_by_key(
            (key, rule_id) for rule_id, keys in regex_keys.items() for key in keys
        )
        indexes.regex_fallback_ids = frozenset(
            rule_id
            for rule_id, candidate in indexes.regex_candidates.items()
            if not _single_token_key_is_safe(
                regex_keys.get(rule_id, []),
                lambda key, candidate=candidate: _regex_token_key_is_safe(
                    candidate.regex.pattern if candidate.regex is not None else "",
                    key,
                ),
            )
        )

        positive: dict[str, set[str]] = {}
        negated: dict[str, set[str]] = {}
        for rule_id, indexed_type, is_negated in conn.execute(
            "SELECT rule_id, resource_type, negated FROM resource_type_index"
        ):
            if not rule_id:
                continue
            target = negated if int(is_negated or 0) else positive
            target.setdefault(str(rule_id), set()).add(str(indexed_type or "").lower())
        indexes.resource_types_by_id = {
            rule_id: (
                frozenset(positive.get(rule_id, ())),
                frozenset(negated.get(rule_id, ())),
            )
            for rule_id in positive.keys() | negated.keys()
        }
        return indexes

    def matching_host_pattern_ids(
        self,
        host: str,
        host_suffixes: list[str],
    ) -> set[str]:
        candidates_by_id = self.host_patterns
        if not candidates_by_id:
            return set()
        candidate_ids = set(self.host_pattern_ids_by_key.get("", ()))
        for token in _url_literal_tokens(host):
            candidate_ids.update(self.host_pattern_ids_by_key.get(token, ()))
        candidate_ids.update(self.host_pattern_fallback_ids)
        return {
            rule_id
            for rule_id in candidate_ids
            if rule_id in candidates_by_id
            and _host_pattern_matches_candidate(
                host, host_suffixes, candidates_by_id[rule_id]
            )
        }

    def matching_regex_ids(self, url: str, url_tokens: list[str]) -> set[str]:
        candidates_by_id = self.regex_candidates
        if not candidates_by_id:
            return set()
        candidate_ids = set(self.regex_ids_by_key.get("", ()))
        for token in url_tokens:
            candidate_ids.update(self.regex_ids_by_key.get(token, ()))
        candidate_ids.update(self.regex_fallback_ids)
        matched: set[str] = set()
        for rule_id in candidate_ids:
            candidate = candidates_by_id.get(rule_id)
            if (
                candidate is not None
                and candidate.regex is not None
                and candidate.regex.search(url or "")
            ):
                matched.add(candidate.rule_id)
        return matched

    def filter_by_resource_type(
        self,
        rule_ids: set[str],
        resource_type: str,
    ) -> set[str]:
        normalized_type = (resource_type or "").strip().lower()
        if not rule_ids or not normalized_type:
            return rule_ids
        types_by_id = self.resource_types_by_id
        kept: set[str] = set()
        for rule_id in rule_ids:
            types = types_by_id.get(rule_id)
            if types is None:
                kept.add(rule_id)
                continue
            positive, negated = types
            if normalized_type in negated:
                continue
            if positive and normalized_type not in positive:
                continue
            kept.add(rule_id)
        return kept


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


def _rule_order(rule: dict[str, Any]) -> _OrderKey:
    """Total candidate order: the first matching rule is attributed the decision.

    The same rule text in two lists ties on (action, kind, raw); list key and
    rule id break the tie so attribution never depends on the database's
    physical row order or on which candidates were cached.
    """
    return (
        0 if rule.get("action") == "allow" else 1,
        str(rule.get("pattern_kind") or ""),
        str(rule.get("raw") or ""),
        str(rule.get("list_key") or ""),
        str(rule.get("rule_id") or ""),
    )


def _rules_by_ids(conn: sqlite3.Connection, rule_ids: list[str]) -> list[sqlite3.Row]:
    if not rule_ids:
        return []
    return _query_by_values(
        conn,
        "SELECT * FROM rules WHERE rule_id IN ",
        sorted(rule_ids),
    )
