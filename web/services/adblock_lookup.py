from __future__ import annotations

import fnmatch
import ipaddress
import json
import re
import sqlite3
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_.-]{2,}", re.IGNORECASE)
_DEFAULT_SQLITE_CACHE_KIB = 32768
_DEFAULT_SQLITE_MMAP_BYTES = 256 * 1024 * 1024
_DEFAULT_RULE_CACHE_MAX = 50000
_SQLITE_IN_CHUNK_SIZE = 500


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
    __slots__ = ("host_pattern", "rule_id")

    def __init__(self, host_pattern: str, rule_id: str) -> None:
        self.host_pattern = host_pattern
        self.rule_id = rule_id


def _normalize_host(host: str) -> str:
    value = (host or "").strip().lower().rstrip(".")
    if not value:
        return ""
    if value.startswith("[") and "]" in value:
        literal = value[1:].split("]", 1)[0].strip()
        try:
            ip = ipaddress.ip_address(literal)
            return (
                f"[{ip.compressed.lower()}]"
                if ip.version == 6
                else ip.compressed.lower()
            )
        except ValueError:
            return value.split("]", 1)[0] + "]"
    if ":" in value:
        try:
            ip = ipaddress.ip_address(value)
            return (
                f"[{ip.compressed.lower()}]"
                if ip.version == 6
                else ip.compressed.lower()
            )
        except ValueError:
            if value.count(":") == 1:
                value = value.split(":", 1)[0]
            else:
                return value
    try:
        ip = ipaddress.ip_address(value)
        return (
            f"[{ip.compressed.lower()}]" if ip.version == 6 else ip.compressed.lower()
        )
    except ValueError:
        pass
    try:
        return value.encode("idna").decode("ascii").lower().rstrip(".")
    except Exception:
        return value


def _host_suffix_candidates(host: str) -> list[str]:
    normalized = _normalize_host(host)
    if not normalized or normalized.startswith("["):
        return [normalized] if normalized else []
    labels = [part for part in normalized.split(".") if part]
    if len(labels) < 2:
        return [normalized]
    return [".".join(labels[index:]) for index in range(len(labels) - 1)]


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


def _row_payload_json(row: sqlite3.Row) -> str:
    try:
        return str(row["payload_json"] or "")
    except Exception:
        return ""


def _row_to_rule(
    row: sqlite3.Row,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if payload is None:
        try:
            payload = json.loads(_row_payload_json(row) or "{}")
        except Exception:
            payload = {}
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
    if isinstance(payload, dict):
        rule.update(payload)
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
    ) -> None:
        self.db_path = Path(db_path)
        self.rule_cache_max = max(0, int(rule_cache_max or 0))
        self._local = threading.local()
        self._payloads: dict[str, dict[str, Any]] | None = None
        self._payloads_lock = threading.Lock()
        self._rule_cache: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._rule_cache_lock = threading.Lock()
        self._host_patterns: dict[str, _HostPatternCandidate] | None = None
        self._host_patterns_lock = threading.Lock()
        self._host_pattern_token_index_available: bool | None = None
        self._regex_candidates: dict[str, _RegexCandidate] | None = None
        self._regex_candidates_lock = threading.Lock()
        self._regex_token_index_available: bool | None = None

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        _configure_read_connection(conn)
        return conn

    def _thread_connection(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(
                f"file:{self.db_path}?mode=ro",
                uri=True,
                check_same_thread=False,
            )
            _configure_read_connection(conn)
            self._local.conn = conn
        return conn

    def candidate_rules(
        self,
        url: str,
        *,
        resource_type: str = "",
    ) -> list[dict[str, Any]]:
        conn = self._thread_connection()
        return self._rules_by_ids(
            conn,
            self._candidate_rule_ids(
                conn,
                url,
                resource_type=resource_type,
            ),
        )

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
        for row in _rules_by_ids(
            conn,
            missing,
        ):
            payload: dict[str, Any] | None = None
            if not _row_payload_json(row):
                payload = self._payload_by_id().get(str(row["rule_id"] or ""))
            rule = _row_to_rule(row, payload=payload)
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

    def _payload_by_id(self) -> dict[str, dict[str, Any]]:
        if self._payloads is not None:
            return self._payloads
        with self._payloads_lock:
            if self._payloads is not None:
                return self._payloads
            path = self.db_path.parent / "network_rules.jsonl"
            payloads: dict[str, dict[str, Any]] = {}
            try:
                with path.open(encoding="utf-8", errors="replace") as handle:
                    for line in handle:
                        if not line.strip():
                            continue
                        rec = json.loads(line)
                        rule_id = str(rec.get("id") or "")
                        if rule_id:
                            payloads[rule_id] = rec
            except Exception:
                payloads = {}
            self._payloads = payloads
            return payloads

    def _candidate_rule_ids(
        self,
        conn: sqlite3.Connection,
        url: str,
        *,
        resource_type: str = "",
    ) -> set[str]:
        parsed = urlsplit(url or "")
        host = _normalize_host(parsed.hostname or parsed.netloc or "")
        rule_ids: set[str] = set()

        rule_ids.update(
            str(row["rule_id"])
            for row in _query_by_values(
                conn,
                "SELECT rule_id FROM domain_index WHERE host IN ",
                _host_suffix_candidates(host),
            )
        )

        if host:
            rule_ids.update(
                str(row["rule_id"])
                for row in conn.execute(
                    "SELECT rule_id FROM host_index WHERE host=?",
                    (host,),
                )
            )

            rule_ids.update(self._matching_host_pattern_ids(conn, host))

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

        if _table_exists(conn, "resource_type_index"):
            return _filter_by_resource_type(conn, rule_ids, resource_type)
        return rule_ids

    def _matching_host_pattern_ids(
        self,
        conn: sqlite3.Connection,
        host: str,
    ) -> set[str]:
        candidates_by_id = self._load_host_patterns(conn)
        if not candidates_by_id:
            return set()
        candidate_ids = self._host_pattern_candidate_ids(conn, host)
        candidates = (
            candidates_by_id.values()
            if candidate_ids is None
            else (
                candidates_by_id[rule_id]
                for rule_id in candidate_ids
                if rule_id in candidates_by_id
            )
        )
        return {
            candidate.rule_id
            for candidate in candidates
            if fnmatch.fnmatchcase(host, candidate.host_pattern)
        }

    def _host_pattern_candidate_ids(
        self,
        conn: sqlite3.Connection,
        host: str,
    ) -> set[str] | None:
        if self._host_pattern_token_index_available is False:
            return None
        if self._host_pattern_token_index_available is None:
            self._host_pattern_token_index_available = _table_exists(
                conn,
                "host_pattern_token_index",
            )
            if not self._host_pattern_token_index_available:
                return None
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
                    str(row["rule_id"] or ""),
                )
                for row in conn.execute(
                    "SELECT host_pattern, rule_id FROM host_pattern_index",
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
        candidate_ids = self._regex_candidate_ids(conn, url)
        candidates = (
            candidates_by_id.values()
            if candidate_ids is None
            else (
                candidates_by_id[rule_id]
                for rule_id in candidate_ids
                if rule_id in candidates_by_id
            )
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
    ) -> set[str] | None:
        if self._regex_token_index_available is False:
            return None
        if self._regex_token_index_available is None:
            self._regex_token_index_available = _table_exists(
                conn,
                "regex_token_index",
            )
            if not self._regex_token_index_available:
                return None
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


def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1",
        (table_name,),
    ).fetchone()
    return row is not None


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
