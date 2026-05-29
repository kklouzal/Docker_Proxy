from __future__ import annotations

import fnmatch
import json
import re
import sqlite3
import threading
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_.-]{2,}", re.IGNORECASE)


def _normalize_host(host: str) -> str:
    value = (host or "").strip().lower().rstrip(".")
    if not value:
        return ""
    if value.startswith("[") and "]" in value:
        return value.split("]", 1)[0] + "]"
    if ":" in value:
        value = value.split(":", 1)[0]
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


class AdblockLookupIndex:
    """Fast candidate lookup for compiled adblock request indexes.

    This deliberately returns candidate rules, not a full ABP decision. Callers
    still apply final URL/resource/domain-scope semantics after using the
    indexed tables to avoid scanning every parsed rule.
    """

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self._local = threading.local()
        self._payloads: dict[str, dict[str, Any]] | None = None
        self._payloads_lock = threading.Lock()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _thread_connection(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(
                f"file:{self.db_path}?mode=ro",
                uri=True,
                check_same_thread=False,
            )
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return conn

    def candidate_rules(
        self,
        url: str,
        *,
        resource_type: str = "",
    ) -> list[dict[str, Any]]:
        conn = self._thread_connection()
        rules: list[dict[str, Any]] = []
        for row in self._candidate_rule_rows(
            conn,
            url,
            resource_type=resource_type,
        ):
            payload: dict[str, Any] | None = None
            if not _row_payload_json(row):
                payload = self._payload_by_id().get(str(row["rule_id"] or ""))
            rules.append(_row_to_rule(row, payload=payload))
        return rules

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

    def _candidate_rule_rows(
        self,
        conn: sqlite3.Connection,
        url: str,
        *,
        resource_type: str = "",
    ) -> list[sqlite3.Row]:
        parsed = urlsplit(url or "")
        host = _normalize_host(parsed.netloc or parsed.hostname or "")
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

            for row in conn.execute(
                "SELECT host_pattern, rule_id FROM host_pattern_index",
            ):
                if fnmatch.fnmatchcase(host, str(row["host_pattern"] or "")):
                    rule_ids.add(str(row["rule_id"]))

        rule_ids.update(
            str(row["rule_id"])
            for row in conn.execute("SELECT rule_id FROM regex_index")
        )

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

        return _rules_by_ids(conn, rule_ids)


def _query_by_values(
    conn: sqlite3.Connection,
    sql_prefix: str,
    values: list[str],
) -> list[sqlite3.Row]:
    filtered = [value for value in values if value]
    if not filtered:
        return []
    placeholders = ",".join("?" for _ in filtered)
    return list(conn.execute(sql_prefix + "(" + placeholders + ")", tuple(filtered)))


def _rules_by_ids(conn: sqlite3.Connection, rule_ids: set[str]) -> list[sqlite3.Row]:
    if not rule_ids:
        return []
    ordered_ids = sorted(rule_ids)
    placeholders = ",".join("?" for _ in ordered_ids)
    rows = list(
        conn.execute(
            "SELECT * FROM rules WHERE rule_id IN (" + placeholders + ")",  # noqa: S608
            tuple(ordered_ids),
        )
    )
    return sorted(
        rows,
        key=lambda row: (
            0 if row["action"] == "allow" else 1,
            str(row["pattern_kind"] or ""),
            str(row["raw"] or ""),
        ),
    )
