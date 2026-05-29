from __future__ import annotations

import fnmatch
import json
import re
import sqlite3
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


def _row_to_rule(row: sqlite3.Row) -> dict[str, Any]:
    return {
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


class AdblockLookupIndex:
    """Fast candidate lookup for compiled adblock request indexes.

    This deliberately returns candidate rules, not a full ABP decision. Callers
    still apply final URL/resource/domain-scope semantics after using the
    indexed tables to avoid scanning every parsed rule.
    """

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def candidate_rules(
        self,
        url: str,
        *,
        resource_type: str = "",
    ) -> list[dict[str, Any]]:
        with self.connect() as conn:
            return [
                _row_to_rule(row)
                for row in self._candidate_rule_rows(
                    conn,
                    url,
                    resource_type=resource_type,
                )
            ]

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

        if resource_type:
            resource_type = resource_type.strip().lower()
            if resource_type:
                typed_ids = {
                    str(row["rule_id"])
                    for row in conn.execute(
                        """
                        SELECT rule_id FROM resource_type_index
                        WHERE resource_type=? AND negated=0
                        """,
                        (resource_type,),
                    )
                }
                untyped_ids = rule_ids - {
                    str(row["rule_id"])
                    for row in conn.execute(
                        "SELECT DISTINCT rule_id FROM resource_type_index WHERE negated=0",
                    )
                }
                excluded_ids = {
                    str(row["rule_id"])
                    for row in conn.execute(
                        """
                        SELECT rule_id FROM resource_type_index
                        WHERE resource_type=? AND negated=1
                        """,
                        (resource_type,),
                    )
                }
                rule_ids = ((rule_ids & typed_ids) | untyped_ids) - excluded_ids

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
    rows: list[sqlite3.Row] = []
    for rule_id in sorted(rule_ids):
        row = conn.execute("SELECT * FROM rules WHERE rule_id=?", (rule_id,)).fetchone()
        if row is not None:
            rows.append(row)
    return sorted(
        rows,
        key=lambda row: (
            0 if row["action"] == "allow" else 1,
            str(row["pattern_kind"] or ""),
            str(row["raw"] or ""),
        ),
    )
