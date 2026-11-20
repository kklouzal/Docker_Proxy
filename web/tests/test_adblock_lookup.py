from __future__ import annotations

import sqlite3
import threading
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from pathlib import Path


def _build_lookup_db(tmp_path: Path, lines: list[str]) -> Path:
    from tools import adblock_compile as ac  # type: ignore

    out = tmp_path / "compiled"
    out.mkdir()
    db_path = out / "request_lookup.sqlite"
    ac._write_request_lookup_index(str(db_path), [("sample", lines)], ac._Aggregate())
    return db_path


def _raws(rules: list[dict[str, Any]]) -> set[str]:
    return {str(rule["raw"]) for rule in rules}


def test_adblock_lookup_close_waits_for_in_flight_candidate_query(
    tmp_path: Path,
) -> None:
    db_path = _build_lookup_db(tmp_path, ["||ads.example^"])

    from services.adblock_lookup import AdblockLookupIndex

    index = AdblockLookupIndex(db_path)
    query_entered = threading.Event()
    release_query = threading.Event()
    close_started = threading.Event()
    close_done = threading.Event()
    original_candidate_rule_ids = index._candidate_rule_ids
    result: list[dict[str, Any]] = []

    def blocked_candidate_rule_ids(
        conn: sqlite3.Connection,
        url: str,
        *,
        resource_type: str = "",
    ) -> set[str]:
        query_entered.set()
        assert release_query.wait(timeout=2.0)
        return original_candidate_rule_ids(
            conn,
            url,
            resource_type=resource_type,
        )

    def query() -> None:
        result.extend(index.candidate_rules("https://ads.example/banner.js"))

    def close() -> None:
        close_started.set()
        index.close()
        close_done.set()

    index._candidate_rule_ids = blocked_candidate_rule_ids  # type: ignore[method-assign]
    query_thread = threading.Thread(target=query)
    close_thread = threading.Thread(target=close)
    query_thread.start()
    assert query_entered.wait(timeout=2.0)
    close_thread.start()
    assert close_started.wait(timeout=2.0)
    assert close_done.wait(timeout=0.1) is False

    release_query.set()
    query_thread.join(timeout=2.0)
    close_thread.join(timeout=2.0)

    assert query_thread.is_alive() is False
    assert close_thread.is_alive() is False
    assert _raws(result) == {"||ads.example^"}
    index.close()
    with pytest.raises(RuntimeError, match="lookup index is closed"):
        index.candidate_rules("https://ads.example/banner.js")


def test_adblock_lookup_close_is_bounded_and_rejects_new_acquisitions(
    tmp_path: Path,
) -> None:
    db_path = _build_lookup_db(tmp_path, ["||ads.example^"])

    from services.adblock_lookup import (
        AdblockLookupClosedError,
        AdblockLookupCloseTimeoutError,
        AdblockLookupIndex,
    )

    index = AdblockLookupIndex(db_path, close_timeout_seconds=0.05)
    query_entered = threading.Event()
    release_query = threading.Event()
    query_done = threading.Event()
    original_candidate_rule_ids = index._candidate_rule_ids
    query_errors: list[BaseException] = []

    def blocked_candidate_rule_ids(
        conn: sqlite3.Connection,
        url: str,
        *,
        resource_type: str = "",
    ) -> set[str]:
        query_entered.set()
        assert release_query.wait(timeout=2.0)
        return original_candidate_rule_ids(conn, url, resource_type=resource_type)

    def query() -> None:
        try:
            index.candidate_rules("https://ads.example/banner.js")
        except BaseException as exc:  # pragma: no cover - asserted below
            query_errors.append(exc)
        finally:
            query_done.set()

    index._candidate_rule_ids = blocked_candidate_rule_ids  # type: ignore[method-assign]
    query_thread = threading.Thread(target=query)
    query_thread.start()
    assert query_entered.wait(timeout=2.0)

    with pytest.raises(
        AdblockLookupCloseTimeoutError,
        match=r"with 1 active connection\(s\)",
    ):
        index.close()
    with pytest.raises(AdblockLookupClosedError):
        index.candidate_rules("https://ads.example/after-close.js")

    release_query.set()
    assert query_done.wait(timeout=2.0)
    query_thread.join(timeout=2.0)
    assert query_errors == []
    assert index._connections == set()
    assert index._connection_users == {}
    index.close()


def test_adblock_lookup_close_thread_connection_is_bounded_during_reentrant_use(
    tmp_path: Path,
) -> None:
    db_path = _build_lookup_db(tmp_path, ["||ads.example^"])

    from services.adblock_lookup import (
        AdblockLookupCloseTimeoutError,
        AdblockLookupIndex,
    )

    index = AdblockLookupIndex(db_path, close_timeout_seconds=0)
    original_candidate_rule_ids = index._candidate_rule_ids

    def close_during_candidate_lookup(
        conn: sqlite3.Connection,
        url: str,
        *,
        resource_type: str = "",
    ) -> set[str]:
        with pytest.raises(AdblockLookupCloseTimeoutError):
            index.close_thread_connection()
        return original_candidate_rule_ids(conn, url, resource_type=resource_type)

    index._candidate_rule_ids = close_during_candidate_lookup  # type: ignore[method-assign]
    assert _raws(index.candidate_rules("https://ads.example/banner.js")) == {
        "||ads.example^"
    }
    assert index._local.conn in index._connections
    index.close_thread_connection()
    assert index._connections == set()


def test_adblock_lookup_index_returns_indexed_url_candidates(tmp_path: Path) -> None:
    db_path = _build_lookup_db(
        tmp_path,
        [
            "||ads.example^",
            "@@||allow.example^",
            "||cdn.example.com/assets/ad.js^$script",
            "||*.example.net/ad^",
            "wss://loader.*.com/ws^$websocket,third-party",
            "/tracker[.]example/$third-party",
            "plain-ad-token$~stylesheet",
        ],
    )

    from services.adblock_lookup import AdblockLookupIndex

    lookup = AdblockLookupIndex(db_path)

    assert "||ads.example^" in _raws(
        lookup.candidate_rules("https://sub.ads.example/banner.js")
    )
    assert "||ads.example^" in _raws(
        lookup.candidate_rules("https://user:pass@sub.ads.example/banner.js")
    )
    script_candidates = _raws(
        lookup.candidate_rules(
            "https://cdn.example.com/assets/ad.js?slot=1",
            resource_type="script",
        )
    )
    assert "||cdn.example.com/assets/ad.js^$script" in script_candidates
    wildcard_host_candidates = _raws(
        lookup.candidate_rules("https://sub.example.net/ad.js")
    )
    assert "||*.example.net/ad^" in wildcard_host_candidates

    negated_script_candidates = _raws(
        lookup.candidate_rules(
            "https://static.example/plain-ad-token.js",
            resource_type="script",
        )
    )
    assert "plain-ad-token$~stylesheet" in negated_script_candidates
    negated_stylesheet_candidates = _raws(
        lookup.candidate_rules(
            "https://static.example/plain-ad-token.css",
            resource_type="stylesheet",
        )
    )
    assert "plain-ad-token$~stylesheet" not in negated_stylesheet_candidates

    websocket_candidates = _raws(
        lookup.candidate_rules(
            "wss://loader.foo.com/ws",
            resource_type="websocket",
        )
    )
    assert "wss://loader.*.com/ws^$websocket,third-party" in websocket_candidates

    generic_candidates = _raws(
        lookup.candidate_rules("https://static.example/plain-ad-token.js")
    )
    assert "plain-ad-token$~stylesheet" in generic_candidates
    assert "/tracker[.]example/$third-party" not in generic_candidates

    regex_candidates = _raws(
        lookup.candidate_rules("https://cdn.example/tracker.example/pixel")
    )
    assert "/tracker[.]example/$third-party" in regex_candidates


def test_lookup_returns_domain_anchored_wildcard_host_subdomain_candidates(
    tmp_path: Path,
) -> None:
    db_path = _build_lookup_db(
        tmp_path,
        ["||google.*/pagead/lvz?$script"],
    )

    from services.adblock_lookup import AdblockLookupIndex

    lookup = AdblockLookupIndex(db_path)

    candidates = _raws(
        lookup.candidate_rules(
            "https://www.google.com/pagead/lvz?slot=1",
            resource_type="script",
        ),
    )

    assert "||google.*/pagead/lvz?$script" in candidates


def test_token_prefilters_preserve_host_pattern_and_regex_candidate_superset(
    tmp_path: Path,
) -> None:
    db_path = _build_lookup_db(
        tmp_path,
        [
            "||ad*server.example^",
            "/tracker*/",
            "/tracker.*/",
            "/tracker[.]example/",
        ],
    )

    from services.adblock_lookup import AdblockLookupIndex

    urls = [
        "https://adXYZserver.example/banner.js",
        "https://static.example/tracke",
        "https://static.example/trackerxyz",
        "https://static.example/tracker.example/pixel",
    ]
    indexed_lookup = AdblockLookupIndex(db_path)
    indexed_candidates = {
        url: _raws(indexed_lookup.candidate_rules(url)) for url in urls
    }

    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(
            """
            DELETE FROM host_pattern_token_index;
            DELETE FROM regex_token_index;
            """,
        )
        conn.commit()
    finally:
        conn.close()

    missing_rows_lookup = AdblockLookupIndex(db_path)
    missing_rows_candidates = {
        url: _raws(missing_rows_lookup.candidate_rules(url)) for url in urls
    }

    # Without token rows every pattern is a fallback candidate (a full scan),
    # so the prefiltered result must equal it.
    assert indexed_candidates == missing_rows_candidates
    assert "||ad*server.example^" in indexed_candidates[urls[0]]
    assert "/tracker*/" in indexed_candidates[urls[1]]
    assert "/tracker.*/" in indexed_candidates[urls[2]]
    assert "/tracker[.]example/" in indexed_candidates[urls[3]]


def test_adblock_lookup_rejects_malformed_authority_candidates(
    tmp_path: Path,
) -> None:
    db_path = _build_lookup_db(
        tmp_path,
        ["||ads.example^", "||safe.example^", "||[2001:db8::20]^"],
    )

    from services.adblock_lookup import AdblockLookupIndex

    lookup = AdblockLookupIndex(db_path)

    assert _raws(lookup.candidate_rules("http://[::1")) == set()
    assert _raws(lookup.candidate_rules("https://ads.example:bad/banner.js")) == set()
    assert _raws(lookup.candidate_rules("https://ads.example:99999/banner.js")) == set()
    assert (
        _raws(lookup.candidate_rules(r"https://safe.example\@ads.example/banner.js"))
        == set()
    )
    assert (
        _raws(lookup.candidate_rules(r"https://safe.example\.ads.example/banner.js"))
        == set()
    )
    assert _raws(lookup.candidate_rules(r"https://ads.example\path/banner.js")) == set()
    assert (
        _raws(lookup.candidate_rules("https://ads.example\n.evil/banner.js")) == set()
    )
    assert (
        _raws(lookup.candidate_rules("https://safe.example%2f.ads.example/banner.js"))
        == set()
    )
    assert "||ads.example^" in _raws(
        lookup.candidate_rules("https://user:pass@sub.ads.example/banner.js")
    )
    assert "||[2001:db8::20]^" in _raws(
        lookup.candidate_rules("https://[2001:db8::20]/banner.js")
    )


@pytest.mark.parametrize("version", [None, "1", "5"])
def test_lookup_rejects_unsupported_schema_version(
    tmp_path: Path, version: str | None
) -> None:
    from services.adblock_lookup import (
        LOOKUP_SCHEMA_VERSION,
        AdblockLookupIndex,
        AdblockLookupSchemaError,
    )

    db_path = _build_lookup_db(tmp_path, ["||ads.example^"])
    AdblockLookupIndex(db_path).check_schema()
    assert version != LOOKUP_SCHEMA_VERSION

    conn = sqlite3.connect(str(db_path))
    try:
        if version is None:
            conn.execute("DELETE FROM metadata WHERE key='schema_version'")
        else:
            conn.execute(
                "UPDATE metadata SET value=? WHERE key='schema_version'", (version,)
            )
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(AdblockLookupSchemaError, match="rebuild the adblock artifact"):
        AdblockLookupIndex(db_path).check_schema()


def test_adblock_lookup_chunks_large_sqlite_in_queries(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = _build_lookup_db(
        tmp_path,
        [f"sharedtoken/path{index}" for index in range(8)],
    )

    import services.adblock_lookup as lookup_module

    monkeypatch.setattr(lookup_module, "_SQLITE_IN_CHUNK_SIZE", 3)
    lookup = lookup_module.AdblockLookupIndex(db_path)

    rules = lookup.candidate_rules("https://static.example/sharedtoken/path3")

    assert "sharedtoken/path3" in _raws(rules)
    assert len(rules) == 8
