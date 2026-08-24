from __future__ import annotations

import sys
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.ssl_errors_store import (  # noqa: E402
    SslErrorsStore,  # type: ignore
    _extract_domain,  # type: ignore
)


class _RecordingConnection:
    def __init__(self) -> None:
        self.queries: list[tuple[str, tuple[object, ...]]] = []

    def execute(self, sql: str, params: tuple[object, ...]):
        self.queries.append((sql, params))


def test_upsert_qualifies_existing_row_columns_against_incoming_alias(
    monkeypatch,
) -> None:
    from services import ssl_errors_store

    conn = _RecordingConnection()
    store = SslErrorsStore()
    monkeypatch.setenv("DEFAULT_PROXY_ID", "edge-1")
    monkeypatch.setattr(
        ssl_errors_store,
        "guarded_proxy_write",
        lambda _conn, proxy_id: nullcontext(SimpleNamespace(proxy_id=proxy_id)),
    )
    monkeypatch.setattr(
        store,
        "_enrich_domain_from_context",
        lambda _conn, domain, _ts, _sample: domain,
    )

    store._upsert(
        conn,
        "example.test",
        "tls",
        "handshake failed",
        123,
        "latest sample",
    )

    sql, params = conn.queries[-1]
    duplicate_update = sql.split("ON DUPLICATE KEY UPDATE", 1)[1]
    assert "count = ssl_errors.count + 1" in duplicate_update
    assert (
        "first_seen = LEAST(ssl_errors.first_seen, incoming.first_seen)"
        in duplicate_update
    )
    assert (
        "last_seen = GREATEST(ssl_errors.last_seen, incoming.last_seen)"
        in duplicate_update
    )
    assert "sample = incoming.sample" in duplicate_update
    assert params[1:] == (
        "edge-1",
        "example.test",
        "tls",
        "handshake failed",
        123,
        123,
        "latest sample",
    )


def test_ssl_error_domain_extraction_accepts_peer_token() -> None:
    line = "kid1| Error negotiating TLS on FD 42: SQUID_TLS_ERR_ACCEPT+TLS_LIB_ERR=1 peer=media.steampowered.com:443"
    assert _extract_domain(line) == "media.steampowered.com"


def test_ssl_error_domain_extraction_accepts_quoted_peer_token() -> None:
    line = 'kid1| Error negotiating TLS on FD 42: SQUID_TLS_ERR_ACCEPT peer="media.steampowered.com:443"'
    assert _extract_domain(line) == "media.steampowered.com"


def test_ssl_error_domain_extraction_accepts_bracketed_ipv6_peer_token() -> None:
    line = "kid1| Error negotiating TLS on FD 42: SQUID_TLS_ERR_ACCEPT peer=[2001:db8::1]:443"
    assert _extract_domain(line) == "2001:db8::1"


def test_ssl_error_domain_extraction_accepts_server_name_token() -> None:
    line = "kid1| Error negotiating TLS on FD 42: SQUID_TLS_ERR_ACCEPT server_name=api.steampowered.com"
    assert _extract_domain(line) == "api.steampowered.com"


def test_ssl_error_domain_extraction_accepts_quoted_server_name_with_port() -> None:
    line = 'kid1| Error negotiating TLS on FD 42: SQUID_TLS_ERR_ACCEPT server_name="api.steampowered.com:443"'
    assert _extract_domain(line) == "api.steampowered.com"


def test_ssl_error_domain_extraction_accepts_bracketed_ipv6_sni_with_port() -> None:
    line = "kid1| Error negotiating TLS on FD 42: SQUID_TLS_ERR_ACCEPT sni=[2001:db8::1]:443"
    assert _extract_domain(line) == "2001:db8::1"


def test_ssl_error_domain_extraction_accepts_quoted_host_with_port() -> None:
    line = "kid1| Error negotiating TLS on FD 42: SQUID_TLS_ERR_ACCEPT host='cdn.steampowered.com:443'"
    assert _extract_domain(line) == "cdn.steampowered.com"


def test_ssl_error_domain_extraction_accepts_sni_colon_equals_form() -> None:
    line = "kid1| Error negotiating TLS on FD 42: SQUID_TLS_ERR_ACCEPT SNI := api.steampowered.com:443"
    assert _extract_domain(line) == "api.steampowered.com"


def test_ssl_errors_filtered_where_reuses_proxy_since_search_and_domain_filters(
    monkeypatch,
) -> None:
    monkeypatch.setenv("DEFAULT_PROXY_ID", "edge-1")
    where_sql, params = SslErrorsStore()._filtered_errors_where(
        since=123,
        search="steam_%/host",
        require_domain=True,
    )

    assert where_sql == (
        "WHERE proxy_id = %s AND domain <> '' AND last_seen >= %s "
        "AND domain LIKE %s ESCAPE '\\\\'"
    )
    assert params == ("edge-1", 123, "%steam\\_\\%/host%")


def test_steam_compatibility_preset_is_shipped_once() -> None:
    from services.ssl_compatibility_presets import (
        COMPATIBILITY_PRESETS,  # type: ignore
    )

    matches = [preset for preset in COMPATIBILITY_PRESETS if preset.id == "steam"]
    assert len(matches) == 1
    assert "*.steamserver.net" in matches[0].domains
    assert "cdn.cloudflare.steamstatic.com" in matches[0].domains


def test_seed_discards_partial_long_record_at_bounded_tail_start(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cache_log = tmp_path / "cache.log"
    cache_log.write_text(
        "2020/09/13 12:26:40| "
        + ("x" * 800)
        + " TLS handshake failed host=fabricated.example\n"
        + "2026/08/04 12:00:00| TLS handshake failed host=complete.example\n",
        encoding="utf-8",
    )
    store = SslErrorsStore(str(cache_log), seed_max_lines=2)
    samples: list[str] = []

    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "_connect", lambda: nullcontext(object()))
    monkeypatch.setattr(store, "_latest_seen_ts", lambda _conn: 1_700_000_000)
    monkeypatch.setattr(
        store,
        "_upsert",
        lambda _conn, _domain, _category, _reason, _ts, sample: samples.append(
            sample,
        ),
    )

    store.seed_from_recent_log()

    assert samples == ["TLS handshake failed host=complete.example"]


def test_seed_ignores_incompletely_written_trailing_record(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cache_log = tmp_path / "cache.log"
    cache_log.write_text(
        "2026/08/04 11:59:59| TLS handshake failed host=complete.example\n"
        "2026/08/04 12:00:00| TLS handshake failed host=partial.example",
        encoding="utf-8",
    )
    store = SslErrorsStore(str(cache_log), seed_max_lines=10)
    samples: list[str] = []

    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "_connect", lambda: nullcontext(object()))
    monkeypatch.setattr(store, "_latest_seen_ts", lambda _conn: 0)
    monkeypatch.setattr(
        store,
        "_upsert",
        lambda _conn, _domain, _category, _reason, _ts, sample: samples.append(
            sample,
        ),
    )

    store.seed_from_recent_log()

    assert samples == ["TLS handshake failed host=complete.example"]


def test_read_last_lines_preserves_complete_blank_and_replacement_lines(
    tmp_path: Path,
) -> None:
    cache_log = tmp_path / "cache.log"
    cache_log.write_bytes(b"discard\nvalid \xff\n\n")

    assert SslErrorsStore(str(cache_log))._read_last_lines(2) == ["valid �", ""]
