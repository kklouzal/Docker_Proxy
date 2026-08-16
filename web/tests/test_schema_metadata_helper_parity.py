from __future__ import annotations

import pytest
from services import adblock_store, live_stats, webfilter_store


@pytest.mark.parametrize(
    ("module", "owner"),
    [
        (adblock_store, adblock_store.AdblockStore),
        (live_stats, live_stats.LiveStatsStore),
        (webfilter_store, webfilter_store.WebFilterStore),
    ],
)
def test_store_index_adapter_preserves_injected_connection_and_contract(
    monkeypatch, module, owner
) -> None:
    conn = object()
    calls: list[tuple[object, str, str, str]] = []

    def shared_ensure_index(
        passed_conn, *, table_name: str, index_name: str, ddl: str
    ) -> bool:
        calls.append((passed_conn, table_name, index_name, ddl))
        return True

    monkeypatch.setattr(module, "ensure_index", shared_ensure_index)

    result = owner._ensure_index(
        conn,
        "sample_table",
        "idx_sample",
        "ALTER TABLE sample_table ADD INDEX idx_sample (id)",
    )

    assert result is None
    assert calls == [
        (
            conn,
            "sample_table",
            "idx_sample",
            "ALTER TABLE sample_table ADD INDEX idx_sample (id)",
        )
    ]


def test_webfilter_column_adapter_preserves_injected_connection_and_contract(
    monkeypatch,
) -> None:
    conn = object()
    calls: list[tuple[object, str, str, str]] = []

    def shared_ensure_column(
        passed_conn, *, table_name: str, column_name: str, ddl: str
    ) -> bool:
        calls.append((passed_conn, table_name, column_name, ddl))
        return True

    monkeypatch.setattr(webfilter_store, "ensure_column", shared_ensure_column)

    result = webfilter_store.WebFilterStore._ensure_column(
        conn,
        "sample_table",
        "sample_column",
        "ALTER TABLE sample_table ADD COLUMN sample_column INT",
    )

    assert result is None
    assert calls == [
        (
            conn,
            "sample_table",
            "sample_column",
            "ALTER TABLE sample_table ADD COLUMN sample_column INT",
        )
    ]
