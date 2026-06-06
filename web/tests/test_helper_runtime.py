from __future__ import annotations

import json


def test_split_acl_channel_and_write_response(capsys) -> None:
    from services.helper_runtime import split_acl_channel, write_acl_response

    assert split_acl_channel("12 src.example category") == (
        "12",
        ["src.example", "category"],
    )
    assert split_acl_channel("src.example category") == (
        None,
        ["src.example", "category"],
    )

    write_acl_response("12", True)
    write_acl_response(None, False)
    write_acl_response("13", True, message="category=adult social")

    assert capsys.readouterr().out == "12 OK\nERR\n13 OK message=category=adult%20social\n"


def test_helper_event_writes_json_to_stderr(capsys) -> None:
    from services.helper_runtime import helper_event

    helper_event("sample", "startup", value=3, skipped=None)

    payload = json.loads(capsys.readouterr().err)
    assert payload["helper"] == "sample"
    assert payload["event"] == "startup"
    assert payload["value"] == 3
    assert "skipped" not in payload


def test_helper_stats_emits_snapshot_without_blocking_increments(
    monkeypatch, capsys
) -> None:
    from services import helper_runtime

    clock = {"now": 10.0}
    monkeypatch.setattr(helper_runtime.time, "monotonic", lambda: clock["now"])
    stats = helper_runtime.HelperStats("sample", emit_interval_seconds=5.0)

    stats.increment("requests")
    stats.emit_if_due()
    assert capsys.readouterr().err == ""

    clock["now"] = 16.0
    stats.emit_if_due()
    payload = json.loads(capsys.readouterr().err)
    assert payload["event"] == "stats"
    assert payload["requests"] == 1

    stats.increment("requests", 2)
    stats.emit_if_due(force=True)
    payload = json.loads(capsys.readouterr().err)
    assert payload["requests"] == 3


def test_ttl_lru_cache_expires_and_evicts(monkeypatch) -> None:
    from services import helper_runtime

    clock = {"now": 10.0}
    monkeypatch.setattr(helper_runtime.time, "monotonic", lambda: clock["now"])
    cache = helper_runtime.TtlLruCache(max_entries=2, ttl_seconds=5.0)

    cache.put("a", 1)
    cache.put("b", 2)
    assert cache.get("a") == 1
    cache.put("c", 3)
    assert cache.get("b") is None
    assert cache.get("a") == 1
    clock["now"] = 20.0
    assert cache.get("a") is None
