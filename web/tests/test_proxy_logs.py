from __future__ import annotations


def test_proxy_logs_reads_only_allowlisted_current_file_tail(
    monkeypatch, tmp_path
) -> None:
    from services import proxy_logs

    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "access.log").write_text("first\nsecond\nthird\n", encoding="utf-8")
    monkeypatch.setenv("LOG_DIR", str(log_dir))

    payload = proxy_logs.read_proxy_log("access", max_bytes=13)

    assert payload["ok"] is True
    assert payload["content"] == "second\nthird\n"
    assert payload["truncated"] is True
    assert payload["size_bytes"] == 19


def test_proxy_logs_rejects_arbitrary_path_input(monkeypatch, tmp_path) -> None:
    from services import proxy_logs

    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (tmp_path / "passwd").write_text("secret\n", encoding="utf-8")
    monkeypatch.setenv("LOG_DIR", str(log_dir))

    payload = proxy_logs.read_proxy_log("../passwd")

    assert payload["ok"] is False
    assert payload["status"] == "not_found"
    assert "content" not in payload


def test_proxy_logs_missing_allowlisted_file_is_graceful(monkeypatch, tmp_path) -> None:
    from services import proxy_logs

    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    monkeypatch.setenv("LOG_DIR", str(log_dir))

    payload = proxy_logs.read_proxy_log("cache")

    assert payload["ok"] is False
    assert payload["status"] == "missing"
    assert payload["content"] == ""
    assert payload["logs"]
