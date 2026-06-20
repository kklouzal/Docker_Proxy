from __future__ import annotations

from services import proxy_logs


def test_proxy_logs_reads_only_allowlisted_current_file_tail(
    monkeypatch, tmp_path
) -> None:
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
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (tmp_path / "passwd").write_text("secret\n", encoding="utf-8")
    monkeypatch.setenv("LOG_DIR", str(log_dir))

    payload = proxy_logs.read_proxy_log("../passwd")

    assert payload["ok"] is False
    assert payload["status"] == "not_found"
    assert "content" not in payload


def test_proxy_logs_rejects_allowlisted_symlink_outside_log_dir(
    monkeypatch, tmp_path
) -> None:
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    outside = tmp_path / "outside.log"
    outside.write_text("secret\n", encoding="utf-8")
    (log_dir / "access.log").symlink_to(outside)
    monkeypatch.setenv("LOG_DIR", str(log_dir))

    payload = proxy_logs.read_proxy_log("access")
    logs = proxy_logs.list_proxy_logs()
    access_log = next(item for item in logs if item["key"] == "access")

    assert payload["ok"] is False
    assert payload["status"] == "not_found"
    assert "content" not in payload
    assert access_log["available"] is False
    assert access_log["path"] == str(log_dir / "access.log")


def test_proxy_logs_missing_allowlisted_file_is_graceful(monkeypatch, tmp_path) -> None:
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    monkeypatch.setenv("LOG_DIR", str(log_dir))

    payload = proxy_logs.read_proxy_log("cache")

    assert payload["ok"] is False
    assert payload["status"] == "missing"
    assert payload["content"] == ""
    assert payload["logs"]


def test_proxy_logs_unreadable_allowlisted_file_is_server_error(
    monkeypatch, tmp_path
) -> None:
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "access.log").write_text("alpha\n", encoding="utf-8")
    monkeypatch.setenv("LOG_DIR", str(log_dir))
    monkeypatch.setattr(
        proxy_logs,
        "_tail_bytes",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("permission denied")),
    )

    payload = proxy_logs.read_proxy_log("access")

    assert payload["ok"] is False
    assert payload["status"] == "unavailable"
    assert payload["content"] == ""
    assert proxy_logs.proxy_log_status_code(payload) == 500
    assert proxy_logs.proxy_log_status_code({"ok": False, "status": "not_found"}) == 404
