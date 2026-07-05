from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _read(path: str) -> str:
    return (REPO_ROOT / path).read_text(encoding="utf-8")


def test_admin_log_select_options_have_explicit_dark_popup_colors() -> None:
    text = _read("web/static/style.css")

    assert "select option{" in text
    assert "background: var(--panel-strong);" in text
    assert "color: var(--text);" in text


def test_proxy_entrypoint_emits_squid_cache_prepare_context() -> None:
    text = _read("docker/entrypoint.sh")

    assert "[proxy-entrypoint] preparing squid cache dirs" in text
    assert "existing_pidfile=" in text
    assert "squid_pids=" in text
    assert "[proxy-entrypoint] starting supervisord" in text


def test_proxy_entrypoint_suppresses_remote_clamd_download_respmod() -> None:
    text = _read("docker/entrypoint.sh")

    assert "CLAMD_HOST_IS_REMOTE=1" in text
    assert "localhost|127.*|::1|\\[::1\\]) CLAMD_HOST_IS_REMOTE=0" in text
    assert "[proxy-entrypoint] WARNING:" in text
    assert "c-icap virus_scan passes local temporary file paths to clamd" in text
    assert "if [ \"$CLAMD_HOST_IS_REMOTE\" = \"1\" ]; then" in text
    assert "# ${REMOTE_CLAMD_DOWNLOAD_WARNING}" in text
    assert "adaptation_access av_resp_set allow file_security_download_methods" in text
