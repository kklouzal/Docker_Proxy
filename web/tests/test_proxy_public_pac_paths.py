from __future__ import annotations

import json
import sys
from pathlib import Path


def _add_repo_paths() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    web_root = repo_root / "web"
    for path in (repo_root, web_root):
        path_str = str(path)
        if path_str not in sys.path:
            sys.path.insert(0, path_str)


def _write_pac_artifacts(pac_dir: Path, *, public_pac_path: str) -> None:
    pac_dir.mkdir()
    (pac_dir / ".state-sha256").write_text("state-one\n", encoding="utf-8")
    (pac_dir / "manifest.json").write_text(
        json.dumps(
            {
                "fallback_file": "fallback.pac",
                "public_pac_path": public_pac_path,
                "state_sha256": "state-one",
            },
        ),
        encoding="utf-8",
    )
    (pac_dir / "fallback.pac").write_text("PAC __PAC_PROXY_HOST__", encoding="utf-8")


def test_public_listener_serves_configured_pac_path(tmp_path, monkeypatch) -> None:
    _add_repo_paths()
    from services import pac_http  # type: ignore

    from proxy import app as proxy_app  # type: ignore

    pac_dir = tmp_path / "pac"
    _write_pac_artifacts(pac_dir, public_pac_path="/download/wpad.dat?site=lab")
    monkeypatch.setenv("PAC_RENDER_DIR", str(pac_dir))
    monkeypatch.setenv("PAC_HTTP_PORT", "80")
    pac_http.pac_render_dir.cache_clear()
    pac_http._CACHES.clear()

    client = proxy_app.app.test_client()
    response = client.get(
        "/download/wpad.dat?site=lab",
        base_url="http://public-proxy.example",
    )

    assert response.status_code == 200
    assert response.data == b"PAC public-proxy.example"
    assert response.headers["Content-Disposition"] == 'inline; filename="wpad.dat"'


def test_public_listener_serves_percent_encoded_configured_pac_path(
    tmp_path,
    monkeypatch,
) -> None:
    _add_repo_paths()
    from services import pac_http  # type: ignore

    from proxy import app as proxy_app  # type: ignore

    pac_dir = tmp_path / "pac"
    _write_pac_artifacts(pac_dir, public_pac_path="/download/%77pad.dat?site=lab")
    monkeypatch.setenv("PAC_RENDER_DIR", str(pac_dir))
    monkeypatch.setenv("PAC_HTTP_PORT", "80")
    pac_http.pac_render_dir.cache_clear()
    pac_http._CACHES.clear()

    client = proxy_app.app.test_client()
    response = client.get(
        "/download/%77pad.dat?site=lab",
        base_url="http://public-proxy.example",
    )

    assert response.status_code == 200
    assert response.data == b"PAC public-proxy.example"
    assert response.headers["Content-Disposition"] == 'inline; filename="wpad.dat"'


def test_public_listener_rejects_wrong_query_for_configured_pac_path(
    tmp_path,
    monkeypatch,
) -> None:
    _add_repo_paths()
    from services import pac_http  # type: ignore

    from proxy import app as proxy_app  # type: ignore

    pac_dir = tmp_path / "pac"
    _write_pac_artifacts(pac_dir, public_pac_path="/download/wpad.dat?site=lab")
    monkeypatch.setenv("PAC_RENDER_DIR", str(pac_dir))
    monkeypatch.setenv("PAC_HTTP_PORT", "80")
    pac_http.pac_render_dir.cache_clear()
    pac_http._CACHES.clear()

    client = proxy_app.app.test_client()

    assert (
        client.get(
            "/download/wpad.dat?site=other",
            base_url="http://public-proxy.example",
        ).status_code
        == 404
    )
    assert (
        client.get(
            "/download/wpad.dat",
            base_url="http://public-proxy.example",
        ).status_code
        == 404
    )


def test_public_listener_rejects_unconfigured_pac_path(tmp_path, monkeypatch) -> None:
    _add_repo_paths()
    from services import pac_http  # type: ignore

    from proxy import app as proxy_app  # type: ignore

    pac_dir = tmp_path / "pac"
    _write_pac_artifacts(pac_dir, public_pac_path="/download/wpad.dat")
    monkeypatch.setenv("PAC_RENDER_DIR", str(pac_dir))
    monkeypatch.setenv("PAC_HTTP_PORT", "80")
    pac_http.pac_render_dir.cache_clear()
    pac_http._CACHES.clear()

    client = proxy_app.app.test_client()
    response = client.get("/download/other.pac", base_url="http://public-proxy.example")

    assert response.status_code == 404


def test_public_listener_rejects_manifest_backslash_traversal(
    tmp_path,
    monkeypatch,
) -> None:
    _add_repo_paths()
    from services import pac_http  # type: ignore

    from proxy import app as proxy_app  # type: ignore

    pac_dir = tmp_path / "pac"
    pac_dir.mkdir()
    (pac_dir / "subdir").mkdir()
    (tmp_path / "escape.pac").write_text(
        "PAC __PAC_PROXY_HOST__ outside",
        encoding="utf-8",
    )
    (pac_dir / ".state-sha256").write_text("state-one\n", encoding="utf-8")
    (pac_dir / "manifest.json").write_text(
        json.dumps(
            {
                "fallback_file": r"subdir\..\..\escape.pac",
                "public_pac_path": "/proxy.pac",
                "state_sha256": "state-one",
            },
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("PAC_RENDER_DIR", str(pac_dir))
    monkeypatch.setenv("PAC_HTTP_PORT", "80")
    pac_http.pac_render_dir.cache_clear()
    pac_http._CACHES.clear()

    client = proxy_app.app.test_client()
    response = client.get("/proxy.pac", base_url="http://public-proxy.example")

    assert response.status_code == 200
    assert b"outside" not in response.data
    assert b"FindProxyForURL" in response.data
