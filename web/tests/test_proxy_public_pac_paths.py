from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


def _add_repo_paths() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    web_root = repo_root / "web"
    for path in (repo_root, web_root):
        path_str = str(path)
        if path_str not in sys.path:
            sys.path.insert(0, path_str)


def _write_pac_artifacts(
    pac_dir: Path,
    *,
    public_pac_path: str | None = None,
    public_pac_url: str | None = None,
) -> None:
    pac_dir.mkdir()
    manifest = {
        "fallback_file": "fallback.pac",
        "state_sha256": "state-one",
    }
    if public_pac_path is not None:
        manifest["public_pac_path"] = public_pac_path
    if public_pac_url is not None:
        manifest["public_pac_url"] = public_pac_url
    (pac_dir / ".state-sha256").write_text("state-one\n", encoding="utf-8")
    (pac_dir / "manifest.json").write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )
    (pac_dir / "fallback.pac").write_text("PAC __PAC_PROXY_HOST__", encoding="utf-8")


@pytest.fixture
def public_pac_client(monkeypatch):
    _add_repo_paths()
    from services import pac_http  # type: ignore

    from proxy import app as proxy_app  # type: ignore

    def build_client(pac_dir: Path):
        monkeypatch.setenv("PAC_RENDER_DIR", str(pac_dir))
        monkeypatch.setenv("PAC_HTTP_PORT", "80")
        pac_http.pac_render_dir.cache_clear()
        pac_http._CACHES.clear()
        return proxy_app.app.test_client()

    return build_client


def test_public_listener_serves_configured_pac_path(tmp_path, public_pac_client) -> None:
    pac_dir = tmp_path / "pac"
    _write_pac_artifacts(pac_dir, public_pac_path="/download/wpad.dat?site=lab")
    client = public_pac_client(pac_dir)
    response = client.get(
        "/download/wpad.dat?site=lab",
        base_url="http://public-proxy.example",
    )

    assert response.status_code == 200
    assert response.data == b"PAC public-proxy.example"
    assert response.headers["Content-Disposition"] == 'inline; filename="wpad.dat"'


def test_public_listener_fallback_pac_rejects_single_label_request_host(
    tmp_path,
    public_pac_client,
) -> None:
    pac_dir = tmp_path / "pac"
    _write_pac_artifacts(pac_dir)
    client = public_pac_client(pac_dir)

    response = client.get("/proxy.pac", base_url="http://proxy")

    assert response.status_code == 200
    assert response.data == b"PAC 127.0.0.1"
    assert b"PAC proxy" not in response.data


def test_public_listener_serves_configured_pac_url_path(
    tmp_path,
    public_pac_client,
) -> None:
    pac_dir = tmp_path / "pac"
    _write_pac_artifacts(
        pac_dir,
        public_pac_url="https://pac.example/download/wpad.dat?site=lab",
    )
    client = public_pac_client(pac_dir)
    response = client.get(
        "/download/wpad.dat?site=lab",
        base_url="http://public-proxy.example",
    )

    assert response.status_code == 200
    assert response.data == b"PAC public-proxy.example"
    assert response.headers["Content-Disposition"] == 'inline; filename="wpad.dat"'


def test_public_listener_serves_percent_encoded_configured_pac_path(
    tmp_path,
    public_pac_client,
) -> None:
    pac_dir = tmp_path / "pac"
    _write_pac_artifacts(pac_dir, public_pac_path="/download/%77pad.dat?site=lab")
    client = public_pac_client(pac_dir)
    response = client.get(
        "/download/%77pad.dat?site=lab",
        base_url="http://public-proxy.example",
    )

    assert response.status_code == 200
    assert response.data == b"PAC public-proxy.example"
    assert response.headers["Content-Disposition"] == 'inline; filename="wpad.dat"'


def test_public_listener_serves_configured_pac_path_with_encoded_query_space(
    tmp_path,
    public_pac_client,
) -> None:
    pac_dir = tmp_path / "pac"
    _write_pac_artifacts(pac_dir, public_pac_path="/download/wpad.dat?site=lab%20one")
    client = public_pac_client(pac_dir)
    response = client.get(
        "/download/wpad.dat?site=lab%20one",
        base_url="http://public-proxy.example",
    )

    assert response.status_code == 200
    assert response.data == b"PAC public-proxy.example"
    assert response.headers["Content-Disposition"] == 'inline; filename="wpad.dat"'


def test_public_listener_rejects_encoded_separator_alias_for_configured_pac_path(
    tmp_path,
    public_pac_client,
) -> None:
    pac_dir = tmp_path / "pac"
    _write_pac_artifacts(pac_dir, public_pac_path="/download/wpad.dat")
    client = public_pac_client(pac_dir)
    response = client.get(
        "/download%2fwpad.dat",
        base_url="http://public-proxy.example",
    )

    assert response.status_code == 404
    assert b"PAC public-proxy.example" not in response.data


def test_public_listener_rejects_wrong_query_for_configured_pac_path(
    tmp_path,
    public_pac_client,
) -> None:
    pac_dir = tmp_path / "pac"
    _write_pac_artifacts(pac_dir, public_pac_path="/download/wpad.dat?site=lab")
    client = public_pac_client(pac_dir)

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


def test_public_listener_rejects_unconfigured_pac_path(
    tmp_path,
    public_pac_client,
) -> None:
    pac_dir = tmp_path / "pac"
    _write_pac_artifacts(pac_dir, public_pac_path="/download/wpad.dat")
    client = public_pac_client(pac_dir)
    response = client.get("/download/other.pac", base_url="http://public-proxy.example")

    assert response.status_code == 404


def test_public_listener_rejects_manifest_backslash_traversal(
    tmp_path,
    public_pac_client,
) -> None:
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
    client = public_pac_client(pac_dir)
    response = client.get("/proxy.pac", base_url="http://public-proxy.example")

    assert response.status_code == 200
    assert b"outside" not in response.data
    assert b"FindProxyForURL" in response.data
