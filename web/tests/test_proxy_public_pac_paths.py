from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from werkzeug.test import Client

if TYPE_CHECKING:
    from pathlib import Path


def _write_verified_state(
    pac_dir: Path,
    manifest: dict[str, object],
    files: dict[str, str],
) -> None:
    from services.pac_request import (  # type: ignore
        calculate_pac_manifest_state_sha,
        render_pac_manifest_text,
    )

    pac_dir.mkdir(exist_ok=True)
    state_sha = calculate_pac_manifest_state_sha(manifest, files)
    for rel_path, content in files.items():
        (pac_dir / rel_path).write_text(content, encoding="utf-8")
    (pac_dir / "manifest.json").write_text(
        render_pac_manifest_text({**manifest, "state_sha256": state_sha}),
        encoding="utf-8",
    )
    (pac_dir / ".state-sha256").write_text(state_sha + "\n", encoding="utf-8")


def _write_pac_artifacts(
    pac_dir: Path,
    *,
    public_pac_path: str | None = None,
    public_pac_url: str | None = None,
) -> None:
    manifest: dict[str, object] = {"fallback_file": "fallback.pac"}
    if public_pac_path is not None:
        manifest["public_pac_path"] = public_pac_path
    if public_pac_url is not None:
        manifest["public_pac_url"] = public_pac_url
    _write_verified_state(pac_dir, manifest, {"fallback.pac": "PAC __PAC_PROXY_HOST__"})


@pytest.fixture
def public_pac_client(monkeypatch):
    from services import pac_http  # type: ignore

    from proxy import public_app as proxy_app  # type: ignore

    def build_client(pac_dir: Path):
        monkeypatch.setenv("PAC_RENDER_DIR", str(pac_dir))
        monkeypatch.setenv("PAC_HTTP_PORT", "80")
        pac_http.pac_render_dir.cache_clear()
        pac_http._CACHES.clear()
        return Client(proxy_app.app)

    return build_client


def test_public_listener_serves_configured_pac_path(
    tmp_path, public_pac_client
) -> None:
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
    assert response.headers["Cache-Control"] == "private, max-age=30"


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


def test_public_listener_allows_safe_percent_encoded_query_on_default_pac_path(
    tmp_path,
    public_pac_client,
) -> None:
    pac_dir = tmp_path / "pac"
    _write_pac_artifacts(pac_dir)
    client = public_pac_client(pac_dir)
    response = client.get(
        "/proxy.pac?client=lab%20one",
        base_url="http://public-proxy.example",
    )

    assert response.status_code == 200
    assert response.data == b"PAC public-proxy.example"


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


def test_public_listener_rejects_ambiguous_forwarded_host_chain(
    tmp_path,
    public_pac_client,
    monkeypatch,
) -> None:
    pac_dir = tmp_path / "pac"
    _write_pac_artifacts(pac_dir)
    monkeypatch.setenv("PAC_TRUSTED_PROXY_CIDRS", "127.0.0.0/8")
    client = public_pac_client(pac_dir)

    response = client.get(
        "/proxy.pac",
        base_url="http://internal-proxy.example",
        headers={"X-Forwarded-Host": "attacker.example:4444, public-proxy.example:80"},
    )

    assert response.status_code == 200
    assert response.data == b"PAC internal-proxy.example"
    assert b"attacker.example" not in response.data


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
    # The verified state holds only fallback.pac; reading the traversal target
    # would add a file outside that state and fail verification.
    _write_verified_state(
        pac_dir,
        {
            "fallback_file": "fallback.pac",
            "public_pac_path": "/proxy.pac",
            "profiles": [
                {"client_cidr": "0.0.0.0/0", "file": r"subdir\..\..\escape.pac"},
            ],
        },
        {"fallback.pac": "PAC __PAC_PROXY_HOST__"},
    )
    client = public_pac_client(pac_dir)
    response = client.get("/proxy.pac", base_url="http://public-proxy.example")

    assert response.status_code == 200
    assert response.data == b"PAC public-proxy.example"
