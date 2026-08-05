from __future__ import annotations

import io
import json
from typing import Any

from services.version_status import (
    _MAX_GITHUB_API_RESPONSE_BYTES,
    VersionStatusClient,
    build_component_version_status,
    current_component_metadata,
)

from .admin_route_test_utils import FakeProxyClient, load_admin_app, login_client


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


class _TrackingResponse(_Response):
    def __init__(self, payload: bytes) -> None:
        super().__init__(payload)
        self.read_sizes: list[int] = []

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        return super().read(size)


def _json_response(payload: dict[str, Any]) -> _Response:
    return _Response(json.dumps(payload).encode("utf-8"))


def test_current_component_metadata_preserves_published_image_identity(
    monkeypatch,
) -> None:
    monkeypatch.setenv("APP_VERSION", "main")
    monkeypatch.setenv("GIT_COMMIT", "dfae11636e8e00b74983b8335ad427d2a07c8119")
    monkeypatch.setenv("GIT_REF_NAME", "main")
    monkeypatch.setenv("BUILD_DATE", "2026-07-17T20:00:00Z")
    monkeypatch.setenv(
        "IMAGE_NAME",
        "ghcr.io/kklouzal/docker_proxy-admin-ui",
    )

    metadata = current_component_metadata("admin-ui")

    assert metadata["component"] == "admin-ui"
    assert metadata["version"] == "main"
    assert metadata["revision_short"] == "dfae11636e8e"
    assert metadata["source_ref"] == "main"
    assert metadata["built_at"] == "2026-07-17T20:00:00Z"
    assert metadata["image"] == "ghcr.io/kklouzal/docker_proxy-admin-ui"


def test_current_component_status_counts_commits_behind_from_compare_api() -> None:
    def urlopen(request, *, timeout):
        assert "compare/abc123...main" in request.full_url
        assert abs(timeout - 0.5) < 0.001
        return _json_response(
            {
                "status": "ahead",
                "ahead_by": 3,
                "behind_by": 0,
                "total_commits": 3,
                "commits": [
                    {"sha": "badc0ffee"},
                    {"sha": "feedfacecafebeef"},
                ],
            }
        )

    client = VersionStatusClient(
        repository="owner/repo",
        timeout_seconds=0.5,
        urlopen=urlopen,
        monotonic=lambda: 10.0,
    )

    status = build_component_version_status(
        {"component": "admin-ui", "version": "main", "revision": "abc123"},
        client=client,
    )

    assert status["state"] == "outdated"
    assert status["commits_behind"] == 3
    assert status["latest_revision_short"] == "feedfacecafe"


def test_compare_revision_identical_main_is_ok() -> None:
    def urlopen(_request, *, timeout):
        return _json_response(
            {
                "status": "identical",
                "ahead_by": 0,
                "behind_by": 0,
                "total_commits": 0,
            }
        )

    client = VersionStatusClient(repository="owner/repo", urlopen=urlopen)

    status = client.compare_revision("abc123")

    assert status.state == "ok"
    assert status.commits_behind == 0
    assert status.latest_revision == "abc123"


def test_compare_revision_oversized_github_response_is_bounded_unknown() -> None:
    secret_body = b'{"detail":"ghp_secret-token should not leak", "padding":"'
    response = _TrackingResponse(
        secret_body + (b"x" * (_MAX_GITHUB_API_RESPONSE_BYTES + 1))
    )

    def urlopen(_request, *, timeout):
        return response

    client = VersionStatusClient(repository="owner/repo", urlopen=urlopen)

    status = client.compare_revision("abc123")

    assert status.state == "unknown"
    assert status.commits_behind is None
    assert "GitHub version check failed" in status.detail
    assert "exceeded" in status.detail
    assert str(_MAX_GITHUB_API_RESPONSE_BYTES) in status.detail
    assert "ghp_secret-token" not in status.detail
    assert "padding" not in status.detail
    assert response.read_sizes == [_MAX_GITHUB_API_RESPONSE_BYTES + 1]


def test_compare_revision_first_oversized_failure_is_not_ttl_cached() -> None:
    calls = {"count": 0}

    def urlopen(_request, *, timeout):
        calls["count"] += 1
        if calls["count"] == 1:
            return _Response(b"x" * (_MAX_GITHUB_API_RESPONSE_BYTES + 1))
        return _json_response(
            {
                "status": "identical",
                "ahead_by": 0,
                "behind_by": 0,
                "total_commits": 0,
            }
        )

    client = VersionStatusClient(
        repository="owner/repo",
        urlopen=urlopen,
        monotonic=lambda: 1.0,
    )

    first = client.compare_revision("abc123", ttl_seconds=3600)
    second = client.compare_revision("abc123", ttl_seconds=3600)

    assert first.state == "unknown"
    assert second.state == "ok"
    assert calls["count"] == 2


def test_compare_revision_rejects_status_count_contradiction() -> None:
    def urlopen(_request, *, timeout):
        return _json_response(
            {
                "status": "identical",
                "ahead_by": 1,
                "behind_by": 0,
                "total_commits": 1,
            }
        )

    client = VersionStatusClient(repository="owner/repo", urlopen=urlopen)

    status = client.compare_revision("abc123")

    assert status.state == "unknown"
    assert status.commits_behind is None
    assert "inconsistent status and counts" in status.detail


def test_compare_revision_running_commit_ahead_of_main_warns() -> None:
    def urlopen(_request, *, timeout):
        return _json_response(
            {
                "status": "behind",
                "ahead_by": 0,
                "behind_by": 2,
                "total_commits": 0,
                "commits": [],
            }
        )

    client = VersionStatusClient(repository="owner/repo", urlopen=urlopen)

    status = client.compare_revision("abc123")

    assert status.state == "warn"
    assert status.commits_behind == 0
    assert "2 commit(s) ahead" in status.detail


def test_compare_revision_diverged_reports_main_and_running_counts() -> None:
    def urlopen(_request, *, timeout):
        return _json_response(
            {
                "status": "diverged",
                "ahead_by": 4,
                "behind_by": 2,
                "total_commits": 4,
                "commits": [{"sha": "feedfacecafebeef"}],
            }
        )

    client = VersionStatusClient(repository="owner/repo", urlopen=urlopen)

    status = client.compare_revision("abc123")

    assert status.state == "warn"
    assert status.commits_behind == 4
    assert status.latest_revision == "feedfacecafebeef"
    assert "(4 behind, 2 ahead)" in status.detail


def test_compare_revision_rejects_path_like_repository_without_github_call() -> None:
    def urlopen(request, *, timeout):
        msg = f"unexpected GitHub call to {request.full_url}"
        raise AssertionError(msg)

    client = VersionStatusClient(repository="owner/repo/issues", urlopen=urlopen)

    status = client.compare_revision("abc123")

    assert status.state == "unknown"
    assert status.commits_behind is None
    assert "repository" in status.detail


def test_compare_revision_rejects_unsafe_branch_config_without_github_call(
    monkeypatch,
) -> None:
    monkeypatch.setenv("VERSION_STATUS_GITHUB_BRANCH", "refs/heads/main\nother")

    def urlopen(request, *, timeout):
        msg = f"unexpected GitHub call to {request.full_url}"
        raise AssertionError(msg)

    client = VersionStatusClient(
        repository="owner/repo",
        urlopen=urlopen,
    )

    status = client.compare_revision("abc123")

    assert status.state == "unknown"
    assert status.commits_behind is None
    assert "GitHub version check disabled" in status.detail
    assert "branch" in status.detail


def test_compare_revision_preserves_safe_configured_branch_in_compare_url() -> None:
    seen_urls: list[str] = []

    def urlopen(request, *, timeout):
        seen_urls.append(request.full_url)
        return _json_response(
            {
                "status": "identical",
                "ahead_by": 0,
                "behind_by": 0,
                "total_commits": 0,
            }
        )

    client = VersionStatusClient(
        repository="owner/repo",
        branch="release/2026.07",
        urlopen=urlopen,
    )

    status = client.compare_revision("abc123")

    assert status.state == "ok"
    assert seen_urls == [
        "https://api.github.com/repos/owner/repo/compare/abc123...release%2F2026.07"
    ]


def test_compare_cache_survives_later_github_failure() -> None:
    calls = {"count": 0}

    def urlopen(_request, *, timeout):
        calls["count"] += 1
        if calls["count"] == 1:
            return _json_response(
                {
                    "status": "identical",
                    "ahead_by": 0,
                    "behind_by": 0,
                    "total_commits": 0,
                }
            )
        msg = "network down"
        raise OSError(msg)

    now = {"value": 1.0}
    client = VersionStatusClient(
        repository="owner/repo",
        urlopen=urlopen,
        monotonic=lambda: now["value"],
    )

    first = client.compare_revision("abc123", ttl_seconds=1)
    now["value"] = 5.0
    second = client.compare_revision("abc123", ttl_seconds=1)

    assert first.state == "ok"
    assert second.state == "ok"
    assert calls["count"] == 2


def test_missing_running_commit_is_unknown_without_github_call() -> None:
    def urlopen(_request, *, timeout):
        msg = "GitHub should not be called"
        raise AssertionError(msg)

    client = VersionStatusClient(urlopen=urlopen)

    status = client.compare_revision("")

    assert status.state == "unknown"
    assert "No running commit" in status.detail


class _VersionedProxyClient(FakeProxyClient):
    def get_health(self, proxy_id: object, *args: Any, **kwargs: Any) -> dict[str, Any]:
        payload = super().get_health(proxy_id, *args, **kwargs)
        payload["version"] = {
            "component": "proxy",
            "version": "main",
            "revision": "abc123",
            "revision_short": "abc123",
        }
        return payload


def test_api_version_status_uses_selected_proxy_health_metadata(
    monkeypatch,
    tmp_path,
) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    loaded.module._ADMIN_VERSION_STATUS_CACHE = (
        999999999.0,
        {
            "component": "admin-ui",
            "version": "main",
            "state": "ok",
            "commits_behind": 0,
            "detail": "cached",
        },
    )
    monkeypatch.setattr(
        loaded.module,
        "get_proxy_client",
        lambda: _VersionedProxyClient(loaded.module),
    )
    monkeypatch.setattr(
        loaded.module,
        "build_component_version_status",
        lambda metadata: {
            "component": metadata.get("component"),
            "version": metadata.get("version"),
            "revision_short": metadata.get("revision_short", "abc123"),
            "state": "outdated" if metadata.get("component") == "proxy" else "ok",
            "commits_behind": 2 if metadata.get("component") == "proxy" else 0,
            "detail": "checked",
        },
    )
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/api/version-status")

    assert response.status_code == 200
    assert response.json["admin"]["state"] == "ok"
    assert response.json["proxy"]["component"] == "proxy"
    assert response.json["proxy"]["commits_behind"] == 2


def test_layout_renders_compact_version_status_without_github_call(
    monkeypatch,
    tmp_path,
) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    monkeypatch.setenv("APP_VERSION", "main")
    monkeypatch.setattr(
        loaded.module,
        "build_component_version_status",
        lambda _metadata: (_ for _ in ()).throw(AssertionError("no github")),
    )
    client = loaded.module.app.test_client()
    login_client(client)

    response = client.get("/")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert 'id="version-status"' in body
    assert 'data-version-status-url="/api/version-status' in body
    assert ">Admin<" in body
    assert ">Proxy<" in body
