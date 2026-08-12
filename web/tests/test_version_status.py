from __future__ import annotations

import io
import json
import threading
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from services import version_status
from services.version_status import (
    _MAX_GITHUB_API_RESPONSE_BYTES,
    _MAX_VERSION_STATUS_CACHE_ENTRIES,
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


def _branch_ref_response(request, sha: str = "f" * 40) -> _Response:
    branch = request.full_url.split("/git/ref/heads/", 1)[1]
    branch = urllib.parse.unquote(branch)
    return _json_response(
        {"ref": f"refs/heads/{branch}", "object": {"type": "commit", "sha": sha}}
    )


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
        if "/git/ref/heads/" in request.full_url:
            return _branch_ref_response(request)
        assert "compare/abc123..." + ("f" * 40) in request.full_url
        assert abs(timeout - 0.5) < 0.001
        return _json_response(
            {
                "status": "ahead",
                "ahead_by": 3,
                "behind_by": 0,
                "total_commits": 3,
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
    assert status["latest_revision_short"] == "ffffffffffff"


def test_compare_revision_identical_main_is_ok() -> None:
    def urlopen(_request, *, timeout):
        if "/git/ref/heads/" in _request.full_url:
            return _branch_ref_response(_request)
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
    assert status.latest_revision == "f" * 40


def test_compare_revision_freezes_branch_tip_and_needs_no_paginated_head_commit() -> (
    None
):
    tip = "a" * 40
    seen_urls: list[str] = []

    def urlopen(request, *, timeout):
        seen_urls.append(request.full_url)
        if "/git/ref/heads/" in request.full_url:
            return _branch_ref_response(request, tip)
        return _json_response(
            {
                "status": "ahead",
                "ahead_by": 1,
                "behind_by": 0,
                "total_commits": 1,
                "commits": [],
            }
        )

    status = VersionStatusClient(
        repository="owner/repo", branch="release/next", urlopen=urlopen
    ).compare_revision("abc123")

    assert status.state == "outdated"
    assert status.latest_revision == tip
    assert seen_urls == [
        "https://api.github.com/repos/owner/repo/git/ref/heads/release%2Fnext",
        f"https://api.github.com/repos/owner/repo/compare/abc123...{tip}?per_page=1&page=2",
    ]


def test_compare_revision_rejects_malformed_authoritative_tip_without_compare() -> None:
    seen_urls: list[str] = []

    def urlopen(request, *, timeout):
        seen_urls.append(request.full_url)
        return _json_response(
            {
                "ref": "refs/heads/main",
                "object": {"type": "commit", "sha": "not-a-full-commit-sha"},
            }
        )

    status = VersionStatusClient(
        repository="owner/repo", urlopen=urlopen
    ).compare_revision("abc123")

    assert status.state == "unknown"
    assert status.commits_behind is None
    assert "invalid commit identity" in status.detail
    assert seen_urls == ["https://api.github.com/repos/owner/repo/git/ref/heads/main"]


def test_compare_revision_rejects_mismatched_authoritative_ref_identity() -> None:
    def urlopen(request, *, timeout):
        return _json_response(
            {
                "ref": "refs/heads/other",
                "object": {"type": "commit", "sha": "a" * 40},
            }
        )

    status = VersionStatusClient(
        repository="owner/repo", urlopen=urlopen
    ).compare_revision("abc123")

    assert status.state == "unknown"
    assert "unexpected identity" in status.detail


def test_compare_revision_oversized_github_response_is_bounded_unknown() -> None:
    secret_body = b'{"detail":"ghp_secret-token should not leak", "padding":"'
    response = _TrackingResponse(
        secret_body + (b"x" * (_MAX_GITHUB_API_RESPONSE_BYTES + 1))
    )

    def urlopen(_request, *, timeout):
        if "/git/ref/heads/" in _request.full_url:
            return _branch_ref_response(_request)
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
        if "/git/ref/heads/" in _request.full_url:
            return _branch_ref_response(_request)
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


def test_default_client_failure_is_retried_and_can_recover(
    monkeypatch,
) -> None:
    monkeypatch.setenv("VERSION_STATUS_GITHUB_REPOSITORY", "retry/repo")
    calls = {"count": 0}

    def urlopen(_request, *, timeout):
        if "/git/ref/heads/" in _request.full_url:
            return _branch_ref_response(_request)
        calls["count"] += 1
        if calls["count"] == 1:
            msg = "temporary outage"
            raise OSError(msg)
        return _json_response(
            {
                "status": "identical",
                "ahead_by": 0,
                "behind_by": 0,
                "total_commits": 0,
            }
        )

    monkeypatch.setattr(version_status.urllib.request, "urlopen", urlopen)

    failed = build_component_version_status({"revision": "retry-revision"})
    recovered = build_component_version_status({"revision": "retry-revision"})

    assert failed["state"] == "unknown"
    assert recovered["state"] == "ok"
    assert calls["count"] == 2


def test_compare_revision_rejects_status_count_contradiction() -> None:
    def urlopen(_request, *, timeout):
        if "/git/ref/heads/" in _request.full_url:
            return _branch_ref_response(_request)
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
        if "/git/ref/heads/" in _request.full_url:
            return _branch_ref_response(_request)
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
        if "/git/ref/heads/" in _request.full_url:
            return _branch_ref_response(_request)
        return _json_response(
            {
                "status": "diverged",
                "ahead_by": 4,
                "behind_by": 2,
                "total_commits": 4,
            }
        )

    client = VersionStatusClient(repository="owner/repo", urlopen=urlopen)

    status = client.compare_revision("abc123")

    assert status.state == "warn"
    assert status.commits_behind == 4
    assert status.latest_revision == "f" * 40
    assert "(4 behind, 2 ahead)" in status.detail


def test_compare_revision_rejects_path_like_repository_without_github_call() -> None:
    def urlopen(request, *, timeout):
        if "/git/ref/heads/" in request.full_url:
            return _branch_ref_response(request)
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
        if "/git/ref/heads/" in request.full_url:
            return _branch_ref_response(request)
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
        if "/git/ref/heads/" in request.full_url:
            return _branch_ref_response(request)
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
        "https://api.github.com/repos/owner/repo/compare/abc123...ffffffffffffffffffffffffffffffffffffffff?per_page=1&page=2"
    ]


def test_compare_cache_marks_expired_success_stale_until_github_recovers() -> None:
    calls = {"count": 0}

    def urlopen(_request, *, timeout):
        if "/git/ref/heads/" in _request.full_url:
            return _branch_ref_response(_request)
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
        if calls["count"] == 2:
            msg = "network down"
            raise OSError(msg)
        if calls["count"] == 3:
            msg = "request timed out"
            raise TimeoutError(msg)
        return _json_response(
            {
                "status": "ahead",
                "ahead_by": 2,
                "behind_by": 0,
                "total_commits": 2,
            }
        )

    now = {"value": 1.0}
    client = VersionStatusClient(
        repository="owner/repo",
        urlopen=urlopen,
        monotonic=lambda: now["value"],
    )

    current = client.compare_revision("abc123", ttl_seconds=1)
    now["value"] = 1.5
    current_cache_hit = client.compare_revision("abc123", ttl_seconds=1)
    now["value"] = 3.0
    stale_after_failure = client.compare_revision("abc123", ttl_seconds=1)
    now["value"] = 4.0
    stale_after_repeated_failure = client.compare_revision("abc123", ttl_seconds=1)
    now["value"] = 5.0
    recovered = client.compare_revision("abc123", ttl_seconds=1)
    now["value"] = 5.5
    recovered_cache_hit = client.compare_revision("abc123", ttl_seconds=1)

    assert current.state == "ok"
    assert current_cache_hit == current
    assert stale_after_failure.state == "warn"
    assert stale_after_failure.commits_behind == 0
    assert stale_after_failure.latest_revision == "f" * 40
    assert "showing stale cached result" in stale_after_failure.detail
    assert "Running commit matches main" in stale_after_failure.detail
    assert "network down" in stale_after_failure.detail
    assert stale_after_repeated_failure.state == "warn"
    assert "showing stale cached result" in stale_after_repeated_failure.detail
    assert "request timed out" in stale_after_repeated_failure.detail
    assert recovered.state == "outdated"
    assert recovered.commits_behind == 2
    assert recovered.latest_revision == "f" * 40
    assert "stale" not in recovered.detail
    assert recovered_cache_hit == recovered
    assert calls["count"] == 4


def test_concurrent_compare_requests_for_one_revision_share_github_call() -> None:
    calls = {"count": 0}
    request_started = threading.Event()
    release_request = threading.Event()

    def urlopen(_request, *, timeout):
        if "/git/ref/heads/" in _request.full_url:
            return _branch_ref_response(_request)
        calls["count"] += 1
        request_started.set()
        assert release_request.wait(timeout=2)
        return _json_response(
            {
                "status": "identical",
                "ahead_by": 0,
                "behind_by": 0,
                "total_commits": 0,
            }
        )

    client = VersionStatusClient(repository="owner/repo", urlopen=urlopen)

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(client.compare_revision, "abc123")
        assert request_started.wait(timeout=2)
        second = executor.submit(client.compare_revision, "abc123")
        release_request.set()
        results = [first.result(timeout=2), second.result(timeout=2)]

    assert [result.state for result in results] == ["ok", "ok"]
    assert calls["count"] == 1


def test_compare_cache_evicts_least_recently_used_revision_at_fixed_bound() -> None:
    calls: list[str] = []

    def urlopen(request, *, timeout):
        if "/git/ref/heads/" in request.full_url:
            return _branch_ref_response(request)
        calls.append(request.full_url)
        return _json_response(
            {
                "status": "identical",
                "ahead_by": 0,
                "behind_by": 0,
                "total_commits": 0,
            }
        )

    client = VersionStatusClient(repository="owner/repo", urlopen=urlopen)

    for index in range(_MAX_VERSION_STATUS_CACHE_ENTRIES):
        client.compare_revision(f"revision-{index}")

    client.compare_revision("revision-0")
    client.compare_revision("overflow-revision")

    assert len(client._cache) == _MAX_VERSION_STATUS_CACHE_ENTRIES
    assert len(calls) == _MAX_VERSION_STATUS_CACHE_ENTRIES + 1
    assert "owner/repo:main:revision-0" in client._cache
    assert "owner/repo:main:revision-1" not in client._cache
    assert "owner/repo:main:overflow-revision" in client._cache

    client.compare_revision("revision-1")

    assert len(client._cache) == _MAX_VERSION_STATUS_CACHE_ENTRIES
    assert len(calls) == _MAX_VERSION_STATUS_CACHE_ENTRIES + 2


def test_default_client_cache_isolates_revisions_and_tracks_config_changes(
    monkeypatch,
) -> None:
    monkeypatch.setenv("VERSION_STATUS_GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("VERSION_STATUS_GITHUB_BRANCH", "main")
    seen_urls: list[str] = []

    def urlopen(request, *, timeout):
        if "/git/ref/heads/" in request.full_url:
            return _branch_ref_response(request)
        seen_urls.append(request.full_url)
        if "revision-a" in request.full_url:
            return _json_response(
                {
                    "status": "identical",
                    "ahead_by": 0,
                    "behind_by": 0,
                    "total_commits": 0,
                }
            )
        return _json_response(
            {
                "status": "ahead",
                "ahead_by": 2,
                "behind_by": 0,
                "total_commits": 2,
            }
        )

    monkeypatch.setattr(version_status.urllib.request, "urlopen", urlopen)

    revision_a = build_component_version_status({"revision": "revision-a"})
    revision_a["detail"] = "mutated by caller"
    revision_b = build_component_version_status({"revision": "revision-b"})
    revision_a_again = build_component_version_status({"revision": "revision-a"})
    revision_b_again = build_component_version_status({"revision": "revision-b"})
    monkeypatch.setenv("VERSION_STATUS_GITHUB_BRANCH", "release/next")
    after_config_change = build_component_version_status({"revision": "revision-a"})

    assert revision_a_again["state"] == "ok"
    assert revision_a_again["detail"] == "Running commit matches main."
    assert revision_b["state"] == "outdated"
    assert revision_b_again == revision_b
    assert after_config_change["state"] == "ok"
    assert after_config_change["detail"] == "Running commit matches release/next."
    assert seen_urls == [
        "https://api.github.com/repos/owner/repo/compare/revision-a...ffffffffffffffffffffffffffffffffffffffff?per_page=1&page=2",
        "https://api.github.com/repos/owner/repo/compare/revision-b...ffffffffffffffffffffffffffffffffffffffff?per_page=1&page=2",
        "https://api.github.com/repos/owner/repo/compare/revision-a...ffffffffffffffffffffffffffffffffffffffff?per_page=1&page=2",
    ]


def test_missing_running_commit_is_unknown_without_github_call() -> None:
    def urlopen(_request, *, timeout):
        if "/git/ref/heads/" in _request.full_url:
            return _branch_ref_response(_request)
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


def test_api_version_status_reuses_compare_cache_across_admin_and_proxy(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("GIT_COMMIT", "abc123")
    monkeypatch.setenv("VERSION_STATUS_GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("VERSION_STATUS_GITHUB_BRANCH", "main")
    monkeypatch.setenv("VERSION_STATUS_CACHE_TTL_SECONDS", "60")
    loaded = load_admin_app(monkeypatch, tmp_path)
    loaded.module._ADMIN_VERSION_STATUS_CACHE = None
    monkeypatch.setattr(
        loaded.module,
        "get_proxy_client",
        lambda: _VersionedProxyClient(loaded.module),
    )
    now = {"value": 100.0}
    monkeypatch.setattr(loaded.module.time, "monotonic", lambda: now["value"])
    calls = {"count": 0}

    def urlopen(_request, *, timeout):
        if "/git/ref/heads/" in _request.full_url:
            return _branch_ref_response(_request)
        calls["count"] += 1
        if calls["count"] == 2:
            return _json_response(
                {
                    "status": "ahead",
                    "ahead_by": 1,
                    "behind_by": 0,
                    "total_commits": 1,
                }
            )
        return _json_response(
            {
                "status": "identical",
                "ahead_by": 0,
                "behind_by": 0,
                "total_commits": 0,
            }
        )

    monkeypatch.setattr(version_status.urllib.request, "urlopen", urlopen)
    client = loaded.module.app.test_client()
    login_client(client)

    first = client.get("/api/version-status")
    second = client.get("/api/version-status")
    now["value"] = 161.0
    refreshed = client.get("/api/version-status")

    assert first.status_code == 200
    assert second.status_code == 200
    assert refreshed.status_code == 200
    assert first.json["admin"]["state"] == "ok"
    assert first.json["proxy"]["state"] == "ok"
    assert second.json["admin"]["state"] == "ok"
    assert second.json["proxy"]["state"] == "ok"
    assert refreshed.json["admin"]["state"] == "outdated"
    assert refreshed.json["proxy"]["state"] == "outdated"
    assert calls["count"] == 2


def test_admin_version_status_retries_failure_without_shortening_success_cache(
    monkeypatch,
    tmp_path,
) -> None:
    loaded = load_admin_app(monkeypatch, tmp_path)
    loaded.module._ADMIN_VERSION_STATUS_CACHE = None
    monkeypatch.setenv("VERSION_STATUS_CACHE_TTL_SECONDS", "3600")
    now = {"value": 100.0}
    monkeypatch.setattr(loaded.module.time, "monotonic", lambda: now["value"])
    results = iter(
        [
            {
                "component": "admin-ui",
                "state": "unknown",
                "detail": "GitHub version check failed: temporary outage",
            },
            {
                "component": "admin-ui",
                "state": "warn",
                "detail": (
                    "GitHub version check failed; showing stale cached result. "
                    "Last successful result: Running commit matches main."
                ),
            },
            {
                "component": "admin-ui",
                "state": "warn",
                "detail": "Running commit is ahead of main (1 commit(s) ahead).",
            },
            {
                "component": "admin-ui",
                "state": "outdated",
                "detail": "Running commit is 1 commit(s) behind main.",
            },
        ]
    )
    calls = {"count": 0}

    def build_status(_metadata: dict[str, Any]) -> dict[str, Any]:
        calls["count"] += 1
        return next(results)

    monkeypatch.setattr(loaded.module, "build_component_version_status", build_status)

    failed = loaded.module._cached_admin_version_status()
    failed["state"] = "mutated-by-caller"
    now["value"] = 159.0
    cached_failure = loaded.module._cached_admin_version_status()
    now["value"] = 161.0
    stale_failure = loaded.module._cached_admin_version_status()
    now["value"] = 220.0
    cached_stale_failure = loaded.module._cached_admin_version_status()
    now["value"] = 222.0
    successful_warning = loaded.module._cached_admin_version_status()
    now["value"] = 3821.0
    cached_successful_warning = loaded.module._cached_admin_version_status()
    now["value"] = 3823.0
    refreshed_success = loaded.module._cached_admin_version_status()

    assert cached_failure["state"] == "unknown"
    assert stale_failure["state"] == "warn"
    assert cached_stale_failure["state"] == "warn"
    assert successful_warning["state"] == "warn"
    assert cached_successful_warning["detail"].startswith("Running commit is ahead")
    assert refreshed_success["state"] == "outdated"
    assert calls["count"] == 4


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
