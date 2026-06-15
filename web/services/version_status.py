from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

UNKNOWN_VALUE = "unknown"
DEFAULT_GITHUB_REPOSITORY = "kklouzal/Docker_Proxy"


def _clean(value: object | None) -> str:
    return str(value or "").strip()


def _short_commit(value: object | None) -> str:
    raw = _clean(value)
    if not raw:
        return UNKNOWN_VALUE
    return raw[:12]


def _env_float(name: str, default: float, *, minimum: float, maximum: float) -> float:
    try:
        value = float(_clean(os.environ.get(name)) or default)
    except Exception:
        value = float(default)
    return max(float(minimum), min(float(maximum), value))


def _env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    try:
        value = int(_clean(os.environ.get(name)) or default)
    except Exception:
        value = int(default)
    return max(int(minimum), min(int(maximum), value))


def _int_or_zero(value: object | None) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def current_component_metadata(component: str) -> dict[str, str]:
    normalized_component = _clean(component).lower() or "unknown"
    version = (
        _clean(os.environ.get("APP_VERSION"))
        or _clean(os.environ.get("DOCKER_PROXY_VERSION"))
        or _clean(os.environ.get("IMAGE_VERSION"))
        or _clean(os.environ.get("GIT_REF_NAME"))
        or _short_commit(os.environ.get("GIT_COMMIT"))
    )
    revision = (
        _clean(os.environ.get("GIT_COMMIT"))
        or _clean(os.environ.get("GITHUB_SHA"))
        or _clean(os.environ.get("SOURCE_COMMIT"))
    )
    source_ref = (
        _clean(os.environ.get("GIT_REF_NAME"))
        or _clean(os.environ.get("GITHUB_REF_NAME"))
        or _clean(os.environ.get("SOURCE_REF"))
    )
    built_at = _clean(os.environ.get("BUILD_DATE")) or _clean(
        os.environ.get("BUILD_CREATED")
    )
    image = _clean(os.environ.get("IMAGE_NAME"))
    return {
        "component": normalized_component,
        "version": version or UNKNOWN_VALUE,
        "revision": revision,
        "revision_short": _short_commit(revision),
        "source_ref": source_ref,
        "built_at": built_at,
        "image": image,
    }


@dataclass(frozen=True)
class CompareResult:
    state: str
    commits_behind: int | None
    latest_revision: str
    detail: str


class VersionStatusClient:
    def __init__(
        self,
        *,
        repository: str | None = None,
        branch: str | None = None,
        token: str | None = None,
        timeout_seconds: float | None = None,
        urlopen: Any | None = None,
        monotonic: Any | None = None,
    ) -> None:
        self.repository = (
            repository
            or _clean(os.environ.get("VERSION_STATUS_GITHUB_REPOSITORY"))
            or DEFAULT_GITHUB_REPOSITORY
        ).strip("/")
        self.branch = (
            branch or _clean(os.environ.get("VERSION_STATUS_GITHUB_BRANCH")) or "main"
        )
        self.token = (
            token if token is not None else _clean(os.environ.get("GITHUB_TOKEN"))
        )
        self.timeout_seconds = float(
            timeout_seconds
            if timeout_seconds is not None
            else _env_float(
                "VERSION_STATUS_GITHUB_TIMEOUT_SECONDS",
                2.0,
                minimum=0.2,
                maximum=10.0,
            )
        )
        self.urlopen = urlopen or urllib.request.urlopen  # noqa: S310
        self.monotonic = monotonic or time.monotonic
        self._cache: dict[str, tuple[float, CompareResult]] = {}

    def _api_get(self, path: str) -> dict[str, Any]:
        url = f"https://api.github.com/repos/{self.repository}/{path.lstrip('/')}"
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "docker-proxy-version-status",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(url, headers=headers)
        with self.urlopen(request, timeout=self.timeout_seconds) as response:
            raw = response.read().decode("utf-8", errors="replace")
        data = json.loads(raw) if raw else {}
        if not isinstance(data, dict):
            msg = "GitHub API returned a non-object response."
            raise RuntimeError(msg)
        return data

    def compare_revision(
        self,
        revision: object | None,
        *,
        ttl_seconds: float | None = None,
    ) -> CompareResult:
        current = _clean(revision)
        if not current or current == UNKNOWN_VALUE:
            return CompareResult("unknown", None, "", "No running commit is stamped.")

        ttl = (
            float(ttl_seconds)
            if ttl_seconds is not None
            else float(
                _env_int(
                    "VERSION_STATUS_CACHE_TTL_SECONDS",
                    3600,
                    minimum=60,
                    maximum=86400,
                )
            )
        )
        key = f"{self.repository}:{self.branch}:{current}"
        now = float(self.monotonic())
        cached = self._cache.get(key)
        if cached is not None and now - cached[0] <= max(0.0, ttl):
            return cached[1]

        try:
            compare = self._api_get(
                "compare/"
                + urllib.parse.quote(current, safe="")
                + "..."
                + urllib.parse.quote(self.branch, safe="")
            )
            status = _clean(compare.get("status"))
            behind_by = compare.get("behind_by")
            ahead_by = compare.get("ahead_by")
            total_commits = compare.get("total_commits")
            commits = compare.get("commits")
            latest_commit = commits[-1] if isinstance(commits, list) and commits else {}
            latest_revision = _clean(
                latest_commit.get("sha") if isinstance(latest_commit, dict) else ""
            )
            main_commits_ahead = _int_or_zero(ahead_by or total_commits)
            running_commits_ahead = _int_or_zero(behind_by)
            if status == "identical":
                result = CompareResult("ok", 0, current, "Running commit matches main.")
            elif status == "ahead":
                result = CompareResult(
                    "outdated",
                    main_commits_ahead,
                    latest_revision,
                    f"Running commit is {main_commits_ahead} commit(s) behind main.",
                )
            elif status == "diverged":
                result = CompareResult(
                    "warn",
                    main_commits_ahead,
                    latest_revision,
                    f"Running commit has diverged from main ({main_commits_ahead} behind, {running_commits_ahead} ahead).",
                )
            elif status == "behind":
                result = CompareResult(
                    "warn",
                    0,
                    latest_revision,
                    f"Running commit is ahead of main ({running_commits_ahead} commit(s) ahead).",
                )
            else:
                result = CompareResult(
                    "unknown",
                    None,
                    latest_revision,
                    "GitHub compare status was unavailable.",
                )
        except (
            TimeoutError,
            urllib.error.URLError,
            urllib.error.HTTPError,
            OSError,
            RuntimeError,
            ValueError,
            json.JSONDecodeError,
        ) as exc:
            if cached is not None:
                return cached[1]
            result = CompareResult(
                "unknown",
                None,
                "",
                f"GitHub version check failed: {exc}",
            )

        self._cache[key] = (now, result)
        return result


def build_component_version_status(
    metadata: dict[str, Any] | None,
    *,
    client: VersionStatusClient | None = None,
) -> dict[str, Any]:
    meta = dict(metadata or {})
    revision = _clean(meta.get("revision"))
    compare = (client or VersionStatusClient()).compare_revision(revision)
    return {
        "component": _clean(meta.get("component")) or "unknown",
        "version": _clean(meta.get("version")) or UNKNOWN_VALUE,
        "revision": revision,
        "revision_short": _short_commit(revision),
        "source_ref": _clean(meta.get("source_ref")),
        "built_at": _clean(meta.get("built_at")),
        "state": compare.state,
        "commits_behind": compare.commits_behind,
        "latest_revision": compare.latest_revision,
        "latest_revision_short": _short_commit(compare.latest_revision),
        "detail": compare.detail,
    }
