from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

from services.runtime_helpers import env_float as _env_float
from services.runtime_helpers import env_int as _env_int

UNKNOWN_VALUE = "unknown"
DEFAULT_GITHUB_REPOSITORY = "kklouzal/Docker_Proxy"
_GITHUB_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_GITHUB_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_GITHUB_BRANCH_FORBIDDEN_CHARS = frozenset(" ~^:?*[\\")
_GITHUB_COMMIT_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_MAX_GITHUB_API_RESPONSE_BYTES = 512 * 1024
_MAX_VERSION_STATUS_CACHE_ENTRIES = 128
_CACHE_LOCK_STRIPES = 16


class _RejectGitHubRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        error = "GitHub API redirects are not allowed."
        raise RuntimeError(error)


_GITHUB_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    _RejectGitHubRedirects(),
)


def _open_github_request(request: urllib.request.Request, *, timeout: float):
    """Open directly, without redirects, so bearer credentials stay on GitHub."""
    return _GITHUB_OPENER.open(request, timeout=timeout)


def _clean(value: object | None) -> str:
    return str(value or "").strip()


def _short_commit(value: object | None) -> str:
    raw = _clean(value)
    if not raw:
        return UNKNOWN_VALUE
    return raw[:12]


def _validated_compare_summary(compare: dict[str, Any]) -> tuple[str, int, int]:
    status = compare.get("status")
    if not isinstance(status, str) or status not in {
        "identical",
        "ahead",
        "behind",
        "diverged",
    }:
        msg = "GitHub compare response has an invalid status."
        raise RuntimeError(msg)

    counts: dict[str, int] = {}
    for field in ("ahead_by", "behind_by", "total_commits"):
        value = compare.get(field)
        if type(value) is not int or value < 0:
            msg = "GitHub compare response has invalid commit counts."
            raise RuntimeError(msg)
        counts[field] = value

    ahead_by = counts["ahead_by"]
    behind_by = counts["behind_by"]
    if counts["total_commits"] != ahead_by:
        msg = "GitHub compare response has inconsistent commit counts."
        raise RuntimeError(msg)

    counts_match_status = {
        "identical": ahead_by == 0 and behind_by == 0,
        "ahead": ahead_by > 0 and behind_by == 0,
        "behind": ahead_by == 0 and behind_by > 0,
        "diverged": ahead_by > 0 and behind_by > 0,
    }
    if not counts_match_status[status]:
        msg = "GitHub compare response has inconsistent status and counts."
        raise RuntimeError(msg)
    return status, ahead_by, behind_by


def _normalize_github_repository(value: object | None) -> tuple[str, str]:
    repository = _clean(value).strip("/")
    parts = repository.split("/")
    if len(parts) != 2 or not all(parts):
        return repository, "GitHub repository must be in owner/name form."
    owner, name = parts
    if not _GITHUB_OWNER_RE.fullmatch(owner) or not _GITHUB_REPOSITORY_RE.fullmatch(
        name
    ):
        return repository, "GitHub repository contains unsupported characters."
    if name in {".", ".."}:
        return repository, "GitHub repository name is not valid."
    return repository, ""


def _normalize_github_branch(value: object | None) -> tuple[str, str]:
    branch = _clean(value)
    if not branch:
        return "main", ""
    if len(branch) > 250:
        return branch, "GitHub branch contains too many characters."
    if any(ord(char) < 32 or ord(char) == 127 for char in branch):
        return branch, "GitHub branch contains control characters."
    if any(char in _GITHUB_BRANCH_FORBIDDEN_CHARS for char in branch):
        return branch, "GitHub branch contains unsupported characters."
    if branch in {"@", "HEAD"} or branch.startswith("refs/"):
        return branch, "GitHub branch is an ambiguous ref form."
    if branch.startswith("/") or branch.endswith("/") or "//" in branch:
        return branch, "GitHub branch contains unsafe path separators."
    if branch.endswith(".") or ".." in branch or "@{" in branch:
        return branch, "GitHub branch is not a safe branch name."
    parts = branch.split("/")
    if any(
        part in {"", ".", ".."} or part.startswith(".") or part.endswith(".lock")
        for part in parts
    ):
        return branch, "GitHub branch contains an unsafe path component."
    return branch, ""


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
        repository_value = (
            repository
            or _clean(os.environ.get("VERSION_STATUS_GITHUB_REPOSITORY"))
            or DEFAULT_GITHUB_REPOSITORY
        )
        self.repository, self.repository_error = _normalize_github_repository(
            repository_value
        )
        branch_value = (
            branch
            if branch is not None
            else os.environ.get("VERSION_STATUS_GITHUB_BRANCH")
        )
        self.branch, self.branch_error = _normalize_github_branch(branch_value)
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
        self.urlopen = urlopen or _open_github_request
        self.monotonic = monotonic or time.monotonic
        self._cache: OrderedDict[str, tuple[float, CompareResult]] = OrderedDict()
        self._cache_lock = threading.Lock()
        self._request_locks = tuple(
            threading.Lock() for _ in range(_CACHE_LOCK_STRIPES)
        )

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
            raw = response.read(_MAX_GITHUB_API_RESPONSE_BYTES + 1)
        if len(raw) > _MAX_GITHUB_API_RESPONSE_BYTES:
            msg = (
                f"GitHub API response exceeded {_MAX_GITHUB_API_RESPONSE_BYTES} bytes."
            )
            raise RuntimeError(msg)
        text = raw.decode("utf-8", errors="replace")
        data = json.loads(text) if text else {}
        if not isinstance(data, dict):
            msg = "GitHub API returned a non-object response."
            raise RuntimeError(msg)
        return data

    def _resolve_branch_tip(self) -> str:
        branch_ref = f"refs/heads/{self.branch}"
        payload = self._api_get(
            "git/ref/heads/" + urllib.parse.quote(self.branch, safe="")
        )
        if payload.get("ref") != branch_ref:
            msg = "GitHub branch ref response has an unexpected identity."
            raise RuntimeError(msg)
        target = payload.get("object")
        if not isinstance(target, dict) or target.get("type") != "commit":
            msg = "GitHub branch ref response has an invalid target."
            raise RuntimeError(msg)
        tip = _clean(target.get("sha"))
        if not _GITHUB_COMMIT_SHA_RE.fullmatch(tip):
            msg = "GitHub branch ref response has an invalid commit identity."
            raise RuntimeError(msg)
        return tip.lower()

    def compare_revision(
        self,
        revision: object | None,
        *,
        ttl_seconds: float | None = None,
    ) -> CompareResult:
        current = _clean(revision)
        if not current or current == UNKNOWN_VALUE:
            return CompareResult("unknown", None, "", "No running commit is stamped.")
        if self.repository_error:
            return CompareResult(
                "unknown",
                None,
                "",
                f"GitHub version check disabled: {self.repository_error}",
            )
        if self.branch_error:
            return CompareResult(
                "unknown",
                None,
                "",
                f"GitHub version check disabled: {self.branch_error}",
            )

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
        request_lock = self._request_locks[hash(key) % len(self._request_locks)]
        with request_lock:
            return self._compare_revision_locked(current, key=key, ttl=ttl)

    def _compare_revision_locked(
        self,
        current: str,
        *,
        key: str,
        ttl: float,
    ) -> CompareResult:
        now = float(self.monotonic())
        with self._cache_lock:
            cached = self._cache.get(key)
            if cached is not None:
                self._cache.move_to_end(key)
        if cached is not None and now - cached[0] <= max(0.0, ttl):
            return cached[1]

        try:
            # Resolve the mutable branch to an authoritative commit first.  The
            # compare is then frozen to that identity, while a later one-item page
            # avoids the potentially large changed-files list on page one.
            latest_revision = self._resolve_branch_tip()
            compare = self._api_get(
                "compare/"
                + urllib.parse.quote(current, safe="")
                + "..."
                + urllib.parse.quote(latest_revision, safe="")
                + "?per_page=1&page=2"
            )
            status, main_commits_ahead, running_commits_ahead = (
                _validated_compare_summary(compare)
            )
            if status == "identical":
                result = CompareResult(
                    "ok", 0, latest_revision, f"Running commit matches {self.branch}."
                )
            elif status == "ahead":
                result = CompareResult(
                    "outdated",
                    main_commits_ahead,
                    latest_revision,
                    f"Running commit is {main_commits_ahead} commit(s) behind {self.branch}.",
                )
            elif status == "diverged":
                result = CompareResult(
                    "warn",
                    main_commits_ahead,
                    latest_revision,
                    f"Running commit has diverged from {self.branch} ({main_commits_ahead} behind, {running_commits_ahead} ahead).",
                )
            elif status == "behind":
                result = CompareResult(
                    "warn",
                    0,
                    latest_revision,
                    f"Running commit is ahead of {self.branch} ({running_commits_ahead} commit(s) ahead).",
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
                cached_result = cached[1]
                return CompareResult(
                    "warn",
                    cached_result.commits_behind,
                    cached_result.latest_revision,
                    "GitHub version check failed; showing stale cached result. "
                    f"Last successful result: {cached_result.detail} "
                    f"Refresh error: {exc}",
                )
            result = CompareResult(
                "unknown",
                None,
                "",
                f"GitHub version check failed: {exc}",
            )

        if result.state != "unknown":
            with self._cache_lock:
                self._cache[key] = (now, result)
                self._cache.move_to_end(key)
                while len(self._cache) > _MAX_VERSION_STATUS_CACHE_ENTRIES:
                    self._cache.popitem(last=False)
        return result


_DEFAULT_CLIENT_LOCK = threading.Lock()
_DEFAULT_CLIENT: VersionStatusClient | None = None


def _default_version_status_client() -> VersionStatusClient:
    """Return the shared client for the process's current GitHub configuration."""
    global _DEFAULT_CLIENT
    with _DEFAULT_CLIENT_LOCK:
        configured = VersionStatusClient()
        current = _DEFAULT_CLIENT
        if current is None or any(
            (
                current.repository != configured.repository,
                current.repository_error != configured.repository_error,
                current.branch != configured.branch,
                current.branch_error != configured.branch_error,
                current.token != configured.token,
                current.timeout_seconds != configured.timeout_seconds,
                current.urlopen is not configured.urlopen,
                current.monotonic is not configured.monotonic,
            )
        ):
            _DEFAULT_CLIENT = configured
        return _DEFAULT_CLIENT


def build_component_version_status(
    metadata: dict[str, Any] | None,
    *,
    client: VersionStatusClient | None = None,
) -> dict[str, Any]:
    meta = dict(metadata or {})
    revision = _clean(meta.get("revision"))
    compare = (client or _default_version_status_client()).compare_revision(revision)
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
