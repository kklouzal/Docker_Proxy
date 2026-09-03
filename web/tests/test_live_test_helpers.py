from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from . import live_test_helpers
from .live_test_helpers import (
    HttpResponse,
    assert_adblock_revision_enforcement_ready,
    wait_for_admin_response,
)


@dataclass
class _FakeAdminClient:
    responses: list[HttpResponse]
    requests: list[str]

    def admin_request(self, path_or_url: str) -> HttpResponse:
        self.requests.append(path_or_url)
        if len(self.requests) <= len(self.responses):
            return self.responses[len(self.requests) - 1]
        return self.responses[-1]


def _response(body: str) -> HttpResponse:
    return HttpResponse(
        url="http://admin-ui:5000/certs",
        status=200,
        body=body.encode(),
        headers={},
    )


def test_wait_for_admin_response_polls_until_semantic_acceptance(monkeypatch) -> None:
    sleeps = 0

    def record_sleep() -> None:
        nonlocal sleeps
        sleeps += 1

    client = _FakeAdminClient(
        responses=[
            _response('<div data-proxy-id="live" data-certificate-state="applying">'),
            _response(
                '<div data-proxy-id="live" data-certificate-state="applied_unverified">'
            ),
        ],
        requests=[],
    )
    monkeypatch.setattr(live_test_helpers, "_live_poll_sleep", record_sleep)

    response = wait_for_admin_response(
        client,  # type: ignore[arg-type]
        "/certs",
        accept=lambda candidate: "applied_unverified" in candidate.text,
        description="certificate page state to converge",
        timeout_seconds=1.0,
    )

    assert "applied_unverified" in response.text
    assert client.requests == [
        "http://admin-ui:5000/certs",
        "http://admin-ui:5000/certs",
    ]
    assert sleeps == 1


def _adblock_revision_evidence(*, detail: str, changed: bool) -> tuple:
    artifact_sha256 = "a" * 64
    revision = SimpleNamespace(revision_id=42, artifact_sha256=artifact_sha256)
    application = SimpleNamespace(
        application_id=73,
        revision_id=42,
        ok=True,
        artifact_sha256=artifact_sha256,
    )
    payload = {
        "ok": True,
        "adblock_changed": changed,
        "adblock_revision_id": 42,
        "adblock_application_id": 73,
        "adblock_runtime_enabled": "1",
        "artifact_sha256": artifact_sha256,
        "current_adblock_artifact_sha256": artifact_sha256,
        "detail": detail,
    }
    return payload, revision, revision, application


@pytest.mark.parametrize(
    ("detail", "changed"),
    [
        ("Squid reconfigured for policy update.", True),
        ("Proxy is already using the active adblock artifact.", False),
    ],
)
def test_adblock_revision_evidence_accepts_applied_or_background_preapplied(
    detail: str,
    changed: bool,
) -> None:
    evidence = _adblock_revision_evidence(detail=detail, changed=changed)

    assert_adblock_revision_enforcement_ready(
        sync_payload=evidence[0],
        revision=evidence[1],
        active_revision=evidence[2],
        application=evidence[3],
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("detail", "Proxy sync completed successfully."),
        ("current_adblock_artifact_sha256", "b" * 64),
        ("adblock_runtime_enabled", "0"),
        ("adblock_application_id", 74),
    ],
)
def test_adblock_revision_evidence_rejects_generic_or_stale_noop(
    field: str,
    value: object,
) -> None:
    payload, revision, active_revision, application = _adblock_revision_evidence(
        detail="Proxy is already using the active adblock artifact.",
        changed=False,
    )
    payload[field] = value

    with pytest.raises(AssertionError):
        assert_adblock_revision_enforcement_ready(
            sync_payload=payload,
            revision=revision,
            active_revision=active_revision,
            application=application,
        )
