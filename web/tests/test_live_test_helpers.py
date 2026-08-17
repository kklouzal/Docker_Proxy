from __future__ import annotations

from dataclasses import dataclass

from . import live_test_helpers
from .live_test_helpers import HttpResponse, wait_for_admin_response


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
