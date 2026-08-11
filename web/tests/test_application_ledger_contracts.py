from __future__ import annotations

import importlib

import pytest

AdblockArtifactStore = importlib.import_module(
    "services.adblock_artifacts"
).AdblockArtifactStore
CertificateBundleStore = importlib.import_module(
    "services.certificate_bundles"
).CertificateBundleStore
ConfigRevisionStore = importlib.import_module(
    "services.config_revisions"
).ConfigRevisionStore
application_ledgers = importlib.import_module("services.application_ledgers")
normalize_application_actor = application_ledgers.normalize_application_actor
normalize_application_detail = application_ledgers.normalize_application_detail


class _Result:
    def __init__(self, rows=None, *, lastrowid: int = 0, rowcount: int = 0) -> None:
        self._rows = list(rows or [])
        self.lastrowid = lastrowid
        self.rowcount = rowcount

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)


class _LedgerConn:
    def __init__(self, *, kind: str, revision_sha: str) -> None:
        self.kind = kind
        self.revision_sha = revision_sha
        self.insert_params: tuple[object, ...] | None = None

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql, params=()):
        text = " ".join(str(sql).split())
        params = tuple(params or ())
        if self.kind == "config" and text.startswith(
            "SELECT id, config_sha256 FROM proxy_config_revisions"
        ):
            return _Result([{"id": params[1], "config_sha256": self.revision_sha}])
        if self.kind == "certificate" and text.startswith(
            "SELECT id, bundle_sha256 FROM certificate_bundle_revisions"
        ):
            return _Result([{"id": params[0], "bundle_sha256": self.revision_sha}])
        if self.kind == "adblock" and text.startswith(
            "SELECT id, artifact_sha256 FROM adblock_artifact_revisions"
        ):
            return _Result([{"id": params[0], "artifact_sha256": self.revision_sha}])
        if text.startswith("INSERT INTO proxy_config_applications"):
            self.insert_params = params
            return _Result(lastrowid=44, rowcount=1)
        if text.startswith("INSERT INTO proxy_certificate_applications"):
            self.insert_params = params
            return _Result(lastrowid=45, rowcount=1)
        if text.startswith("INSERT INTO proxy_adblock_artifact_applications"):
            self.insert_params = params
            return _Result(lastrowid=46, rowcount=1)
        if text.startswith("SELECT * FROM proxy_config_applications WHERE id"):
            proxy_id, revision_id, ok, detail, applied_by, applied_ts, config_sha = (
                self.insert_params or ()
            )
            return _Result(
                [
                    {
                        "id": 44,
                        "proxy_id": proxy_id,
                        "revision_id": revision_id,
                        "ok": ok,
                        "detail": detail,
                        "applied_by": applied_by,
                        "applied_ts": applied_ts,
                        "config_sha256": config_sha,
                    },
                ]
            )
        if text.startswith("SELECT * FROM proxy_certificate_applications WHERE id"):
            proxy_id, revision_id, ok, detail, applied_by, applied_ts, bundle_sha = (
                self.insert_params or ()
            )
            return _Result(
                [
                    {
                        "id": 45,
                        "proxy_id": proxy_id,
                        "revision_id": revision_id,
                        "ok": ok,
                        "detail": detail,
                        "applied_by": applied_by,
                        "applied_ts": applied_ts,
                        "bundle_sha256": bundle_sha,
                    },
                ]
            )
        if text.startswith(
            "SELECT * FROM proxy_adblock_artifact_applications WHERE id"
        ):
            proxy_id, revision_id, ok, detail, applied_by, applied_ts, artifact_sha = (
                self.insert_params or ()
            )
            return _Result(
                [
                    {
                        "id": 46,
                        "proxy_id": proxy_id,
                        "revision_id": revision_id,
                        "ok": ok,
                        "detail": detail,
                        "applied_by": applied_by,
                        "applied_ts": applied_ts,
                        "artifact_sha256": artifact_sha,
                    },
                ]
            )
        return _Result()


def test_config_application_records_revision_sha_and_redacts_detail(
    monkeypatch,
) -> None:
    sha = "a" * 64
    conn = _LedgerConn(kind="config", revision_sha=sha)
    store = ConfigRevisionStore()
    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "_connect", lambda: conn)

    application = store.record_apply_result(
        "edge-a",
        7,
        ok=True,
        detail="apply failed token=supersecret\nretry\tqueued",
        applied_by=("deploy\tbot\r\npassword=hunter2\x00\x7f\u0085\u2028\u2029\u200b"),
    )

    assert application.config_sha256 == sha
    assert application.detail == "apply failed token=[redacted]\nretry\tqueued"
    assert application.applied_by == "deploy bot password=[redacted]"


def test_application_actor_falls_back_when_only_invisible_separators_remain() -> None:
    invisible = "\t\r\n\x00\x1f\x7f\u0085\u2028\u2029\u200b"

    assert normalize_application_actor(invisible) == "proxy"
    assert len(normalize_application_actor("operator-" + ("x" * 300))) == 255


def test_application_detail_preserves_useful_line_and_tab_structure() -> None:
    detail = "first line\nsecond line\tqueued"

    assert normalize_application_detail(detail) == detail


def test_application_detail_canonicalizes_crlf_and_lone_cr() -> None:
    detail = "apply started\r\nreload queued\rhealth check\tpending"

    assert normalize_application_detail(detail) == (
        "apply started\nreload queued\nhealth check\tpending"
    )


def test_application_detail_normalizes_newlines_before_bounding() -> None:
    assert normalize_application_detail("step one\r\nstep two", max_len=10) == (
        "step one\ns"
    )


def test_certificate_application_success_evidence_must_match_revision(
    monkeypatch,
) -> None:
    sha = "b" * 64
    conn = _LedgerConn(kind="certificate", revision_sha=sha)
    store = CertificateBundleStore()
    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "_connect", lambda: conn)

    application = store.record_apply_result("edge-a", 8, ok=True, detail="ok")
    assert application.bundle_sha256 == sha

    with pytest.raises(ValueError, match="does not match"):
        store.record_apply_result("edge-a", 8, ok=True, bundle_sha256="c" * 64)


def test_certificate_failure_preserves_different_valid_runtime_evidence(
    monkeypatch,
) -> None:
    revision_sha = "d" * 64
    current_sha = "e" * 64
    conn = _LedgerConn(kind="certificate", revision_sha=revision_sha)
    store = CertificateBundleStore()
    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "_connect", lambda: conn)

    application = store.record_apply_result(
        "edge-a",
        9,
        ok=False,
        detail="failed api_key=secret",
        bundle_sha256=current_sha,
    )

    assert application.bundle_sha256 == current_sha
    assert application.detail == "failed api_key=[redacted]"


def test_adblock_application_success_evidence_must_match_revision(monkeypatch) -> None:
    sha = "f" * 64
    conn = _LedgerConn(kind="adblock", revision_sha=sha)
    store = AdblockArtifactStore(compiled_dir="/tmp/docker-proxy-test-adblock")
    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "_connect", lambda: conn)

    application = store.record_apply_result("edge-a", 10, ok=True, detail="ok")
    assert application.artifact_sha256 == sha

    with pytest.raises(ValueError, match="does not match"):
        store.record_apply_result("edge-a", 10, ok=True, artifact_sha256="0" * 64)
