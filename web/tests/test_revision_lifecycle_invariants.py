from __future__ import annotations

import concurrent.futures
import importlib
import sys
from pathlib import Path
from unittest import SkipTest

import pytest

from .mysql_test_utils import configure_test_mysql_env


def _add_web_to_path() -> None:
    web_dir = Path(__file__).resolve().parents[1]
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))


_add_web_to_path()
from services import revision_lifecycle  # type: ignore  # noqa: E402
from services.config_revisions import ConfigRevisionStore  # type: ignore  # noqa: E402


class _SqlResult:
    def __init__(self, rows=(), *, rowcount: int = 0) -> None:
        self._rows = list(rows)
        self.rowcount = rowcount

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)


def test_duplicate_active_repair_uses_deterministic_partition_update() -> None:
    calls: list[str] = []

    class Conn:
        def execute(self, sql, params=()):
            calls.append(" ".join(str(sql).split()))
            return _SqlResult(rowcount=2)

    changed = revision_lifecycle.repair_duplicate_active_rows(
        Conn(),
        table_name="proxy_config_revisions",
        scope_column="proxy_id",
    )

    assert changed == 2
    sql = calls[-1]
    assert "ROW_NUMBER() OVER (PARTITION BY proxy_id ORDER BY created_ts DESC, id DESC)" in sql
    assert "SET target.is_active=0" in sql
    assert "ranked.active_rank > 1" in sql


class _ConfigRestoreConn:
    def __init__(self, *, current_id: int | None, previous_exists: bool = True) -> None:
        self.current_id = current_id
        self.previous_exists = previous_exists
        self.updates: list[tuple[str, tuple[object, ...]]] = []

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql, params=()):
        text = " ".join(str(sql).split())
        params = tuple(params or ())
        if "GET_LOCK" in text:
            return _SqlResult([{"acquired": 1}])
        if "RELEASE_LOCK" in text:
            return _SqlResult()
        if text.startswith("SELECT id FROM proxy_config_revisions WHERE proxy_id=%s AND is_active=1"):
            return _SqlResult([] if self.current_id is None else [{"id": self.current_id}])
        if text.startswith("SELECT id FROM proxy_config_revisions WHERE proxy_id=%s AND id=%s"):
            return _SqlResult([{"id": params[1]}] if self.previous_exists else [])
        if text.startswith("UPDATE proxy_config_revisions SET is_active"):
            self.updates.append((text, params))
            return _SqlResult(rowcount=1)
        msg = f"Unexpected SQL: {text}"
        raise AssertionError(msg)


def test_config_restore_previous_is_compare_and_swap(monkeypatch) -> None:
    store = ConfigRevisionStore()
    conn = _ConfigRestoreConn(current_id=7)
    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "_connect", lambda: conn)

    assert store.restore_previous_if_current("edge-a", 7, 3) is True
    assert any("id<>%s" in sql and params == ("edge-a", 3) for sql, params in conn.updates)
    assert any("id=%s" in sql and params == ("edge-a", 3) for sql, params in conn.updates)


def test_config_restore_does_not_stomp_newer_active(monkeypatch) -> None:
    store = ConfigRevisionStore()
    conn = _ConfigRestoreConn(current_id=9)
    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "_connect", lambda: conn)

    assert store.restore_previous_if_current("edge-a", 7, 3) is False
    assert conn.updates == []


def _import_fresh_config_store(tmp_path: Path):
    configure_test_mysql_env(tmp_path, secret_path=tmp_path / "flask_secret.key")
    _add_web_to_path()
    import services.config_revisions as config_module  # type: ignore

    return importlib.reload(config_module)


@pytest.mark.integration
@pytest.mark.mysql
def test_mysql_config_revision_legacy_repair_and_unique_active(tmp_path: Path) -> None:
    try:
        config_module = _import_fresh_config_store(tmp_path)
    except SkipTest as exc:
        pytest.skip(str(exc))

    from services.db import connect  # type: ignore

    with connect() as conn:
        conn.execute(
            """
            CREATE TABLE proxy_config_revisions (
                id BIGINT PRIMARY KEY AUTO_INCREMENT,
                proxy_id VARCHAR(64) NOT NULL,
                config_sha256 CHAR(64) NOT NULL,
                config_text LONGTEXT NOT NULL,
                source_kind VARCHAR(64) NOT NULL DEFAULT 'manual',
                created_by VARCHAR(255) NOT NULL DEFAULT '',
                created_ts BIGINT NOT NULL,
                is_active TINYINT(1) NOT NULL DEFAULT 1,
                KEY idx_proxy_config_revisions_proxy_active (proxy_id, is_active, created_ts),
                KEY idx_proxy_config_revisions_proxy_sha (proxy_id, config_sha256)
            )
            """,
        )
        conn.execute(
            """
            INSERT INTO proxy_config_revisions(proxy_id, config_sha256, config_text, source_kind, created_by, created_ts, is_active)
            VALUES('edge-a', REPEAT('a',64), 'old', 'manual', 'tester', 10, 1),
                  ('edge-a', REPEAT('b',64), 'new', 'manual', 'tester', 20, 1),
                  ('edge-b', REPEAT('c',64), 'other', 'manual', 'tester', 15, 1)
            """,
        )

    store = config_module.ConfigRevisionStore()
    store.init_db()

    with connect() as conn:
        rows = conn.execute(
            """
            SELECT proxy_id, SUM(is_active) AS active_count, MAX(CASE WHEN is_active=1 THEN config_text ELSE '' END) AS active_text
            FROM proxy_config_revisions
            GROUP BY proxy_id
            ORDER BY proxy_id
            """,
        ).fetchall()
        assert [(row["proxy_id"], int(row["active_count"]), row["active_text"]) for row in rows] == [
            ("edge-a", 1, "new"),
            ("edge-b", 1, "other"),
        ]
        column = conn.execute(
            """
            SELECT 1 FROM information_schema.columns
            WHERE table_schema=DATABASE() AND table_name='proxy_config_revisions' AND column_name='active_proxy_id'
            LIMIT 1
            """,
        ).fetchone()
        index = conn.execute(
            """
            SELECT 1 FROM information_schema.statistics
            WHERE table_schema=DATABASE() AND table_name='proxy_config_revisions' AND index_name='uniq_proxy_config_revisions_active_proxy'
            LIMIT 1
            """,
        ).fetchone()
        assert column is not None
        assert index is not None


@pytest.mark.integration
@pytest.mark.mysql
def test_mysql_config_revision_concurrent_activation_is_single_active_per_proxy(tmp_path: Path) -> None:
    try:
        config_module = _import_fresh_config_store(tmp_path)
    except SkipTest as exc:
        pytest.skip(str(exc))

    from services.db import connect  # type: ignore

    store = config_module.ConfigRevisionStore()
    store.init_db()

    def create_revision(index: int) -> int:
        local_store = config_module.ConfigRevisionStore()
        revision = local_store.create_revision(
            "edge-a",
            f"workers {index}\n",
            created_by="pytest",
            source_kind="concurrency",
            activate=True,
        )
        return revision.revision_id

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        revision_ids = list(executor.map(create_revision, range(12)))

    assert len(set(revision_ids)) >= 1
    with connect() as conn:
        active = conn.execute(
            "SELECT id, config_text FROM proxy_config_revisions WHERE proxy_id='edge-a' AND is_active=1",
        ).fetchall()
        assert len(active) == 1

    # Per-proxy scope must not serialize into a single global active config.
    edge_b = store.create_revision("edge-b", "workers b\n", created_by="pytest")
    assert edge_b.proxy_id == "edge-b"
    with connect() as conn:
        counts = conn.execute(
            """
            SELECT proxy_id, COUNT(*) AS n
            FROM proxy_config_revisions
            WHERE is_active=1
            GROUP BY proxy_id
            """,
        ).fetchall()
        assert {row["proxy_id"]: int(row["n"]) for row in counts} == {"edge-a": 1, "edge-b": 1}


def _import_fresh_module(module_name: str, tmp_path: Path):
    configure_test_mysql_env((module_name, tmp_path), secret_path=tmp_path / "flask_secret.key")
    _add_web_to_path()
    module = importlib.import_module(module_name)
    return importlib.reload(module)


@pytest.mark.integration
@pytest.mark.mysql
def test_mysql_certificate_bundle_legacy_repair_enforces_global_single_active(tmp_path: Path) -> None:
    try:
        cert_module = _import_fresh_module("services.certificate_bundles", tmp_path)
    except SkipTest as exc:
        pytest.skip(str(exc))

    from services.db import connect  # type: ignore

    with connect() as conn:
        conn.execute(
            """
            CREATE TABLE certificate_bundle_revisions (
                id BIGINT PRIMARY KEY AUTO_INCREMENT,
                bundle_sha256 CHAR(64) NOT NULL,
                cert_sha256 CHAR(64) NOT NULL,
                cert_pem LONGTEXT NOT NULL,
                key_pem LONGTEXT NOT NULL,
                chain_pem LONGTEXT NOT NULL,
                source_kind VARCHAR(64) NOT NULL DEFAULT 'manual',
                subject_dn TEXT,
                not_before VARCHAR(255) NOT NULL DEFAULT '',
                not_after VARCHAR(255) NOT NULL DEFAULT '',
                original_filename VARCHAR(255) NOT NULL DEFAULT '',
                original_pfx_blob LONGBLOB NULL,
                created_by VARCHAR(255) NOT NULL DEFAULT '',
                created_ts BIGINT NOT NULL,
                is_active TINYINT(1) NOT NULL DEFAULT 1,
                KEY idx_certificate_bundle_revisions_active (is_active, created_ts),
                KEY idx_certificate_bundle_revisions_sha (bundle_sha256, created_ts)
            )
            """,
        )
        conn.execute(
            """
            INSERT INTO certificate_bundle_revisions(bundle_sha256, cert_sha256, cert_pem, key_pem, chain_pem, created_by, created_ts, is_active)
            VALUES(REPEAT('a',64), REPEAT('1',64), 'cert-a', 'key-a', '', 'pytest', 10, 1),
                  (REPEAT('b',64), REPEAT('2',64), 'cert-b', 'key-b', '', 'pytest', 20, 1)
            """,
        )

    cert_module.CertificateBundleStore().init_db()

    with connect() as conn:
        rows = conn.execute("SELECT id, cert_pem FROM certificate_bundle_revisions WHERE is_active=1").fetchall()
        assert [(int(row["id"]), row["cert_pem"]) for row in rows] == [(2, "cert-b")]
        assert conn.execute(
            """
            SELECT 1 FROM information_schema.statistics
            WHERE table_schema=DATABASE() AND table_name='certificate_bundle_revisions' AND index_name='uniq_certificate_bundle_revisions_active'
            LIMIT 1
            """,
        ).fetchone() is not None


@pytest.mark.integration
@pytest.mark.mysql
def test_mysql_adblock_artifact_legacy_repair_enforces_global_single_active(tmp_path: Path) -> None:
    try:
        artifacts_module = _import_fresh_module("services.adblock_artifacts", tmp_path)
    except SkipTest as exc:
        pytest.skip(str(exc))

    from services.db import connect  # type: ignore

    with connect() as conn:
        conn.execute(
            """
            CREATE TABLE adblock_artifact_revisions (
                id BIGINT PRIMARY KEY AUTO_INCREMENT,
                artifact_sha256 CHAR(64) NOT NULL,
                archive_blob LONGBLOB NOT NULL,
                report_json LONGTEXT NOT NULL,
                settings_version BIGINT NOT NULL DEFAULT 0,
                source_kind VARCHAR(64) NOT NULL DEFAULT 'compile',
                enabled_lists_json LONGTEXT NOT NULL,
                created_by VARCHAR(255) NOT NULL DEFAULT '',
                created_ts BIGINT NOT NULL,
                is_active TINYINT(1) NOT NULL DEFAULT 1,
                KEY idx_adblock_artifact_revisions_active (is_active, created_ts, id),
                KEY idx_adblock_artifact_revisions_sha (artifact_sha256, created_ts, id)
            )
            """,
        )
        conn.execute(
            """
            INSERT INTO adblock_artifact_revisions(artifact_sha256, archive_blob, report_json, settings_version, source_kind, enabled_lists_json, created_by, created_ts, is_active)
            VALUES(REPEAT('a',64), %s, '{}', 1, 'compile', '[]', 'pytest', 10, 1),
                  (REPEAT('b',64), %s, '{}', 2, 'compile', '[]', 'pytest', 20, 1)
            """,
            (b"old", b"new"),
        )

    artifacts_module.AdblockArtifactStore().init_db()

    with connect() as conn:
        rows = conn.execute("SELECT id, settings_version FROM adblock_artifact_revisions WHERE is_active=1").fetchall()
        assert [(int(row["id"]), int(row["settings_version"])) for row in rows] == [(2, 2)]
        assert conn.execute(
            """
            SELECT 1 FROM information_schema.statistics
            WHERE table_schema=DATABASE() AND table_name='adblock_artifact_revisions' AND index_name='uniq_adblock_artifact_revisions_active'
            LIMIT 1
            """,
        ).fetchone() is not None
