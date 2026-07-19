from __future__ import annotations

import concurrent.futures
import sys
from pathlib import Path
from unittest import SkipTest

import pytest

from .mysql_test_utils import configure_test_mysql_env

WEB_ROOT = Path(__file__).resolve().parents[1]
if str(WEB_ROOT) not in sys.path:
    sys.path.insert(0, str(WEB_ROOT))


def _schema_module(tmp_path: Path):
    try:
        configure_test_mysql_env(tmp_path, secret_path=tmp_path / "flask_secret.key")
    except SkipTest as exc:
        pytest.skip(str(exc))
    from services import schema_lifecycle  # type: ignore
    from services.db import connect  # type: ignore

    return schema_lifecycle, connect


def _spec(schema_lifecycle, version: int, name: str, step):
    return schema_lifecycle.SchemaMigrationSpec(
        version=version,
        name=name,
        data_steps=(schema_lifecycle.SchemaDataStep("apply", step),),
    )


@pytest.mark.integration
@pytest.mark.mysql
def test_mysql_schema_lifecycle_serializes_concurrent_migrators(tmp_path: Path) -> None:
    schema_lifecycle, connect = _schema_module(tmp_path)

    def step(conn):
        conn.execute("CREATE TABLE IF NOT EXISTS lifecycle_counter(id INT PRIMARY KEY, n INT NOT NULL)")
        conn.execute("INSERT IGNORE INTO lifecycle_counter(id, n) VALUES(1, 1)")

    spec = _spec(schema_lifecycle, 801, "concurrent", step)

    def migrate_once() -> str:
        return schema_lifecycle.apply_schema_migration(spec, require_privileges=False)[0].status

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        statuses = list(executor.map(lambda _i: migrate_once(), range(12)))

    assert statuses.count("applied") == 1
    assert statuses.count("noop") == 11
    with connect() as conn:
        row = conn.execute("SELECT COUNT(*) AS n FROM lifecycle_counter").fetchone()
        assert int(row["n"] or 0) == 1


@pytest.mark.integration
@pytest.mark.mysql
def test_mysql_schema_lifecycle_failed_migration_retries_idempotently(tmp_path: Path) -> None:
    schema_lifecycle, connect = _schema_module(tmp_path)
    fail = {"value": True}

    def step(conn):
        conn.execute("CREATE TABLE IF NOT EXISTS lifecycle_retry(id INT PRIMARY KEY)")
        if fail["value"]:
            fail["value"] = False
            msg = "simulated interruption"
            raise RuntimeError(msg)

    spec = _spec(schema_lifecycle, 802, "retry", step)
    with pytest.raises(RuntimeError, match="simulated interruption"):
        schema_lifecycle.apply_schema_migration(spec, require_privileges=False)
    with connect() as conn:
        row = conn.execute("SELECT status, error FROM schema_migrations WHERE version=802").fetchone()
        assert row["status"] == "failed"
        assert "simulated interruption" in row["error"]

    result = schema_lifecycle.apply_schema_migration(spec, require_privileges=False)
    assert result[0].status == "applied"
    with connect() as conn:
        assert conn.execute("SELECT 1 FROM lifecycle_retry LIMIT 1").fetchone() is None


@pytest.mark.integration
@pytest.mark.mysql
def test_mysql_schema_lifecycle_legacy_revision_repair_before_unique(tmp_path: Path) -> None:
    schema_lifecycle, connect = _schema_module(tmp_path)
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
                KEY idx_proxy_config_revisions_proxy_active (proxy_id, is_active, created_ts)
            )
            """,
        )
        conn.execute(
            """
            INSERT INTO proxy_config_revisions(proxy_id, config_sha256, config_text, created_ts, is_active)
            VALUES('edge-a', REPEAT('a', 64), 'old', 1, 1),
                  ('edge-a', REPEAT('b', 64), 'new', 2, 1)
            """,
        )

    schema_lifecycle.migrate_schema(require_privileges=False)
    with connect() as conn:
        active_count = conn.execute(
            "SELECT SUM(is_active) AS n FROM proxy_config_revisions WHERE proxy_id='edge-a'",
        ).fetchone()
        assert int(active_count["n"] or 0) == 1
        assert schema_lifecycle.column_exists(conn, "proxy_config_revisions", "active_proxy_id")
        assert schema_lifecycle.index_exists(conn, "proxy_config_revisions", "uniq_proxy_config_revisions_active_proxy")


@pytest.mark.integration
@pytest.mark.mysql
def test_mysql_schema_lifecycle_checksum_drift_reports_expected_and_actual(tmp_path: Path) -> None:
    schema_lifecycle, _connect = _schema_module(tmp_path)
    spec = _spec(schema_lifecycle, 803, "original", lambda _conn: None)
    schema_lifecycle.apply_schema_migration(spec, require_privileges=False)
    drifted = _spec(schema_lifecycle, 803, "changed", lambda _conn: None)

    with pytest.raises(RuntimeError, match="checksum drift"):
        schema_lifecycle.apply_schema_migration(drifted, require_privileges=False)


@pytest.mark.integration
@pytest.mark.mysql
def test_mysql_schema_lifecycle_lock_timeout_is_clear(tmp_path: Path, monkeypatch) -> None:
    schema_lifecycle, connect = _schema_module(tmp_path)
    monkeypatch.setenv("MYSQL_SCHEMA_LOCK_TIMEOUT_SECONDS", "1")
    with connect() as holder:
        row = holder.execute("SELECT GET_LOCK(%s, %s) AS acquired", ("docker_proxy:schema_lifecycle:migrate", 1)).fetchone()
        assert int(row["acquired"] or 0) == 1
        spec = _spec(schema_lifecycle, 804, "locked", lambda _conn: None)
        with pytest.raises(TimeoutError, match="schema_lifecycle"):
            schema_lifecycle.apply_schema_migration(spec, require_privileges=False)
        holder.execute("DO RELEASE_LOCK(%s)", ("docker_proxy:schema_lifecycle:migrate",))
