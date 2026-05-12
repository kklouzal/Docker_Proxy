import os
import sys

from .mysql_test_utils import configure_test_mysql_env


def _add_web_to_path() -> None:
    web_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if web_dir not in sys.path:
        sys.path.insert(0, web_dir)


def test_webcat_acl_uses_local_snapshot_for_parent_domain_lookups(tmp_path, monkeypatch):
    _add_web_to_path()
    configure_test_mysql_env(tmp_path / "webcat-acl")

    from services.db import connect  # type: ignore
    from tools import webcat_acl  # type: ignore

    with connect() as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS webcat_domains (domain VARCHAR(255) PRIMARY KEY, categories TEXT NOT NULL)")
        conn.execute("CREATE TABLE IF NOT EXISTS webcat_meta (k VARCHAR(64) PRIMARY KEY, v LONGTEXT NOT NULL)")
        conn.execute(
            "INSERT INTO webcat_domains(domain, categories) VALUES(%s, %s) ON DUPLICATE KEY UPDATE categories=VALUES(categories)",
            ("example.com", "adult|phishing"),
        )
        conn.execute(
            "INSERT INTO webcat_meta(k, v) VALUES(%s, %s) ON DUPLICATE KEY UPDATE v=VALUES(v)",
            ("built_ts", "123"),
        )

    snapshot_dir = tmp_path / "snapshot"
    monkeypatch.setenv("WEBFILTER_SNAPSHOT_DIR", str(snapshot_dir))
    db = webcat_acl._Db()

    assert db._build_snapshot_from_db(expected_built_ts=123) is True
    assert (snapshot_dir / "webcat.sqlite").exists()

    db._conn = None
    db._last_open_attempt = webcat_acl._now()

    assert db.lookup_categories("cdn.example.com") == {"adult", "phishing"}


def test_webcat_acl_refreshes_stale_disk_snapshot_before_negative_lookup(tmp_path, monkeypatch):
    _add_web_to_path()
    configure_test_mysql_env(tmp_path / "webcat-acl-stale-snapshot")

    from services.db import connect  # type: ignore
    from tools import webcat_acl  # type: ignore

    snapshot_dir = tmp_path / "snapshot"
    monkeypatch.setenv("WEBFILTER_SNAPSHOT_DIR", str(snapshot_dir))
    db = webcat_acl._Db()

    with connect() as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS webcat_domains (domain VARCHAR(255) PRIMARY KEY, categories TEXT NOT NULL)")
        conn.execute("CREATE TABLE IF NOT EXISTS webcat_meta (k VARCHAR(64) PRIMARY KEY, v LONGTEXT NOT NULL)")
        conn.execute(
            "INSERT INTO webcat_meta(k, v) VALUES(%s, %s) ON DUPLICATE KEY UPDATE v=VALUES(v)",
            ("built_ts", "100"),
        )

    assert db._build_snapshot_from_db(expected_built_ts=100) is True

    with connect() as conn:
        conn.execute(
            "INSERT INTO webcat_domains(domain, categories) VALUES(%s, %s) ON DUPLICATE KEY UPDATE categories=VALUES(categories)",
            ("traffic-fixture", "adult"),
        )
        conn.execute(
            "INSERT INTO webcat_meta(k, v) VALUES(%s, %s) ON DUPLICATE KEY UPDATE v=VALUES(v)",
            ("built_ts", "200"),
        )

    fresh_db = webcat_acl._Db()
    fresh_db.start = lambda: None

    assert fresh_db.lookup_categories("traffic-fixture") == {"adult"}

def test_webcat_acl_normalizes_explicit_proxy_uri_host():
    _add_web_to_path()

    from tools import webcat_acl  # type: ignore

    assert webcat_acl._norm_domain('http://traffic-fixture:8080/live.js') == 'traffic-fixture'
    assert webcat_acl._norm_domain('traffic-fixture:8080') == 'traffic-fixture'


def test_webcat_acl_prefers_uri_host_over_dst_field():
    _add_web_to_path()

    from tools import webcat_acl  # type: ignore

    channel, src_ip, domain, url, category = webcat_acl._parse_line(
        '7 172.18.0.4 93.184.216.34 http://traffic-fixture:8080/live.js malware'
    )

    assert channel == '7'
    assert src_ip == '172.18.0.4'
    assert domain == '93.184.216.34'
    assert webcat_acl._norm_domain(url) == 'traffic-fixture'
    assert category == 'malware'
