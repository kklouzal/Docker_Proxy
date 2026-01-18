def test_auth_store_allows_relative_db_and_secret_paths(tmp_path, monkeypatch):
    # Regression: os.makedirs(os.path.dirname(path)) crashes when path has no directory.
    monkeypatch.chdir(tmp_path)

    # Import from the local web/ folder layout (tests are executed with CWD=web).
    from services.auth_store import AuthStore

    store = AuthStore(db_path="auth.db", secret_path="flask_secret.key")
    store.ensure_default_admin()
    store.get_or_create_secret_key()

    assert (tmp_path / "auth.db").exists()
    assert (tmp_path / "flask_secret.key").exists()


def test_other_stores_allow_relative_db_paths(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    from services.audit_store import AuditStore
    from services.exclusions_store import ExclusionsStore
    from services.pac_profiles_store import PacProfilesStore
    from services.sslfilter_store import SslFilterStore

    AuditStore(db_path="audit.db").init_db()
    ExclusionsStore(db_path="exclusions.db").init_db()
    PacProfilesStore(db_path="pac_profiles.db").init_db()
    SslFilterStore(db_path="sslfilter.db", squid_include_path=str(tmp_path / "ssl.conf"), nobump_list_path=str(tmp_path / "nobump.txt")).init_db()

    assert (tmp_path / "audit.db").exists()
    assert (tmp_path / "exclusions.db").exists()
    assert (tmp_path / "pac_profiles.db").exists()
    assert (tmp_path / "sslfilter.db").exists()
