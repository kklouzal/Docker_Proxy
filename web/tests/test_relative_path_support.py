from .mysql_test_utils import configure_test_mysql_env


def test_auth_store_allows_relative_secret_paths(tmp_path, monkeypatch):
    # Regression: os.makedirs(os.path.dirname(path)) crashes when path has no directory.
    monkeypatch.chdir(tmp_path)
    configure_test_mysql_env(tmp_path, secret_path="flask_secret.key")

    from services.auth_store import AuthStore

    store = AuthStore(secret_path="flask_secret.key")
    store.ensure_default_admin()
    store.get_or_create_secret_key()

    assert not list(tmp_path.glob("*.db"))
    assert (tmp_path / "flask_secret.key").exists()


def test_store_initialization_does_not_create_local_db_files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    configure_test_mysql_env(tmp_path, secret_path=tmp_path / "flask_secret.key")

    from services.audit_store import AuditStore
    from services.exclusions_store import ExclusionsStore
    from services.pac_profiles_store import PacProfilesStore
    from services.sslfilter_store import SslFilterStore

    AuditStore().init_db()
    ExclusionsStore().init_db()
    PacProfilesStore().init_db()
    SslFilterStore(squid_include_path=str(tmp_path / "ssl.conf"), nobump_list_path=str(tmp_path / "nobump.txt")).init_db()

    assert not list(tmp_path.glob("*.db"))
