from __future__ import annotations

from .mysql_test_utils import configure_test_mysql_env


def test_pac_profiles_validate_scope_dedupe_match_and_delete(tmp_path) -> None:
    configure_test_mysql_env(tmp_path / "pac-profile-mutations")

    from services.pac_profiles_store import PacProfilesStore  # type: ignore
    from services.proxy_context import reset_proxy_id, set_proxy_id  # type: ignore

    store = PacProfilesStore()
    store.init_db()

    token = set_proxy_id("edge-a")
    try:
        ok, detail, profile_id = store.upsert_profile(
            profile_id=None,
            name="Kids devices",
            client_cidr="10.20.30.44/24",
            direct_domains_text="Example.COM\n.example.com\nmedia.example\n",
            direct_dst_nets_text="10.77.0.1/24\n10.77.0.128/24\n",
        )
        assert ok is True, detail
        assert profile_id is not None

        profiles = store.list_profiles()
        assert len(profiles) == 1
        assert profiles[0].client_cidr == "10.20.30.0/24"
        assert profiles[0].direct_domains == ["example.com", "media.example"]
        assert profiles[0].direct_dst_nets == ["10.77.0.0/24"]
        assert store.match_profile_for_client_ip("10.20.30.99").id == profile_id
        assert store.match_profile_for_client_ip("not-an-ip") is None

        ok, detail, missing_id = store.upsert_profile(
            profile_id=999999,
            name="Missing",
            client_cidr="",
            direct_domains_text="orphan.example",
            direct_dst_nets_text="",
        )
        assert ok is False
        assert missing_id is None
        assert "not found" in detail.lower()
        assert store.list_profiles()[0].direct_domains == ["example.com", "media.example"]

        ok, detail, _ = store.upsert_profile(
            profile_id=None,
            name="Bad CIDR",
            client_cidr="2001:db8::/32",
            direct_domains_text="",
            direct_dst_nets_text="",
        )
        assert ok is False
        assert "ipv4" in detail.lower()

        store.delete_profile(profile_id)
        assert store.list_profiles() == []
    finally:
        reset_proxy_id(token)

    token = set_proxy_id("edge-b")
    try:
        ok, detail, profile_id_b = store.upsert_profile(
            profile_id=None,
            name="Other proxy",
            client_cidr="",
            direct_domains_text="other.example",
            direct_dst_nets_text="",
        )
        assert ok is True, detail
        assert profile_id_b is not None
        assert [p.name for p in store.list_profiles()] == ["Other proxy"]
    finally:
        reset_proxy_id(token)

    token = set_proxy_id("edge-a")
    try:
        assert store.list_profiles() == []
    finally:
        reset_proxy_id(token)


def test_exclusions_store_validates_dedupes_and_scopes_rules(tmp_path) -> None:
    configure_test_mysql_env(tmp_path / "exclusions-mutations")

    from services.exclusions_store import ExclusionsStore  # type: ignore
    from services.proxy_context import reset_proxy_id, set_proxy_id  # type: ignore

    store = ExclusionsStore()
    store.init_db()

    token = set_proxy_id("edge-a")
    try:
        assert store.add_domain("*.Example.COM") == (True, "")
        assert store.add_domain("*.example.com") == (True, "")
        ok, detail = store.add_domain("bad domain/example")
        assert ok is False
        assert "invalid" in detail.lower()

        assert store.add_net("src_nets", "192.168.44.99/24") == (True, "")
        ok, detail = store.add_net("src_nets", "not-a-cidr")
        assert ok is False
        assert "invalid cidr" in detail.lower()
        ok, detail = store.add_net("unknown", "10.0.0.0/8")
        assert ok is False
        assert "invalid target" in detail.lower()

        store.set_exclude_private_nets(False)
        current = store.list_all()
        assert current.domains == ["*.example.com"]
        assert current.src_nets == ["192.168.44.0/24"]
        assert current.exclude_private_nets is False

        store.remove_domain("*.example.com")
        store.remove_net("src_nets", "192.168.44.0/24")
        assert store.list_all().domains == []
        assert store.list_all().src_nets == []
    finally:
        reset_proxy_id(token)

    token = set_proxy_id("edge-b")
    try:
        assert store.add_domain("edge-b.example") == (True, "")
        assert store.list_all().domains == ["edge-b.example"]
    finally:
        reset_proxy_id(token)

    token = set_proxy_id("edge-a")
    try:
        assert store.list_all().domains == []
    finally:
        reset_proxy_id(token)


def test_sslfilter_store_canonicalizes_dedupes_removes_and_materializes(tmp_path) -> None:
    configure_test_mysql_env(tmp_path / "sslfilter-mutations")

    from services.proxy_context import reset_proxy_id, set_proxy_id  # type: ignore
    from services.sslfilter_store import SslFilterStore  # type: ignore

    include_path = tmp_path / "10-sslfilter.conf"
    list_path = tmp_path / "nobump.txt"
    store = SslFilterStore(squid_include_path=str(include_path), nobump_list_path=str(list_path))
    store.init_db()

    token = set_proxy_id("edge-a")
    try:
        ok, detail, canonical = store.add_nobump("10.1.2.3")
        assert ok is True, detail
        assert canonical == "10.1.2.3/32"
        assert store.add_nobump("10.1.2.3/32")[0] is True
        ok, detail, canonical = store.add_nobump("not-a-cidr")
        assert ok is False
        assert canonical == ""
        assert "invalid" in detail.lower()

        rows = store.list_nobump()
        assert [cidr for cidr, _ts in rows] == ["10.1.2.3/32"]

        store.apply_squid_include()
        assert "10.1.2.3/32" in list_path.read_text(encoding="utf-8")
        assert "ssl_bump splice sslfilter_nobump" in include_path.read_text(encoding="utf-8")

        store.remove_nobump("10.1.2.3/32")
        store.remove_nobump("10.1.2.3/32")
        assert store.list_nobump() == []
        store.apply_squid_include()
        assert list_path.read_text(encoding="utf-8") == ""
        assert "none configured" in include_path.read_text(encoding="utf-8")
    finally:
        reset_proxy_id(token)
