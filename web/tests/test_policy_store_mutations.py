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
        assert store.list_profiles()[0].direct_domains == [
            "example.com",
            "media.example",
        ]

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


def test_sslfilter_store_validates_dedupes_and_scopes_granular_policy(tmp_path) -> None:
    configure_test_mysql_env(tmp_path / "sslfilter-policy-mutations")

    from services.proxy_context import reset_proxy_id, set_proxy_id  # type: ignore
    from services.sslfilter_store import SslFilterStore  # type: ignore

    store = SslFilterStore()
    store.init_db()

    token = set_proxy_id("edge-a")
    try:
        assert store.add_domain("nobump", "*.Example.COM") == (
            True,
            "",
            "*.example.com",
        )
        assert store.add_domain("nobump", "*.example.com") == (
            True,
            "",
            "*.example.com",
        )
        assert store.add_domain("nocache", "cache.example") == (
            True,
            "",
            "cache.example",
        )
        ok, detail, canonical = store.add_domain("nobump", "bad domain/example")
        assert ok is False
        assert canonical == ""
        assert "invalid" in detail.lower()

        assert store.add_src_net("nobump", "192.168.44.99/24") == (
            True,
            "",
            "192.168.44.0/24",
        )
        assert store.add_src_net("nocache", "192.168.55.99/24") == (
            True,
            "",
            "192.168.55.0/24",
        )
        ok, detail, canonical = store.add_src_net("nobump", "not-a-cidr")
        assert ok is False
        assert canonical == ""
        assert "invalid cidr" in detail.lower()
        ok, detail, canonical = store.add_src_net("unknown", "10.0.0.0/8")
        assert ok is False
        assert canonical == ""
        assert "invalid" in detail.lower()

        store.set_exclude_private_nets(False)
        added, attempted, err = store.install_compatibility_preset("discord")
        assert err == ""
        assert attempted > 0
        assert added > 0
        presets = store.list_compatibility_presets()
        discord_preset = next(p for p in presets if p["id"] == "discord")
        assert discord_preset["complete"] is True

        current = store.list_all()
        assert "*.example.com" in current.no_bump_domains
        assert "*.discord.com" in current.no_bump_domains
        assert current.no_cache_domains == ["cache.example"]
        assert current.no_bump_src_nets == ["192.168.44.0/24"]
        assert current.no_cache_src_nets == ["192.168.55.0/24"]
        assert current.exclude_private_nets is False
        assert current.inspection_enabled is True

        store.set_inspection_enabled(False)
        assert store.list_all().inspection_enabled is False

        store.remove_domain("nobump", "*.example.com")
        store.remove_src_net("nobump", "192.168.44.0/24")
        assert store.list_all().no_bump_src_nets == []
    finally:
        reset_proxy_id(token)

    token = set_proxy_id("edge-b")
    try:
        assert store.add_domain("nobump", "edge-b.example") == (
            True,
            "",
            "edge-b.example",
        )
        assert store.list_all().no_bump_domains == ["edge-b.example"]
    finally:
        reset_proxy_id(token)

    token = set_proxy_id("edge-a")
    try:
        assert "edge-b.example" not in store.list_all().no_bump_domains
    finally:
        reset_proxy_id(token)


def test_sslfilter_store_canonicalizes_dedupes_removes_and_materializes(
    tmp_path,
) -> None:
    configure_test_mysql_env(tmp_path / "sslfilter-mutations")

    from services.proxy_context import reset_proxy_id, set_proxy_id  # type: ignore
    from services.sslfilter_store import SslFilterStore  # type: ignore

    include_path = tmp_path / "10-sslfilter.conf"
    list_path = tmp_path / "nobump.txt"
    store = SslFilterStore(
        squid_include_path=str(include_path), nobump_list_path=str(list_path)
    )
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
        assert "ssl_bump splice sslfilter_nobump" in include_path.read_text(
            encoding="utf-8"
        )

        store.set_inspection_enabled(False)
        store.apply_squid_include()
        disabled_include = include_path.read_text(encoding="utf-8")
        assert "ssl_bump splice all" in disabled_include
        assert "ssl_bump splice sslfilter_nobump" not in disabled_include

        store.set_inspection_enabled(True)
        store.remove_nobump("10.1.2.3/32")
        store.remove_nobump("10.1.2.3/32")
        assert store.list_nobump() == []
        store.apply_squid_include()
        assert list_path.read_text(encoding="utf-8") == ""
        assert "none configured" in include_path.read_text(encoding="utf-8")
    finally:
        reset_proxy_id(token)
