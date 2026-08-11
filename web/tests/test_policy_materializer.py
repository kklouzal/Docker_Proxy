from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
WEB_ROOT = REPO_ROOT / "web"


def test_policy_materializer_rejects_conflicting_same_target_files(tmp_path) -> None:

    from services.policy_materializer import (
        build_proxy_policy_state_from_stores,  # type: ignore
    )

    shared_path = tmp_path / "policy.conf"
    sslfilter_store = SimpleNamespace(
        squid_include_path=str(shared_path),
        nobump_list_path=str(shared_path),
        nocache_src_list_path=str(tmp_path / "nocache-src.txt"),
        render_materialized_state=lambda: SimpleNamespace(
            include_text="# ssl include\n",
            nobump_src_list_text="10.0.0.0/8\n",
            nocache_src_list_text="",
        ),
    )
    webfilter_store = SimpleNamespace(
        squid_include_path=str(tmp_path / "webfilter.conf"),
        whitelist_path=str(tmp_path / "whitelist.txt"),
        render_materialized_state=lambda: SimpleNamespace(
            include_text="# web include\n",
            whitelist_text="",
        ),
    )

    from services.proxy_context import (  # type: ignore
        get_proxy_id,
        reset_proxy_id,
        set_proxy_id,
    )

    token = set_proxy_id("outer-proxy")
    try:
        with pytest.raises(ValueError, match="conflicting content"):
            build_proxy_policy_state_from_stores(
                "proxy-a",
                sslfilter_store=sslfilter_store,
                webfilter_store=webfilter_store,
            )
        assert get_proxy_id() == "outer-proxy"
    finally:
        reset_proxy_id(token)


def test_policy_materializer_rejects_duplicate_alias_target(tmp_path) -> None:

    from services.policy_materializer import (  # type: ignore
        build_proxy_policy_state_from_stores,
    )

    shared_path = tmp_path / "policy.conf"
    alias_path = tmp_path / "unused" / ".." / "policy.conf"
    sslfilter_store = SimpleNamespace(
        squid_include_path=str(shared_path),
        nobump_list_path=str(alias_path),
        nocache_src_list_path=str(tmp_path / "nocache-src.txt"),
        render_materialized_state=lambda: SimpleNamespace(
            include_text="same content\n",
            nobump_src_list_text="same content\n",
            nocache_src_list_text="",
        ),
    )
    webfilter_store = SimpleNamespace(
        squid_include_path=str(tmp_path / "webfilter.conf"),
        whitelist_path=str(tmp_path / "whitelist.txt"),
        render_materialized_state=lambda: SimpleNamespace(
            include_text="# web include\n",
            whitelist_text="",
        ),
    )

    with pytest.raises(ValueError, match="duplicate target"):
        build_proxy_policy_state_from_stores(
            "proxy-a",
            sslfilter_store=sslfilter_store,
            webfilter_store=webfilter_store,
        )


def test_policy_sha_uses_canonical_target_identity_and_logical_order(tmp_path) -> None:

    from services.policy_materializer import (  # type: ignore
        MaterializedPolicyFile,
        calculate_policy_sha,
    )

    first_path = tmp_path / "first.conf"
    first_alias = tmp_path / "unused" / ".." / "first.conf"
    second_path = tmp_path / "second.conf"

    canonical_sha = calculate_policy_sha(
        (
            MaterializedPolicyFile(str(first_path), "first\n"),
            MaterializedPolicyFile(str(second_path), "second\n"),
        ),
    )
    equivalent_sha = calculate_policy_sha(
        (
            MaterializedPolicyFile(str(second_path), "second\n"),
            MaterializedPolicyFile(str(first_alias), "first\n"),
        ),
    )

    assert equivalent_sha == canonical_sha
    assert (
        calculate_policy_sha(
            (
                MaterializedPolicyFile(str(first_path), "changed\n"),
                MaterializedPolicyFile(str(second_path), "second\n"),
            ),
        )
        != canonical_sha
    )
    assert (
        calculate_policy_sha(
            (
                MaterializedPolicyFile(str(first_path), "first\n"),
                MaterializedPolicyFile(str(tmp_path / "different.conf"), "second\n"),
            ),
        )
        != canonical_sha
    )


@pytest.mark.parametrize("failing_store", ["webfilter", "sslfilter"])
def test_policy_materializer_restores_context_after_store_render_failure(
    tmp_path,
    failing_store,
) -> None:

    from services.policy_materializer import (  # type: ignore
        build_proxy_policy_state_from_stores,
    )
    from services.proxy_context import (  # type: ignore
        get_proxy_id,
        reset_proxy_id,
        set_proxy_id,
    )

    seen_proxy_ids: list[str] = []

    def render_store(name: str, **state):
        seen_proxy_ids.append(get_proxy_id())
        if name == failing_store:
            failure_message = f"{name} render failed"
            raise RuntimeError(failure_message)
        return SimpleNamespace(**state)

    sslfilter_store = SimpleNamespace(
        squid_include_path=str(tmp_path / "sslfilter.conf"),
        nobump_list_path=str(tmp_path / "nobump.txt"),
        nocache_src_list_path=str(tmp_path / "nocache.txt"),
        render_materialized_state=lambda: render_store(
            "sslfilter",
            include_text="",
            nobump_src_list_text="",
            nocache_src_list_text="",
        ),
    )
    webfilter_store = SimpleNamespace(
        squid_include_path=str(tmp_path / "webfilter.conf"),
        whitelist_path=str(tmp_path / "whitelist.txt"),
        render_materialized_state=lambda: render_store(
            "webfilter",
            include_text="",
            whitelist_text="",
        ),
    )

    token = set_proxy_id("outer-proxy")
    try:
        with pytest.raises(RuntimeError, match=f"{failing_store} render failed"):
            build_proxy_policy_state_from_stores(
                "proxy-a",
                sslfilter_store=sslfilter_store,
                webfilter_store=webfilter_store,
            )
        assert seen_proxy_ids
        assert set(seen_proxy_ids) == {"proxy-a"}
        assert get_proxy_id() == "outer-proxy"
    finally:
        reset_proxy_id(token)


def test_policy_materializer_restores_context_after_success(tmp_path) -> None:

    from services.policy_materializer import (  # type: ignore
        build_proxy_policy_state_from_stores,
    )
    from services.proxy_context import (  # type: ignore
        get_proxy_id,
        reset_proxy_id,
        set_proxy_id,
    )

    seen_proxy_ids: list[str] = []
    sslfilter_store = SimpleNamespace(
        squid_include_path=str(tmp_path / "sslfilter.conf"),
        nobump_list_path=str(tmp_path / "nobump.txt"),
        nocache_src_list_path=str(tmp_path / "nocache.txt"),
        render_materialized_state=lambda: (
            seen_proxy_ids.append(get_proxy_id())
            or SimpleNamespace(
                include_text="",
                nobump_src_list_text="",
                nocache_src_list_text="",
            )
        ),
    )
    webfilter_store = SimpleNamespace(
        squid_include_path=str(tmp_path / "webfilter.conf"),
        whitelist_path=str(tmp_path / "whitelist.txt"),
        render_materialized_state=lambda: (
            seen_proxy_ids.append(get_proxy_id())
            or SimpleNamespace(include_text="", whitelist_text="")
        ),
    )

    token = set_proxy_id("outer-proxy")
    try:
        state = build_proxy_policy_state_from_stores(
            "proxy-a",
            sslfilter_store=sslfilter_store,
            webfilter_store=webfilter_store,
        )
        assert state.proxy_id == "proxy-a"
        assert seen_proxy_ids == ["proxy-a", "proxy-a"]
        assert get_proxy_id() == "outer-proxy"
    finally:
        reset_proxy_id(token)
