from __future__ import annotations

import pytest
from services.directory_auth import DirectoryAuthStore
from services.external_auth_groups import (
    candidate_group_match_tokens,
    first_ldap_group_rdn_value,
    required_group_match_tokens,
    unescape_ldap_rdn_value,
)
from services.saml_auth import (
    _candidate_saml_group_match_tokens,
    _required_saml_group_match_tokens,
)


@pytest.mark.parametrize(
    ("asserted", "expected"),
    [
        (" Domain Admins ", "domain admins"),
        (r"EXAMPLE\Domain Admins", "domain admins"),
        ("Domain Admins@example.local", "domain admins"),
        ("CN=Domain Admins,OU=Groups,DC=example,DC=local", "domain admins"),
        ("name=Domain Admins,OU=Groups", "domain admins"),
        (r"CN=Ops\, Tier\=1,OU=Groups", "ops, tier=1"),
        (r"CN=Path\\Owners,OU=Groups", r"path\owners"),
        (r"CN=Gr\c3\bcppe,OU=Groups", "grüppe"),
    ],
)
def test_candidate_alias_contract_is_shared_by_directory_and_saml(
    asserted: str, expected: str
) -> None:
    shared = candidate_group_match_tokens(asserted, preserve_full_dn=False)
    directory = DirectoryAuthStore()._candidate_group_match_tokens(asserted)
    saml = _candidate_saml_group_match_tokens(asserted)

    assert expected in shared
    assert shared == saml
    assert shared <= directory


@pytest.mark.parametrize("value", [None, "", "   "])
def test_empty_group_values_fail_closed(value: object) -> None:
    assert required_group_match_tokens(value, preserve_full_dn=False) == set()
    assert candidate_group_match_tokens(value, preserve_full_dn=False) == set()


def test_directory_preserves_full_dn_token_without_saml_broadening() -> None:
    required = "CN=Ops\\, Tier\\=1,OU=Groups,DC=example,DC=local"
    directory_required = DirectoryAuthStore()._required_group_match_tokens(required)
    saml_required = _required_saml_group_match_tokens(required)

    assert "dn:cn=ops, tier=1,ou=groups,dc=example,dc=local" in directory_required
    assert not any(token.startswith("dn:") for token in saml_required)
    assert (
        DirectoryAuthStore()._required_group_matches(required, ["Ops, Tier=1"]) is False
    )
    assert (
        DirectoryAuthStore()._required_group_matches(
            required, ["cn=Ops\\2C Tier\\3D1,ou=Groups,dc=example,dc=local"]
        )
        is True
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (r"Ops\, Tier\=1", "Ops, Tier=1"),
        (r"Path\\Owners", r"Path\Owners"),
        (r"Gr\c3\bcppe", "Grüppe"),
        (r"literal\zz", "literalzz"),
        ("trailing\\", "trailing\\"),
    ],
)
def test_ldap_rdn_unescaping_contract(value: str, expected: str) -> None:
    assert unescape_ldap_rdn_value(value) == expected


@pytest.mark.parametrize(
    "value",
    ["OU=Domain Admins,DC=example", "CN", "=Domain Admins", "CN=", "plain-name"],
)
def test_malformed_or_non_group_first_rdn_has_no_alias(value: str) -> None:
    assert first_ldap_group_rdn_value(value) == ""
