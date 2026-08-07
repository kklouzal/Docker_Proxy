from __future__ import annotations

import pytest
from services.sql_identifiers import normalize_mysql_identifier, quote_mysql_identifier


def test_normalize_mysql_identifier_returns_unquoted_identifier() -> None:
    assert normalize_mysql_identifier(" proxy_config_revisions ") == "proxy_config_revisions"


def test_quote_mysql_identifier_accepts_simple_identifiers() -> None:
    assert quote_mysql_identifier(" diagnostic_requests ") == "`diagnostic_requests`"
    assert quote_mysql_identifier("ts_1m") == "`ts_1m`"
    assert quote_mysql_identifier("_temp") == "`_temp`"


@pytest.mark.parametrize(
    "identifier",
    ["", "bad-name", "table; DROP", "table.name", "123abc", "ümlaut"],
)
def test_mysql_identifier_helpers_reject_unsafe_identifiers(identifier: str) -> None:
    for helper in (normalize_mysql_identifier, quote_mysql_identifier):
        with pytest.raises(ValueError, match="Unsafe MySQL identifier"):
            helper(identifier)
