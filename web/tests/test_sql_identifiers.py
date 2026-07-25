from __future__ import annotations

import pytest
from services.sql_identifiers import quote_mysql_identifier


def test_quote_mysql_identifier_accepts_simple_identifiers() -> None:
    assert quote_mysql_identifier(" diagnostic_requests ") == "`diagnostic_requests`"
    assert quote_mysql_identifier("ts_1m") == "`ts_1m`"
    assert quote_mysql_identifier("_temp") == "`_temp`"


@pytest.mark.parametrize(
    "identifier",
    ["", "bad-name", "table; DROP", "table.name", "123abc", "ümlaut"],
)
def test_quote_mysql_identifier_rejects_unsafe_identifiers(identifier: str) -> None:
    with pytest.raises(ValueError, match="Unsafe MySQL identifier"):
        quote_mysql_identifier(identifier)
