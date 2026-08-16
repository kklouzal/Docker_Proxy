from __future__ import annotations

import pytest
from services.row_access import row_value


def test_row_value_reads_mapping_and_sequence_rows() -> None:
    assert row_value({"name": "mapping"}, "name", 0) == "mapping"
    assert row_value(("sequence",), "name", 0) == "sequence"
    assert row_value(["sequence"], "name", 0) == "sequence"


def test_row_value_falls_back_from_missing_mapping_key_to_integer_key() -> None:
    assert row_value({0: "positional"}, "name", 0) == "positional"


def test_row_value_returns_none_for_absent_key_or_index_and_none_row() -> None:
    assert row_value({}, "missing", 0) is None
    assert row_value((), "missing", 0) is None
    assert row_value(None, "missing", 0) is None


class _MalformedRow:
    def __getitem__(self, key: object) -> object:
        message = f"malformed access: {key}"
        raise RuntimeError(message)


def test_row_value_does_not_mask_unexpected_row_access_errors() -> None:
    with pytest.raises(RuntimeError, match="malformed access: name"):
        row_value(_MalformedRow(), "name", 0)
