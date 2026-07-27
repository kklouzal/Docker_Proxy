from __future__ import annotations

import os
import pathlib
import sys


def _add_web_to_path() -> None:
    web_dir = pathlib.Path(os.path.join(pathlib.Path(__file__).parent, "..")).resolve()
    if web_dir not in sys.path:
        sys.path.insert(0, web_dir)


def test_pseudonymize_is_stable_and_namespaced(monkeypatch) -> None:
    _add_web_to_path()
    from services import privacy_labels  # type: ignore

    monkeypatch.setattr(privacy_labels, "get_proxy_id", lambda: "proxy-a")

    assert privacy_labels.pseudonymize("", namespace="user") == ""
    assert privacy_labels.pseudonymize(" 10.0.0.5 ", namespace="user") == (
        privacy_labels.pseudonymize("10.0.0.5", namespace="user")
    )
    assert privacy_labels.pseudonymize("10.0.0.5", namespace="user").startswith(
        "user-",
    )
    assert privacy_labels.pseudonymize(
        "10.0.0.5",
        namespace="user",
    ) != privacy_labels.pseudonymize("10.0.0.5", namespace="group")


def test_pseudonymize_casefolds_identifier_values(monkeypatch) -> None:
    _add_web_to_path()
    from services import privacy_labels  # type: ignore

    monkeypatch.setattr(privacy_labels, "get_proxy_id", lambda: "proxy-a")

    assert privacy_labels.pseudonymize("Example.COM", namespace="user") == (
        privacy_labels.pseudonymize(" example.com ", namespace="user")
    )
    assert privacy_labels.pseudonymize("GROUP-A", namespace="group") == (
        privacy_labels.pseudonymize("group-a", namespace="group")
    )


def test_is_pseudonymized_label_requires_exact_digest_shape() -> None:
    _add_web_to_path()
    from services import privacy_labels  # type: ignore

    assert privacy_labels.is_pseudonymized_label(
        "user-0123456789",
        namespace="user",
    )
    assert privacy_labels.is_pseudonymized_label(
        " group-abcdef1234 ",
        namespace="group",
    )
    assert not privacy_labels.is_pseudonymized_label(
        "user-alice@example.com",
        namespace="user",
    )
    assert not privacy_labels.is_pseudonymized_label(
        "group-domain-admins",
        namespace="group",
    )
    assert not privacy_labels.is_pseudonymized_label(
        "group-abcdef1234",
        namespace="user",
    )
