from __future__ import annotations

import hashlib
import hmac

import pytest


def _configure(privacy_labels, secret: str = "persistent-test-secret") -> None:
    privacy_labels.configure_pseudonym_secret(secret)


def test_pseudonymize_is_stable_and_namespaced(monkeypatch) -> None:
    from services import privacy_labels  # type: ignore

    monkeypatch.setattr(privacy_labels, "get_proxy_id", lambda: "proxy-a")
    _configure(privacy_labels)

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
    from services import privacy_labels  # type: ignore

    monkeypatch.setattr(privacy_labels, "get_proxy_id", lambda: "proxy-a")
    _configure(privacy_labels)

    assert privacy_labels.pseudonymize("Example.COM", namespace="user") == (
        privacy_labels.pseudonymize(" example.com ", namespace="user")
    )
    assert privacy_labels.pseudonymize("GROUP-A", namespace="group") == (
        privacy_labels.pseudonymize("group-a", namespace="group")
    )


def test_is_pseudonymized_label_requires_exact_digest_shape() -> None:
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


def test_pseudonymize_uses_derived_secret_key(monkeypatch) -> None:
    from services import privacy_labels  # type: ignore

    monkeypatch.setattr(privacy_labels, "get_proxy_id", lambda: "proxy-a")
    secret = "configured-and-persisted-secret"
    _configure(privacy_labels, secret)

    derived_key = hmac.digest(
        secret.encode(),
        b"docker-proxy/observability-pseudonyms/v1",
        "sha256",
    )
    expected = hmac.new(
        derived_key,
        b"proxy-a:user:10.0.0.5",
        hashlib.sha256,
    ).hexdigest()[:10]
    label = privacy_labels.pseudonymize("10.0.0.5", namespace="user")

    assert label == f"user-{expected}"
    assert label != "user-" + hashlib.sha256(b"proxy-a:user:10.0.0.5").hexdigest()[:10]


def test_pseudonymize_separates_proxy_and_secret(monkeypatch) -> None:
    from services import privacy_labels  # type: ignore

    proxy_id = "proxy-a"
    monkeypatch.setattr(privacy_labels, "get_proxy_id", lambda: proxy_id)
    _configure(privacy_labels, "secret-one")
    first = privacy_labels.pseudonymize("alice", namespace="user")

    proxy_id = "proxy-b"
    assert privacy_labels.pseudonymize("alice", namespace="user") != first
    proxy_id = "proxy-a"
    _configure(privacy_labels, "secret-two")
    assert privacy_labels.pseudonymize("alice", namespace="user") != first
    _configure(privacy_labels, "secret-one")
    assert privacy_labels.pseudonymize("alice", namespace="user") == first


def test_pseudonymize_fails_closed_without_key(monkeypatch) -> None:
    from services import privacy_labels  # type: ignore

    monkeypatch.setattr(privacy_labels, "_PSEUDONYM_KEY", None)
    with pytest.raises(RuntimeError, match="key material is unavailable"):
        privacy_labels.pseudonymize("alice", namespace="user")


def test_existing_pseudonym_shape_remains_compatible() -> None:
    from services import privacy_labels  # type: ignore

    # Export sanitization continues to recognize labels emitted before this
    # keyed derivation change, avoiding double-pseudonymization.
    assert privacy_labels.is_pseudonymized_label(
        "user-0123456789",
        namespace="user",
    )


def test_configure_pseudonym_secret_rejects_empty_key_material() -> None:
    from services import privacy_labels  # type: ignore

    with pytest.raises(RuntimeError, match="must not be empty"):
        privacy_labels.configure_pseudonym_secret("")
