from services.blocked_log_runtime import _normalize_log_url
from services.errors import (
    clean_text,
    public_error_message,
    redact_sensitive_text,
    redact_url_for_display,
)
from services.webfilter_store import _sanitize_blocked_log_url


def test_clean_text_strips_newlines_and_bounds_length() -> None:
    s = "hello\nworld\r\n\t\x00!"
    out = clean_text(s, max_len=20)
    assert "\n" not in out
    assert "\r" not in out
    assert len(out) <= 20


def test_redact_sensitive_text_redacts_url_query_credentials_without_losing_context() -> (
    None
):
    msg = redact_sensitive_text(
        "failed: "
        "https://safebrowsing.googleapis.com/v5/hashes:search?key=AIzaSECRET"
        "&hashPrefixes=abcd&prettyPrint=false "
        "mirror=https://example.test/path?api_key=ALIASSECRET&name=keynote "
        "cache key=ordinary"
    )

    assert "AIzaSECRET" not in msg
    assert "ALIASSECRET" not in msg
    assert "safebrowsing.googleapis.com/v5/hashes:search" in msg
    assert "?key=[redacted]" in msg
    assert "&hashPrefixes=abcd" in msg
    assert "&prettyPrint=false" in msg
    assert "https://example.test/path?api_key=[redacted]&name=keynote" in msg
    assert "cache key=ordinary" in msg


def test_shared_url_redactor_preserves_ordinary_query_and_redacts_auth_material() -> (
    None
):
    url = (
        "https://user:pass@example.test/search?q=ordinary&%74oken=secret"
        "&SAMLResponse=assertion&RelayState=%2Fadmin&signature=signed#fragment"
    )

    result = redact_url_for_display(url)

    assert result == (
        "https://example.test/search?q=ordinary&%74oken=[redacted]"
        "&SAMLResponse=[redacted]&RelayState=[redacted]&signature=[redacted]"
    )
    for secret in ("user", "pass", "secret", "assertion", "%2Fadmin", "signed"):
        assert secret not in result


def test_url_redactors_remove_userinfo_from_malformed_authority() -> None:
    url = "https://user:pass@[vbad]/path?token=secret&ok=visible#fragment"
    expected = "https://[vbad]/path?token=[redacted]&ok=visible"

    assert redact_url_for_display(url) == expected
    assert _normalize_log_url(url) == expected
    assert _sanitize_blocked_log_url(url) == expected


def test_public_error_message_hides_details_by_default(monkeypatch) -> None:
    monkeypatch.delenv("EXPOSE_INTERNAL_ERRORS", raising=False)

    class SecretError(RuntimeError):
        pass

    msg = public_error_message(SecretError("db password=supersecret"))
    assert "supersecret" not in msg


def test_public_error_message_shows_valueerror_message(monkeypatch) -> None:
    monkeypatch.delenv("EXPOSE_INTERNAL_ERRORS", raising=False)
    msg = public_error_message(ValueError("Bad input: x"))
    assert "Bad input" in msg


def test_public_error_message_redacts_valueerror_credentials(monkeypatch) -> None:
    monkeypatch.delenv("EXPOSE_INTERNAL_ERRORS", raising=False)

    msg = public_error_message(
        ValueError(
            "Bad proxy config: password=supersecret token: abc "
            "api_key=key123 apikey: altkey client_secret='quoted secret' "
            "Authorization Bearer bearer-token Basic basic-token "
            "url=https://user:pass@example.com/path"
        ),
        max_len=500,
    )

    assert "Bad proxy config" in msg
    for secret in (
        "supersecret",
        "abc",
        "key123",
        "altkey",
        "quoted secret",
        "bearer-token",
        "basic-token",
        "user:pass",
    ):
        assert secret not in msg
    assert "password=[redacted]" in msg
    assert "token: [redacted]" in msg
    assert "api_key=[redacted]" in msg
    assert "apikey: [redacted]" in msg
    assert "client_secret='[redacted]'" in msg
    assert "Bearer [redacted]" in msg
    assert "Basic [redacted]" in msg
    assert "https://[redacted]@example.com/path" in msg


def test_redact_sensitive_text_redacts_multiline_and_escaped_quoted_values() -> None:
    msg = redact_sensitive_text(
        'request failed: password="alpha\r\nbeta" '
        'client_secret="gamma\\"delta\nepsilon"; retry is allowed'
    )

    for secret_fragment in ("alpha", "beta", "gamma", "delta", "epsilon"):
        assert secret_fragment not in msg
    assert 'password="[redacted]"' in msg
    assert 'client_secret="[redacted]"' in msg
    assert "retry is allowed" in msg


def test_public_error_message_redacts_multiline_quoted_credentials(monkeypatch) -> None:
    monkeypatch.delenv("EXPOSE_INTERNAL_ERRORS", raising=False)
    error = ValueError('Bad proxy config: password="alpha\r\nbeta"; keep context')

    msg = public_error_message(error, max_len=500)

    assert "alpha" not in msg
    assert "beta" not in msg
    assert 'password="[redacted]"' in msg
    assert "keep context" in msg


def test_public_error_message_redacts_multiline_exposed_internal_details(
    monkeypatch,
) -> None:
    monkeypatch.setenv("EXPOSE_INTERNAL_ERRORS", "1")
    error = RuntimeError("upstream rejected client_secret='gamma\ndelta'; keep context")

    msg = public_error_message(error, max_len=500)

    assert "gamma" not in msg
    assert "delta" not in msg
    assert "RuntimeError" in msg
    assert "keep context" in msg


def test_redact_sensitive_text_handles_long_unterminated_quoted_value() -> None:
    secret = "s" * 10_000

    msg = redact_sensitive_text(f'password="{secret}')

    assert secret not in msg
    assert msg == "password=[redacted]"


def test_public_error_message_keeps_ordinary_valueerror_context(monkeypatch) -> None:
    monkeypatch.delenv("EXPOSE_INTERNAL_ERRORS", raising=False)
    msg = public_error_message(
        ValueError("Proxy domain example.com is invalid for upstream proxy group")
    )
    assert msg == "Proxy domain example.com is invalid for upstream proxy group"


def test_public_error_message_can_expose_details(monkeypatch) -> None:
    monkeypatch.setenv("EXPOSE_INTERNAL_ERRORS", "1")
    msg = public_error_message(RuntimeError("detail"))
    assert "RuntimeError" in msg
    assert "detail" in msg


def test_public_error_message_redacts_exposed_internal_details(monkeypatch) -> None:
    monkeypatch.setenv("EXPOSE_INTERNAL_ERRORS", "1")
    msg = public_error_message(
        RuntimeError(
            "connection failed for https://admin:p4ss@example.com with token=secret-token"
        )
    )

    assert "RuntimeError" in msg
    assert "connection failed" in msg
    assert "admin:p4ss" not in msg
    assert "secret-token" not in msg
    assert "https://[redacted]@example.com" in msg
    assert "token=[redacted]" in msg
