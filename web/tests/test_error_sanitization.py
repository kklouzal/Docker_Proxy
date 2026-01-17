from services.errors import clean_text, public_error_message


def test_clean_text_strips_newlines_and_bounds_length():
    s = "hello\nworld\r\n\t\x00!"
    out = clean_text(s, max_len=20)
    assert "\n" not in out
    assert "\r" not in out
    assert len(out) <= 20


def test_public_error_message_hides_details_by_default(monkeypatch):
    monkeypatch.delenv("EXPOSE_INTERNAL_ERRORS", raising=False)

    class SecretError(RuntimeError):
        pass

    msg = public_error_message(SecretError("db password=supersecret"))
    assert "supersecret" not in msg


def test_public_error_message_shows_valueerror_message(monkeypatch):
    monkeypatch.delenv("EXPOSE_INTERNAL_ERRORS", raising=False)
    msg = public_error_message(ValueError("Bad input: x"))
    assert "Bad input" in msg


def test_public_error_message_can_expose_details(monkeypatch):
    monkeypatch.setenv("EXPOSE_INTERNAL_ERRORS", "1")
    msg = public_error_message(RuntimeError("detail"))
    assert "RuntimeError" in msg
    assert "detail" in msg
