from email.message import Message

import pytest

from headerguard.fetcher import _collect, normalise_url


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "https://example.com"),
        ("  example.com/path  ", "https://example.com/path"),
        ("http://example.com", "http://example.com"),
        ("HTTPS://Example.com", "HTTPS://Example.com"),
    ],
)
def test_normalise_url(raw, expected):
    assert normalise_url(raw) == expected


@pytest.mark.parametrize("bad", ["", "   ", "ftp://example.com", "file:///etc/passwd", "javascript://x"])
def test_normalise_url_rejects_bad_input(bad):
    with pytest.raises(ValueError):
        normalise_url(bad)


def test_collect_lowercases_and_separates_cookies():
    msg = Message()
    msg["Strict-Transport-Security"] = "max-age=1"
    msg["Set-Cookie"] = "a=1; Secure"
    msg["Set-Cookie"] = "b=2"
    msg["Vary"] = "Accept"
    msg["Vary"] = "Origin"

    headers, cookies = _collect(msg)

    assert headers["strict-transport-security"] == "max-age=1"
    assert headers["vary"] == "Accept, Origin"
    assert "set-cookie" not in headers
    assert cookies == ["a=1; Secure", "b=2"]
