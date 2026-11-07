import pytest

from headerguard.headers import FAIL, PASS, WARN, check_headers

GOOD = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=()",
}


def status_of(headers, name):
    return next(f for f in check_headers(headers) if f.header == name).status


def test_all_good_headers_pass():
    assert all(f.status == PASS for f in check_headers(GOOD))


def test_empty_headers_fail_or_warn():
    statuses = {f.header: f.status for f in check_headers({})}
    assert statuses["Strict-Transport-Security"] == FAIL
    assert statuses["Content-Security-Policy"] == FAIL
    assert statuses["Referrer-Policy"] == WARN
    assert statuses["Permissions-Policy"] == WARN


def test_header_names_are_case_insensitive():
    assert status_of({"X-Content-Type-Options": "nosniff"}, "X-Content-Type-Options") == PASS


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("max-age=31536000; includeSubDomains", PASS),
        ("max-age=31536000", WARN),  # no includeSubDomains
        ("max-age=3600; includeSubDomains", WARN),  # too short
        ('max-age="31536000"; includeSubDomains', PASS),
        ("includeSubDomains", FAIL),  # no max-age
    ],
)
def test_hsts(value, expected):
    assert status_of({"strict-transport-security": value}, "Strict-Transport-Security") == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("default-src 'self'", PASS),
        ("script-src 'self'", PASS),
        ("default-src 'self' 'unsafe-inline'", WARN),
        ("script-src 'unsafe-eval'", WARN),
        ("img-src *", WARN),
    ],
)
def test_csp(value, expected):
    assert status_of({"content-security-policy": value}, "Content-Security-Policy") == expected


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ({"x-frame-options": "deny"}, PASS),
        ({"x-frame-options": "SAMEORIGIN"}, PASS),
        ({"x-frame-options": "ALLOW-FROM https://x"}, WARN),
        ({"content-security-policy": "frame-ancestors 'none'"}, PASS),
        ({}, FAIL),
    ],
)
def test_x_frame_options(headers, expected):
    assert status_of(headers, "X-Frame-Options") == expected


def test_x_content_type_options_wrong_value_warns():
    assert status_of({"x-content-type-options": "sniff"}, "X-Content-Type-Options") == WARN


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("no-referrer", PASS),
        ("unsafe-url", FAIL),
        ("no-referrer-when-downgrade", FAIL),
        ("unsafe-url, strict-origin", PASS),  # last token wins
    ],
)
def test_referrer_policy(value, expected):
    assert status_of({"referrer-policy": value}, "Referrer-Policy") == expected


def test_version_leaking_headers_warn():
    findings = check_headers({"server": "nginx/1.18.0", "x-powered-by": "PHP/8.1"})
    leaks = {f.header: f.status for f in findings if f.header in ("Server", "X-Powered-By")}
    assert leaks == {"Server": WARN, "X-Powered-By": WARN}


def test_server_without_version_is_fine():
    assert not [f for f in check_headers({"server": "cloudflare"}) if f.header == "Server"]
