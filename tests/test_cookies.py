import pytest

from headerguard.cookies import check_cookies, cookie_issues, parse_set_cookie
from headerguard.headers import FAIL, PASS, WARN

SAFE = "session=abc; Path=/; Secure; HttpOnly; SameSite=Lax"


def test_parse_set_cookie():
    cookie = parse_set_cookie("id=a=b; Path=/; Secure; SameSite=Strict")
    assert cookie.name == "id"
    assert cookie.attributes == {"path": "/", "secure": "", "samesite": "Strict"}
    assert cookie.has("secure") and not cookie.has("httponly")


def test_no_cookies_means_no_finding():
    assert check_cookies([]) == []


def test_safe_cookie_passes():
    [finding] = check_cookies([SAFE])
    assert finding.status == PASS


def test_missing_secure_fails_only_on_https():
    cookie = parse_set_cookie("id=1; HttpOnly; SameSite=Lax")
    assert [s for s, _ in cookie_issues(cookie, https=True)] == [FAIL]
    assert cookie_issues(cookie, https=False) == []


def test_missing_httponly_and_samesite_warn():
    [finding] = check_cookies(["id=1; Secure"])
    assert finding.status == WARN
    assert "HttpOnly" in finding.message and "SameSite" in finding.message


def test_samesite_none_needs_secure():
    issues = cookie_issues(parse_set_cookie("id=1; HttpOnly; SameSite=None"), https=False)
    assert (FAIL, "SameSite=None without Secure is rejected by browsers") in issues


@pytest.mark.parametrize(
    ("header", "ok"),
    [
        ("__Host-id=1; Secure; HttpOnly; SameSite=Lax; Path=/", True),
        ("__Host-id=1; Secure; HttpOnly; SameSite=Lax; Path=/app", False),
        ("__Host-id=1; Secure; HttpOnly; SameSite=Lax; Path=/; Domain=example.com", False),
        ("__Secure-id=1; Secure; HttpOnly; SameSite=Lax", True),
    ],
)
def test_cookie_prefixes(header, ok):
    assert (check_cookies([header])[0].status == PASS) is ok


def test_worst_status_wins_across_cookies():
    [finding] = check_cookies([SAFE, "tracker=1; HttpOnly; SameSite=Lax"])
    assert finding.status == FAIL
    assert finding.value == "session, tracker"
