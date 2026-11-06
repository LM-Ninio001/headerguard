"""Cookie security checks based on the site's Set-Cookie headers."""

from __future__ import annotations

from dataclasses import dataclass, field

from headerguard.headers import FAIL, PASS, WARN, Finding

_ORDER = {PASS: 0, WARN: 1, FAIL: 2}


@dataclass
class Cookie:
    name: str
    attributes: dict[str, str] = field(default_factory=dict)  # lower-case keys

    def has(self, attr: str) -> bool:
        return attr in self.attributes


def parse_set_cookie(header: str) -> Cookie:
    """Parse one Set-Cookie value such as `id=abc; Path=/; Secure; HttpOnly`."""
    first, *rest = header.split(";")
    name = first.split("=", 1)[0].strip()
    attributes = {}
    for part in rest:
        key, _, value = part.strip().partition("=")
        if key:
            attributes[key.lower()] = value.strip()
    return Cookie(name, attributes)


def cookie_issues(cookie: Cookie, https: bool) -> list[tuple[str, str]]:
    """Return (status, problem) pairs for a single cookie."""
    issues = []
    secure = cookie.has("secure")
    samesite = cookie.attributes.get("samesite", "").lower()

    if https and not secure:
        issues.append((FAIL, "missing Secure (can be sent over plain HTTP)"))
    if not cookie.has("httponly"):
        issues.append((WARN, "missing HttpOnly (readable by JavaScript, so XSS can steal it)"))
    if not samesite:
        issues.append((WARN, "missing SameSite (relies on browser defaults against CSRF)"))
    elif samesite == "none" and not secure:
        issues.append((FAIL, "SameSite=None without Secure is rejected by browsers"))

    if cookie.name.startswith("__Host-"):
        if not secure or cookie.has("domain") or cookie.attributes.get("path") != "/":
            issues.append((FAIL, "__Host- prefix requires Secure, Path=/ and no Domain"))
    elif cookie.name.startswith("__Secure-") and not secure:
        issues.append((FAIL, "__Secure- prefix requires Secure"))
    return issues


def check_cookies(set_cookies: list[str], https: bool = True) -> list[Finding]:
    """Summarise every cookie into one finding (none if the site sets no cookies)."""
    if not set_cookies:
        return []
    cookies = [parse_set_cookie(value) for value in set_cookies]
    problems = []
    worst = PASS
    for cookie in cookies:
        for status, problem in cookie_issues(cookie, https):
            problems.append(f"{cookie.name}: {problem}")
            if _ORDER[status] > _ORDER[worst]:
                worst = status

    count = len(cookies)
    if worst == PASS:
        message = f"All {count} cookie(s) use Secure, HttpOnly and SameSite"
    else:
        message = f"{len(problems)} issue(s) across {count} cookie(s): " + "; ".join(problems)
    return [
        Finding(
            "Cookies",
            worst,
            message,
            "Weak cookie flags let session cookies leak over HTTP, be stolen by scripts or be abused in CSRF attacks.",
            "Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax; Path=/",
            ", ".join(c.name for c in cookies),
        )
    ]
