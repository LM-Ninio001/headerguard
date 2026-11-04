"""Security header rules.

Each rule checks one header and returns a Finding explaining what was found,
why it matters and how to fix it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

PASS, WARN, FAIL = "pass", "warn", "fail"


@dataclass
class Finding:
    header: str
    status: str  # pass | warn | fail
    message: str
    risk: str
    fix: str
    value: str | None = None


def _hsts(value: str | None) -> tuple[str, str]:
    if value is None:
        return FAIL, "Missing"
    match = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.I)
    if not match:
        return FAIL, "Present but has no valid max-age"
    max_age = int(match.group(1))
    if max_age < 15_552_000:  # 180 days
        return WARN, f"max-age is only {max_age // 86400} days (recommend at least 180)"
    if "includesubdomains" not in value.lower():
        return WARN, "Present, but subdomains are not covered (add includeSubDomains)"
    return PASS, "Present with a long max-age"


def _csp(value: str | None) -> tuple[str, str]:
    if value is None:
        return FAIL, "Missing"
    lowered = value.lower()
    weak = [token for token in ("'unsafe-inline'", "'unsafe-eval'") if token in lowered]
    if weak:
        return WARN, f"Present but allows {' and '.join(weak)}"
    if "default-src" not in lowered and "script-src" not in lowered:
        return WARN, "Present but sets neither default-src nor script-src"
    return PASS, "Present"


def _xfo(value: str | None, csp: str | None) -> tuple[str, str]:
    if csp and "frame-ancestors" in csp.lower():
        return PASS, "Covered by CSP frame-ancestors"
    if value is None:
        return FAIL, "Missing"
    if value.strip().upper() in ("DENY", "SAMEORIGIN"):
        return PASS, f"Set to {value.strip().upper()}"
    return WARN, f"Unrecognised value '{value}'"


def _xcto(value: str | None) -> tuple[str, str]:
    if value is None:
        return FAIL, "Missing"
    if value.strip().lower() == "nosniff":
        return PASS, "Set to nosniff"
    return WARN, f"Should be 'nosniff', got '{value}'"


def _referrer(value: str | None) -> tuple[str, str]:
    if value is None:
        return WARN, "Missing (browsers default to strict-origin-when-cross-origin)"
    # The last valid token wins when several are listed.
    policy = value.split(",")[-1].strip().lower()
    if policy in ("unsafe-url", "no-referrer-when-downgrade"):
        return FAIL, f"'{policy}' leaks full URLs to other sites"
    return PASS, f"Set to {policy}"


def _permissions(value: str | None) -> tuple[str, str]:
    if value is None:
        return WARN, "Missing"
    return PASS, "Present"


@dataclass
class Rule:
    header: str
    risk: str
    fix: str
    check: Callable[[dict[str, str]], tuple[str, str]]


RULES: list[Rule] = [
    Rule(
        "Strict-Transport-Security",
        "Without HSTS, an attacker on the same network can downgrade visitors to plain HTTP.",
        "Strict-Transport-Security: max-age=31536000; includeSubDomains",
        lambda h: _hsts(h.get("strict-transport-security")),
    ),
    Rule(
        "Content-Security-Policy",
        "Without a strict CSP, injected scripts (XSS) can run freely in visitors' browsers.",
        "Content-Security-Policy: default-src 'self'; frame-ancestors 'self'",
        lambda h: _csp(h.get("content-security-policy")),
    ),
    Rule(
        "X-Frame-Options",
        "Other sites can load this page inside an invisible frame and trick users into clicks (clickjacking).",
        "X-Frame-Options: DENY  (or CSP frame-ancestors 'self')",
        lambda h: _xfo(h.get("x-frame-options"), h.get("content-security-policy")),
    ),
    Rule(
        "X-Content-Type-Options",
        "Browsers may guess ('sniff') file types and run an uploaded file as a script.",
        "X-Content-Type-Options: nosniff",
        lambda h: _xcto(h.get("x-content-type-options")),
    ),
    Rule(
        "Referrer-Policy",
        "Full URLs, which can contain tokens or private paths, may be sent to other sites.",
        "Referrer-Policy: strict-origin-when-cross-origin",
        lambda h: _referrer(h.get("referrer-policy")),
    ),
    Rule(
        "Permissions-Policy",
        "Embedded content may request powerful features like camera, microphone or location.",
        "Permissions-Policy: camera=(), microphone=(), geolocation=()",
        lambda h: _permissions(h.get("permissions-policy")),
    ),
]

# Headers that reveal software versions and help attackers pick exploits.
LEAKY_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")


def check_headers(headers: dict[str, str]) -> list[Finding]:
    """Run every rule against a lower-cased header dict."""
    lowered = {k.lower(): v for k, v in headers.items()}
    findings = []
    for rule in RULES:
        status, message = rule.check(lowered)
        findings.append(
            Finding(rule.header, status, message, rule.risk, rule.fix, lowered.get(rule.header.lower()))
        )
    for name in LEAKY_HEADERS:
        value = lowered.get(name)
        if value and re.search(r"\d", value):
            findings.append(
                Finding(
                    name.title(),
                    WARN,
                    f"Reveals software version: '{value}'",
                    "Version numbers help attackers look up known vulnerabilities.",
                    f"Remove the {name.title()} header or hide the version number.",
                    value,
                )
            )
    return findings
