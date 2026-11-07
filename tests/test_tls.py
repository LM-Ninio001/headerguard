from datetime import datetime, timedelta, timezone

import pytest

from headerguard.headers import FAIL, PASS, WARN
from headerguard.tls import TLSInfo, _name, check_tls, inspect

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def info(version="TLSv1.3", days=200, **extra):
    return TLSInfo("example.com", version, "Let's Encrypt", "example.com", NOW + timedelta(days=days), days, **extra)


def by_header(findings):
    return {f.header: f.status for f in findings}


def test_plain_http_fails():
    findings = check_tls("http://example.com", None)
    assert by_header(findings) == {"HTTPS": FAIL}


def test_inspect_skips_http():
    assert inspect("http://example.com") is None


def test_verification_error_fails():
    findings = check_tls("https://x", TLSInfo("x", error="certificate has expired"))
    assert by_header(findings) == {"TLS Certificate": FAIL}
    assert "certificate has expired" in findings[0].message


def test_healthy_tls_passes():
    assert by_header(check_tls("https://x", info())) == {"TLS Version": PASS, "TLS Certificate": PASS}


@pytest.mark.parametrize("version", ["TLSv1", "TLSv1.1"])
def test_old_tls_version_fails(version):
    assert by_header(check_tls("https://x", info(version=version)))["TLS Version"] == FAIL


@pytest.mark.parametrize(("days", "expected"), [(29, WARN), (0, WARN), (-1, FAIL), (30, PASS)])
def test_expiry_thresholds(days, expected):
    assert by_header(check_tls("https://x", info(days=days)))["TLS Certificate"] == expected


def test_issuer_shown_in_message():
    cert = next(f for f in check_tls("https://x", info()) if f.header == "TLS Certificate")
    assert "Let's Encrypt" in cert.message


def test_name_prefers_organisation():
    parts = ((("countryName", "US"),), (("organizationName", "Let's Encrypt"),), (("commonName", "R11"),))
    assert _name(parts) == "Let's Encrypt"
    assert _name(((("commonName", "R11"),),)) == "R11"
    assert _name(None) is None
