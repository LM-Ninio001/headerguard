"""TLS (HTTPS) checks: protocol version and certificate health.

Opens one normal TLS handshake to the site, the same one a browser makes,
and reads the certificate the server presents.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit

from headerguard.headers import FAIL, PASS, WARN, Finding

EXPIRY_WARN_DAYS = 30
MODERN_VERSIONS = ("TLSv1.3", "TLSv1.2")


@dataclass
class TLSInfo:
    host: str
    version: str | None = None
    issuer: str | None = None
    subject: str | None = None
    not_after: datetime | None = None
    days_left: int | None = None
    error: str | None = None


def _name(parts) -> str | None:
    # Certificate names arrive as ((("commonName", "x"),), ...) tuples.
    fields = {key: value for rdn in parts or () for key, value in rdn}
    return fields.get("organizationName") or fields.get("commonName")


def inspect(url: str, timeout: float = 10, now: datetime | None = None) -> TLSInfo | None:
    """Return TLS details for an https:// URL, or None for plain http://."""
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        return None
    host, port = parts.hostname, parts.port or 443
    info = TLSInfo(host=host)
    context = ssl.create_default_context()  # verifies chain and hostname
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                info.version = tls.version()
                cert = tls.getpeercert()
    except ssl.SSLCertVerificationError as err:
        info.error = err.verify_message or str(err)
        return info
    except (ssl.SSLError, OSError) as err:
        info.error = str(err)
        return info

    info.issuer = _name(cert.get("issuer"))
    info.subject = _name(cert.get("subject"))
    if cert.get("notAfter"):
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
        info.not_after = expires
        info.days_left = (expires - (now or datetime.now(timezone.utc))).days
    return info


def check_tls(url: str, info: TLSInfo | None) -> list[Finding]:
    """Turn TLS details into findings that the grader understands."""
    if info is None:
        return [
            Finding(
                "HTTPS",
                FAIL,
                f"Site was served over plain HTTP ({url})",
                "Everything sent between visitors and the site can be read or changed in transit.",
                "Serve the site over HTTPS and redirect all http:// requests to https://.",
            )
        ]
    if info.error:
        return [
            Finding(
                "TLS Certificate",
                FAIL,
                f"Certificate could not be verified: {info.error}",
                "Browsers show a security warning, and visitors cannot tell the real site from an impostor.",
                "Install a valid certificate for this hostname (for example, free from Let's Encrypt).",
            )
        ]

    findings = []
    if info.version in MODERN_VERSIONS:
        version_status, version_msg = PASS, f"Negotiated {info.version}"
    else:
        version_status, version_msg = FAIL, f"Negotiated outdated {info.version}"
    findings.append(
        Finding(
            "TLS Version",
            version_status,
            version_msg,
            "TLS 1.0 and 1.1 have known weaknesses and are rejected by modern browsers.",
            "Allow only TLS 1.2 and TLS 1.3 in the server configuration.",
            info.version,
        )
    )

    days = info.days_left
    if days is None:
        cert_status, cert_msg = WARN, "Valid, but expiry date could not be read"
    elif days < 0:
        cert_status, cert_msg = FAIL, f"Expired {-days} days ago"
    elif days < EXPIRY_WARN_DAYS:
        cert_status, cert_msg = WARN, f"Valid but expires in {days} days"
    else:
        cert_status, cert_msg = PASS, f"Valid for {days} more days"
    issuer = f" (issued by {info.issuer})" if info.issuer else ""
    findings.append(
        Finding(
            "TLS Certificate",
            cert_status,
            cert_msg + issuer,
            "An expired certificate breaks the site for every visitor and trains users to ignore warnings.",
            "Renew automatically (for example, with certbot) well before the expiry date.",
            info.not_after.date().isoformat() if info.not_after else None,
        )
    )
    return findings
