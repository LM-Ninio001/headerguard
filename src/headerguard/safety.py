"""SSRF protection for the web server.

When HeaderGuard runs as a public web service, anyone can ask the *server* to
fetch a URL. Without checks, an attacker could make it request internal
addresses such as http://127.0.0.1:8000/admin or the cloud metadata endpoint
http://169.254.169.254/ (Server-Side Request Forgery). This module rejects any
target that resolves to a non-public IP address or uses an unusual port.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

ALLOWED_PORTS = {80, 443}


class BlockedTarget(ValueError):
    """Raised when a URL points somewhere the server must not connect to."""


def _resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as err:
        raise BlockedTarget(f"Could not resolve host '{host}'") from err
    return sorted({info[4][0] for info in infos})


def is_public_ip(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%", 1)[0])  # drop IPv6 zone id
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped  # ::ffff:127.0.0.1 is really 127.0.0.1
    return ip.is_global and not ip.is_multicast


def check_target(url: str) -> None:
    """Raise BlockedTarget unless `url` is http(s) on a standard port at a public IP."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise BlockedTarget("Only http:// and https:// URLs can be scanned")
    if parts.username or parts.password:
        raise BlockedTarget("URLs containing credentials are not allowed")
    host = parts.hostname
    if not host:
        raise BlockedTarget("URL has no hostname")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as err:
        raise BlockedTarget("Invalid port") from err
    if port not in ALLOWED_PORTS:
        raise BlockedTarget(f"Port {port} is not allowed (only 80 and 443)")

    for address in _resolve(host):
        if not is_public_ip(address):
            raise BlockedTarget(f"'{host}' resolves to a private or reserved address ({address})")
