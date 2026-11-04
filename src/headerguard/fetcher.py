"""Fetch a URL and return its final response headers.

Only a normal GET request is made, exactly like a browser visiting the page,
so HeaderGuard stays a passive tool.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import dataclass, field
from email.message import Message

USER_AGENT = "HeaderGuard/0.1 (+https://github.com/LM-Ninio001/headerguard)"
DEFAULT_TIMEOUT = 10


class FetchError(Exception):
    """Raised when the target could not be reached."""


@dataclass
class FetchResult:
    requested_url: str
    final_url: str
    status: int
    headers: dict[str, str]
    set_cookies: list[str] = field(default_factory=list)


def normalise_url(url: str) -> str:
    """Add https:// when the user typed a bare domain like `example.com`."""
    url = url.strip()
    if not url:
        raise ValueError("URL must not be empty")
    if "://" not in url:
        url = "https://" + url
    if not url.lower().startswith(("http://", "https://")):
        raise ValueError("Only http:// and https:// URLs are supported")
    return url


def _collect(message: Message) -> tuple[dict[str, str], list[str]]:
    # Header names are case-insensitive, so store them lower-cased.
    headers: dict[str, str] = {}
    for name, value in message.items():
        key = name.lower()
        if key == "set-cookie":
            continue
        headers[key] = f"{headers[key]}, {value}" if key in headers else value
    cookies = message.get_all("Set-Cookie") or []
    return headers, list(cookies)


def fetch(url: str, timeout: float = DEFAULT_TIMEOUT) -> FetchResult:
    """GET `url` (following redirects) and return status and headers."""
    url = normalise_url(url)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            headers, cookies = _collect(response.headers)
            return FetchResult(url, response.geturl(), response.status, headers, cookies)
    except urllib.error.HTTPError as err:
        # A 403 or 404 page still sends headers worth auditing.
        headers, cookies = _collect(err.headers)
        return FetchResult(url, err.geturl() or url, err.code, headers, cookies)
    except (urllib.error.URLError, TimeoutError, OSError) as err:
        reason = getattr(err, "reason", err)
        raise FetchError(f"Could not reach {url}: {reason}") from err
