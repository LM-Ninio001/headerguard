"""Run every check against a URL and bundle the results into one Report."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Callable

from headerguard import __version__
from headerguard.cookies import check_cookies
from headerguard.fetcher import DEFAULT_TIMEOUT, fetch
from headerguard.grading import Grade, grade
from headerguard.headers import Finding, check_headers
from headerguard.tls import TLSInfo, check_tls, inspect


@dataclass
class Report:
    url: str
    final_url: str
    status: int
    grade: Grade
    findings: list[Finding]
    tls: TLSInfo | None = None
    scanned_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
    version: str = __version__

    def to_dict(self) -> dict:
        data = asdict(self)
        if self.tls and self.tls.not_after:
            data["tls"]["not_after"] = self.tls.not_after.isoformat()
        return data


def scan(url: str, timeout: float = DEFAULT_TIMEOUT, guard: Callable[[str], None] | None = None) -> Report:
    """Fetch `url` once, then run the TLS, header and cookie checks.

    `guard` is passed to fetch() to vet the URL and every redirect target.
    """
    result = fetch(url, timeout=timeout, guard=guard)
    tls_info = inspect(result.final_url, timeout=timeout)
    findings = check_tls(result.final_url, tls_info)
    findings += check_headers(result.headers)
    findings += check_cookies(result.set_cookies, result.final_url.startswith("https://"))
    return Report(result.requested_url, result.final_url, result.status, grade(findings), findings, tls_info)
