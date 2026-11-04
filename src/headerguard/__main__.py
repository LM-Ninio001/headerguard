"""Entry point so the tool can be run with `python -m headerguard <url>`."""

from __future__ import annotations

import sys

from headerguard import __version__
from headerguard.fetcher import FetchError, fetch
from headerguard.grading import grade
from headerguard.headers import FAIL, PASS, check_headers
from headerguard.tls import check_tls, inspect

ICONS = {PASS: "[PASS]", "warn": "[WARN]", FAIL: "[FAIL]"}


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args or args[0] in ("-h", "--help"):
        print(f"HeaderGuard v{__version__}\nUsage: headerguard <url>")
        return 0 if args else 1

    try:
        result = fetch(args[0])
    except (FetchError, ValueError) as err:
        print(f"Error: {err}", file=sys.stderr)
        return 2

    findings = check_tls(result.final_url, inspect(result.final_url))
    findings += check_headers(result.headers)
    summary = grade(findings)

    print(f"Scanned {result.final_url} (HTTP {result.status})")
    print(f"Grade: {summary.letter}   Score: {summary.score}/100   "
          f"({summary.passed} passed, {summary.warnings} warnings, {summary.failed} failed)\n")
    for finding in findings:
        print(f"{ICONS[finding.status]} {finding.header:<27} {finding.message}")
        if finding.status != PASS:
            print(f"       fix: {finding.fix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
