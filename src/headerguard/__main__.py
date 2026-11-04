"""Entry point so the tool can be run with `python -m headerguard <url>`."""

from __future__ import annotations

import sys

from headerguard import __version__
from headerguard.fetcher import FetchError, fetch
from headerguard.headers import FAIL, PASS, check_headers

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

    print(f"Scanned {result.final_url} (HTTP {result.status})\n")
    for finding in check_headers(result.headers):
        print(f"{ICONS[finding.status]} {finding.header:<27} {finding.message}")
        if finding.status != PASS:
            print(f"       fix: {finding.fix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
