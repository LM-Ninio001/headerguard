"""Command-line interface: `headerguard <url> [--json] [--html FILE]`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from headerguard import __version__
from headerguard.fetcher import DEFAULT_TIMEOUT, FetchError
from headerguard.report import to_html, to_json, to_text
from headerguard.scanner import scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="headerguard",
        description="Passively grade a website's security headers, TLS and cookies.",
    )
    parser.add_argument("url", help="site to scan, e.g. example.com or https://example.com")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    parser.add_argument("--html", metavar="FILE", help="also save an HTML report to FILE")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="network timeout in seconds")
    parser.add_argument("--no-color", action="store_true", help="disable coloured terminal output")
    parser.add_argument(
        "--fail-under", type=int, metavar="SCORE",
        help="exit with code 1 if the score is below SCORE (handy in CI pipelines)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = scan(args.url, timeout=args.timeout)
    except (FetchError, ValueError) as err:
        print(f"Error: {err}", file=sys.stderr)
        return 2

    if args.json:
        print(to_json(report))
    else:
        print(to_text(report, colour=sys.stdout.isatty() and not args.no_color))

    if args.html:
        path = Path(args.html)
        path.write_text(to_html(report), encoding="utf-8")
        print(f"HTML report saved to {path}", file=sys.stderr)

    if args.fail_under is not None and report.grade.score < args.fail_under:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
