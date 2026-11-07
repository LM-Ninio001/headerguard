"""Build the static GitHub Pages demo.

Scans every site listed in sites.txt, saves each JSON report under
<out>/data/, writes <out>/data/index.json, and copies the dashboard files.
The dashboard detects data/index.json and switches to demo mode.

Usage:  python -m headerguard.site sites.txt _site
"""

from __future__ import annotations

import json
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from headerguard.fetcher import FetchError
from headerguard.safety import check_target
from headerguard.scanner import Report, scan

STATIC_DIR = Path(__file__).parent / "static"


def read_sites(path: Path) -> list[str]:
    """One site per line; blank lines and # comments are ignored."""
    sites = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            sites.append(line)
    return sites


def slug(host: str) -> str:
    return re.sub(r"[^a-z0-9.-]", "-", host.lower()) + ".json"


def build(sites: list[str], out: Path, scanner: Callable[..., Report] = scan) -> dict:
    data_dir = out / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(STATIC_DIR / "index.html", out / "index.html")
    shutil.copytree(STATIC_DIR, out / "static", dirs_exist_ok=True)

    entries, failures = [], []
    for site in sites:
        try:
            report = scanner(site, timeout=15, guard=check_target)
        except (FetchError, ValueError) as err:
            failures.append(f"{site}: {err}")
            continue
        data = report.to_dict()
        host = re.sub(r"^www\.", "", re.sub(r"^https?://", "", data["final_url"]).split("/")[0].split(":")[0].lower())
        filename = slug(host)
        (data_dir / filename).write_text(json.dumps(data, indent=2), encoding="utf-8")
        entries.append({"host": host, "file": filename, "letter": report.grade.letter, "score": report.grade.score})

    index = {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "sites": entries}
    (data_dir / "index.json").write_text(json.dumps(index, indent=2), encoding="utf-8")
    (out / ".nojekyll").write_text("", encoding="utf-8")
    for failure in failures:
        print(f"skipped {failure}", file=sys.stderr)
    return index


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2:
        print("Usage: python -m headerguard.site SITES_FILE OUTPUT_DIR", file=sys.stderr)
        return 2
    index = build(read_sites(Path(args[0])), Path(args[1]))
    for entry in index["sites"]:
        print(f"{entry['letter']} {entry['score']:>3}  {entry['host']}")
    return 0 if index["sites"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
