import json

from headerguard.fetcher import FetchError
from headerguard.grading import grade
from headerguard.headers import check_headers
from headerguard.safety import check_target
from headerguard.scanner import Report
from headerguard.site import build, read_sites, slug


def fake_scanner(site, timeout, guard):
    assert guard is check_target  # the demo build must also refuse private targets
    if site == "down.example":
        raise FetchError("timed out")
    findings = check_headers({"x-frame-options": "DENY"})
    return Report(site, f"https://www.{site}/home", 200, grade(findings), findings)


def test_read_sites_skips_comments_and_blanks(tmp_path):
    path = tmp_path / "sites.txt"
    path.write_text("# header\n\na.example\nb.example  # note\n", encoding="utf-8")
    assert read_sites(path) == ["a.example", "b.example"]


def test_slug_is_filename_safe():
    assert slug("Example.COM") == "example.com.json"
    assert slug("../evil") == "..-evil.json"


def test_build_writes_reports_index_and_dashboard(tmp_path):
    index = build(["a.example", "down.example"], tmp_path, scanner=fake_scanner)

    assert [s["host"] for s in index["sites"]] == ["a.example"]  # failures are skipped
    entry = index["sites"][0]
    report = json.loads((tmp_path / "data" / entry["file"]).read_text(encoding="utf-8"))
    assert report["grade"]["letter"] == entry["letter"]
    assert json.loads((tmp_path / "data" / "index.json").read_text(encoding="utf-8")) == index
    assert (tmp_path / "index.html").exists()
    assert (tmp_path / "static" / "app.js").exists()
    assert (tmp_path / ".nojekyll").exists()
