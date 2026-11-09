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


def test_api_origin_validation():
    import pytest

    from headerguard.site import api_origin

    assert api_origin("https://headerguard.onrender.com/") == "https://headerguard.onrender.com"
    for bad in ("http://insecure.example", "https://x.example/api", "javascript:alert(1)", "https://x.example/?a=1"):
        with pytest.raises(ValueError):
            api_origin(bad)


def test_build_with_api_url_allows_only_that_origin(tmp_path):
    index = build(["a.example"], tmp_path, scanner=fake_scanner, api_url="https://hg.onrender.com")
    assert index["api_url"] == "https://hg.onrender.com"
    page = (tmp_path / "index.html").read_text(encoding="utf-8")
    assert "connect-src 'self' https://hg.onrender.com;" in page


def test_build_without_api_url_keeps_strict_csp(tmp_path):
    index = build(["a.example"], tmp_path, scanner=fake_scanner)
    assert "api_url" not in index
    assert "connect-src 'self';" in (tmp_path / "index.html").read_text(encoding="utf-8")
