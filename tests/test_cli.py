"""CLI and report tests. scan() is replaced with a fake so no network is used."""

import json

import pytest

from headerguard import __main__ as cli
from headerguard.fetcher import FetchError
from headerguard.grading import grade
from headerguard.headers import check_headers
from headerguard.report import to_html, to_json, to_text
from headerguard.scanner import Report


def fake_report(headers=None):
    findings = check_headers(headers or {"x-content-type-options": "nosniff"})
    return Report("example.com", "https://example.com/", 200, grade(findings), findings)


@pytest.fixture
def fake_scan(monkeypatch):
    report = fake_report()
    monkeypatch.setattr(cli, "scan", lambda url, timeout: report)
    return report


def test_text_report_shows_grade(fake_scan, capsys):
    assert cli.main(["example.com", "--no-color"]) == 0
    out = capsys.readouterr().out
    assert f"Grade: {fake_scan.grade.letter}" in out
    assert "[FAIL] Content-Security-Policy" in out


def test_json_output_is_valid(fake_scan, capsys):
    cli.main(["example.com", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["grade"]["score"] == fake_scan.grade.score
    assert {f["header"] for f in data["findings"]} >= {"Content-Security-Policy"}


def test_html_report_written(fake_scan, tmp_path):
    out = tmp_path / "r.html"
    cli.main(["example.com", "--html", str(out)])
    html = out.read_text(encoding="utf-8")
    assert html.startswith("<!doctype html>")
    assert "Content-Security-Policy" in html


def test_fail_under(fake_scan):
    assert cli.main(["example.com", "--fail-under", "101"]) == 1
    assert cli.main(["example.com", "--fail-under", "0"]) == 0


def test_fetch_error_exit_code(monkeypatch, capsys):
    def boom(url, timeout):
        raise FetchError("Could not reach example.com")

    monkeypatch.setattr(cli, "scan", boom)
    assert cli.main(["example.com"]) == 2
    assert "Could not reach" in capsys.readouterr().err


def test_html_escapes_untrusted_values():
    report = fake_report({"server": "<script>alert(1)</script>/1.0"})
    html = to_html(report)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_text_without_colour_has_no_escape_codes():
    assert "\033[" not in to_text(fake_report(), colour=False)


def test_json_round_trip():
    assert json.loads(to_json(fake_report()))["final_url"] == "https://example.com/"
