import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from headerguard import web  # noqa: E402
from headerguard.fetcher import FetchError  # noqa: E402
from headerguard.grading import grade  # noqa: E402
from headerguard.headers import check_headers  # noqa: E402
from headerguard.safety import BlockedTarget  # noqa: E402
from headerguard.scanner import Report  # noqa: E402


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(web, "limiter", web._RateLimiter(limit=100, window=60))
    return TestClient(web.app)


def fake_scan(url, timeout, guard):
    findings = check_headers({"x-frame-options": "DENY"})
    return Report(url, "https://example.com/", 200, grade(findings), findings)


def test_health(client):
    assert client.get("/api/health").json()["status"] == "ok"


def test_scan_returns_report(client, monkeypatch):
    calls = {}

    def spy(url, timeout, guard):
        calls.update(url=url, timeout=timeout, guard=guard)
        return fake_scan(url, timeout, guard)

    monkeypatch.setattr(web, "scan", spy)
    response = client.post("/api/scan", json={"url": "example.com"})

    assert response.status_code == 200
    data = response.json()
    assert data["final_url"] == "https://example.com/"
    assert data["grade"]["letter"] in "ABCDEF"
    assert calls["guard"] is web.check_target  # SSRF guard is always applied
    assert calls["timeout"] == web.SCAN_TIMEOUT


@pytest.mark.parametrize("payload", [{}, {"url": ""}, {"url": "x" * 3000}, {"link": "example.com"}])
def test_invalid_body_rejected(client, payload):
    assert client.post("/api/scan", json=payload).status_code == 422


@pytest.mark.parametrize(
    ("error", "status"),
    [(BlockedTarget("private address"), 400), (ValueError("bad url"), 400), (FetchError("timed out"), 502)],
)
def test_errors_map_to_status_codes(client, monkeypatch, error, status):
    def boom(url, timeout, guard):
        raise error

    monkeypatch.setattr(web, "scan", boom)
    response = client.post("/api/scan", json={"url": "example.com"})
    assert response.status_code == status
    assert str(error) in response.json()["detail"]


def test_localhost_blocked_end_to_end(client):
    # Real guard, real scan: must be refused before any connection is made.
    response = client.post("/api/scan", json={"url": "http://127.0.0.1:8000/admin"})
    assert response.status_code == 400
    assert "not allowed" in response.json()["detail"]


def test_rate_limit(monkeypatch):
    monkeypatch.setattr(web, "limiter", web._RateLimiter(limit=2, window=60))
    monkeypatch.setattr(web, "scan", fake_scan)
    client = TestClient(web.app)
    codes = [client.post("/api/scan", json={"url": "example.com"}).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


def test_dashboard_served_with_strict_headers(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "<title>HeaderGuard</title>" in response.text
    csp = response.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_dashboard_passes_its_own_header_checks(client):
    from headerguard.headers import PASS, check_headers

    headers = {k.lower(): v for k, v in client.get("/").headers.items()}
    assert all(f.status == PASS for f in check_headers(headers))


def test_static_assets_served(client):
    for path in ("/static/app.js", "/static/style.css"):
        assert client.get(path).status_code == 200


def test_dashboard_js_never_uses_innerhtml():
    # Header values come from arbitrary websites, so they must never be parsed as HTML.
    from pathlib import Path

    js = (Path(web.__file__).parent / "static" / "app.js").read_text(encoding="utf-8")
    assert "innerHTML" not in js.replace("never innerHTML", "")


def test_docs_still_load(client):
    assert client.get("/docs").status_code == 200


def test_cors_allows_github_pages_only(client):
    headers = {"Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type"}
    ok = client.options("/api/scan", headers={**headers, "Origin": "https://lm-ninio001.github.io"})
    assert ok.headers.get("access-control-allow-origin") == "https://lm-ninio001.github.io"
    assert "access-control-allow-credentials" not in ok.headers
    evil = client.options("/api/scan", headers={**headers, "Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in evil.headers
