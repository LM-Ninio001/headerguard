# 🛡️ HeaderGuard

[![tests](https://github.com/LM-Ninio001/headerguard/actions/workflows/tests.yml/badge.svg)](https://github.com/LM-Ninio001/headerguard/actions/workflows/tests.yml)
![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**HeaderGuard** is a web security auditor that checks how well a website is protected by its HTTP security headers, TLS (HTTPS) setup and cookie settings, then gives it a grade from **A to F** with plain-English explanations and fixes.

> ⚠️ HeaderGuard is a **passive** tool. It only reads the same response any normal browser receives. It does not attack, probe or exploit anything.

## ✨ Planned features

- [x] Fetch a URL and inspect its security headers
- [x] A–F grading with an explanation for every finding
- [x] TLS certificate and protocol version checks
- [x] Cookie flag analysis (`Secure`, `HttpOnly`, `SameSite`)
- [x] CLI with JSON and HTML report output
- [ ] Visual web dashboard (grade badge, score gauge, header cards)
- [x] Automated tests and CI with GitHub Actions

## 🔍 What it checks

| Header | Protects against |
|---|---|
| `Strict-Transport-Security` | HTTPS downgrade / man-in-the-middle attacks |
| `Content-Security-Policy` | Cross-site scripting (XSS) and code injection |
| `X-Frame-Options` | Clickjacking |
| `X-Content-Type-Options` | MIME-type sniffing |
| `Referrer-Policy` | Leaking sensitive URLs to other sites |
| `Permissions-Policy` | Unwanted access to camera, mic, location etc. |

## 🚀 Getting started

```bash
git clone https://github.com/LM-Ninio001/headerguard.git
cd headerguard
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e .
```

## 🖥️ Usage

```bash
headerguard example.com                  # coloured report in the terminal
headerguard example.com --json           # machine-readable JSON
headerguard example.com --html report.html   # save a shareable HTML report
headerguard example.com --fail-under 75  # exit code 1 if the score is below 75
```

Example output:

```
Scanned https://example.com (HTTP 200)
Grade: C   Score: 62/100   (4 passed, 2 warnings, 3 failed)

[PASS] TLS Version                 Negotiated TLSv1.3
[PASS] TLS Certificate             Valid for 74 more days (issued by Let's Encrypt)
[FAIL] Content-Security-Policy     Missing
       fix: Content-Security-Policy: default-src 'self'; frame-ancestors 'self'
...
```

`--fail-under` makes HeaderGuard usable as a check in CI/CD pipelines, so a deployment can be blocked if security headers regress.

## 🌐 Web API

```bash
pip install -e ".[web]"
headerguard-web                      # serves http://127.0.0.1:8000
curl -X POST http://127.0.0.1:8000/api/scan \
     -H "Content-Type: application/json" -d '{"url": "example.com"}'
```

Interactive API docs are at `/docs`. Endpoints: `POST /api/scan` (full JSON report) and `GET /api/health`.

### 🔒 Hardening the scanner itself

A tool that fetches any URL a stranger types in is a classic **Server-Side Request Forgery (SSRF)** risk: an attacker could point it at `http://127.0.0.1/admin` or the cloud metadata service at `169.254.169.254` to reach things that are not public. HeaderGuard's server defends against this:

- Every hostname is resolved and **rejected if any address is private, loopback, link-local, carrier-grade NAT, reserved or multicast** (IPv4 and IPv6, including IPv4-mapped IPv6 tricks like `::ffff:127.0.0.1`)
- **Each redirect is checked too**, so a public site cannot bounce the scanner to an internal address
- Only ports **80 and 443**, so it cannot be used as a port scanner
- URLs with embedded credentials are refused, input length is capped, and each network step has an **8-second timeout**
- An in-memory **rate limit** (10 scans per client per minute, set with `HEADERGUARD_RATE_LIMIT`)

Known limitation: DNS is resolved once for the check and again for the connection, so a DNS-rebinding attacker could in theory switch addresses in between. Pinning the connection to the vetted IP would close this gap.

## 🧮 How scoring works

Every site starts at 100. Each failed check loses its full weight and each warning loses half:

| Check | Weight |
|---|---|
| HTTPS (served over TLS at all) | 40 |
| TLS certificate valid / not expiring | 30 |
| Content-Security-Policy | 25 |
| Strict-Transport-Security | 20 |
| X-Frame-Options, TLS version | 15 each |
| X-Content-Type-Options, Cookies | 10 each |
| Referrer-Policy, Permissions-Policy | 5 each |
| Version-leaking headers (`Server`, `X-Powered-By`) | 3 each |

Grades: **A** 90+, **B** 75+, **C** 60+, **D** 45+, **E** 30+, **F** below 30.

## 🧰 Tech stack

- Python 3.10+, standard library only (`urllib`, `ssl`, `argparse`)
- `pytest` (80 offline tests) and GitHub Actions CI
- FastAPI + uvicorn for the web API
- (coming soon) HTML/CSS/JS dashboard

## 📚 References

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [MDN: HTTP headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)

## 📄 License

MIT © Luban Mahi Ninio
