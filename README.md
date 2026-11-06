# 🛡️ HeaderGuard

**HeaderGuard** is a web security auditor that checks how well a website is protected by its HTTP security headers, TLS (HTTPS) setup and cookie settings, then gives it a grade from **A to F** with plain-English explanations and fixes.

> ⚠️ HeaderGuard is a **passive** tool. It only reads the same response any normal browser receives. It does not attack, probe or exploit anything.

## ✨ Planned features

- [x] Fetch a URL and inspect its security headers
- [x] A–F grading with an explanation for every finding
- [x] TLS certificate and protocol version checks
- [x] Cookie flag analysis (`Secure`, `HttpOnly`, `SameSite`)
- [ ] CLI with JSON and HTML report output
- [ ] Visual web dashboard (grade badge, score gauge, header cards)
- [ ] Automated tests and CI with GitHub Actions

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

> Usage instructions will be added as features are built.

```bash
git clone https://github.com/LM-Ninio001/headerguard.git
cd headerguard
python -m venv .venv
```

## 🧰 Tech stack

- Python 3.10+
- (coming soon) `requests`, `pytest`, FastAPI, HTML/CSS/JS dashboard

## 📚 References

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [MDN: HTTP headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)

## 📄 License

MIT © Luban Mahi Ninio
