"""HTTP API for HeaderGuard (the dashboard talks to this).

Run with:  headerguard-web            (http://127.0.0.1:8000)
     or:   uvicorn headerguard.web:app --reload
"""

from __future__ import annotations

import os
import threading
import time
from collections import defaultdict, deque

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from headerguard import __version__
from headerguard.fetcher import FetchError
from headerguard.safety import BlockedTarget, check_target
from headerguard.scanner import scan

SCAN_TIMEOUT = 8  # seconds per network step
RATE_LIMIT = int(os.environ.get("HEADERGUARD_RATE_LIMIT", "10"))  # scans per client per minute
RATE_WINDOW = 60

app = FastAPI(
    title="HeaderGuard",
    version=__version__,
    description="Passively grade a website's security headers, TLS and cookies.",
)


class ScanRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, examples=["example.com"])


class _RateLimiter:
    """Sliding-window limiter kept in memory (fine for a single-process demo)."""

    def __init__(self, limit: int, window: float):
        self.limit, self.window = limit, window
        self.hits: dict[str, deque[float]] = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self.lock:
            hits = self.hits[key]
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True


limiter = _RateLimiter(RATE_LIMIT, RATE_WINDOW)


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "version": __version__}


@app.post("/api/scan")
def scan_url(body: ScanRequest, request: Request) -> dict:
    client = request.client.host if request.client else "unknown"
    if not limiter.allow(client):
        raise HTTPException(429, f"Rate limit reached: {RATE_LIMIT} scans per minute. Try again shortly.")
    try:
        report = scan(body.url, timeout=SCAN_TIMEOUT, guard=check_target)
    except BlockedTarget as err:
        raise HTTPException(400, f"Target not allowed: {err}") from err
    except ValueError as err:
        raise HTTPException(400, str(err)) from err
    except FetchError as err:
        raise HTTPException(502, str(err)) from err
    return report.to_dict()


def run() -> None:
    """Console entry point: `headerguard-web [--host H] [--port P]`."""
    import argparse

    import uvicorn

    parser = argparse.ArgumentParser(prog="headerguard-web")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    uvicorn.run(app, host=args.host, port=args.port)
