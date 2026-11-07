import socket

import pytest

from headerguard import fetcher, safety
from headerguard.safety import BlockedTarget, check_target, is_public_ip


@pytest.fixture
def dns(monkeypatch):
    """Fake DNS: map hostnames to IP lists without touching the network."""
    table = {}

    def fake_getaddrinfo(host, port, type=0):
        if host not in table:
            raise socket.gaierror("not found")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in table[host]]

    monkeypatch.setattr(safety.socket, "getaddrinfo", fake_getaddrinfo)
    return table


@pytest.mark.parametrize(
    "ip",
    ["127.0.0.1", "10.0.0.5", "172.16.3.4", "192.168.1.1", "169.254.169.254", "0.0.0.0",
     "100.64.0.1", "::1", "fc00::1", "fe80::1", "::ffff:127.0.0.1", "224.0.0.1"],
)
def test_private_and_reserved_ips_are_not_public(ip):
    assert not is_public_ip(ip)


@pytest.mark.parametrize("ip", ["93.184.215.14", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_ips(ip):
    assert is_public_ip(ip)


def test_public_host_allowed(dns):
    dns["example.com"] = ["93.184.215.14"]
    check_target("https://example.com/path")  # no exception


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/",
        "http://metadata.internal/latest/meta-data/",
        "https://sneaky.example/",  # one public and one private record
    ],
)
def test_hosts_resolving_to_private_ips_blocked(dns, url):
    dns.update({"localhost": ["127.0.0.1"], "metadata.internal": ["169.254.169.254"],
                "sneaky.example": ["93.184.215.14", "10.0.0.1"]})
    with pytest.raises(BlockedTarget, match="private or reserved"):
        check_target(url)


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("ftp://example.com", "Only http"),
        ("https://user:pass@example.com", "credentials"),
        ("https://example.com:8080", "Port 8080"),
        ("https://example.com:22", "Port 22"),
        ("https://unknown.invalid", "Could not resolve"),
    ],
)
def test_other_blocked_urls(dns, url, reason):
    dns["example.com"] = ["93.184.215.14"]
    with pytest.raises(BlockedTarget, match=reason):
        check_target(url)


def test_guard_runs_on_redirect_targets():
    seen = []

    def guard(url):
        seen.append(url)
        if "127.0.0.1" in url:
            raise BlockedTarget("blocked")

    handler = fetcher._GuardedRedirects(guard)
    with pytest.raises(BlockedTarget):
        handler.redirect_request(None, None, 302, "Found", {}, "http://127.0.0.1/admin")
    assert seen == ["http://127.0.0.1/admin"]


def test_fetch_calls_guard_before_connecting():
    def guard(url):
        raise BlockedTarget(f"refused {url}")

    with pytest.raises(BlockedTarget, match="refused https://internal"):
        fetcher.fetch("internal", guard=guard)
