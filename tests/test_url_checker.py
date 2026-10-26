import asyncio

import pytest

import tools.text_url_tool as text_tool
import tools.url_checker as uc
from tools.url_checker import (
    _host_is_safe,
    _validate_url_for_fetch,
    check_url_sync,
    check_urls_in_text,
)


class FakeResponse:
    def __init__(self, status_code, headers=None):
        self.status_code = status_code
        self.headers = headers or {}
        self.closed = False

    def iter_content(self, chunk_size=8192):
        yield b"x" * 1024

    def close(self):
        self.closed = True


def _dns(monkeypatch, *ips):
    def fake_getaddrinfo(host, *args, **kwargs):
        return [(None, None, None, None, (ip, 0)) for ip in ips]

    monkeypatch.setattr(uc.socket, "getaddrinfo", fake_getaddrinfo)


# ── Host validation ────────────────────────────────────────────────────────────

def test_private_ip_is_rejected(monkeypatch):
    _dns(monkeypatch, "192.168.1.10")
    assert _host_is_safe("router.local.example") is False


def test_cloud_metadata_ip_is_rejected(monkeypatch):
    _dns(monkeypatch, "169.254.169.254")
    assert _host_is_safe("metadata attacker target") is False


def test_loopback_is_rejected(monkeypatch):
    _dns(monkeypatch, "127.0.0.1")
    assert _host_is_safe("localhost.example") is False


def test_public_ip_is_allowed(monkeypatch):
    _dns(monkeypatch, "93.184.216.34")
    assert _host_is_safe("example.com") is True


def test_mixed_public_and_private_is_rejected(monkeypatch):
    _dns(monkeypatch, "93.184.216.34", "10.0.0.5")
    assert _host_is_safe("mixed.example") is False


def test_dns_failure_is_rejected(monkeypatch):
    def fail(*args, **kwargs):
        raise uc.socket.gaierror("no such host")

    monkeypatch.setattr(uc.socket, "getaddrinfo", fail)
    assert _host_is_safe("nonexistent.invalid") is False


def test_non_http_scheme_is_blocked(monkeypatch):
    _dns(monkeypatch, "93.184.216.34")
    with pytest.raises(ValueError, match="non-http"):
        _validate_url_for_fetch("gopher://example.com/x")


def test_localhost_hostname_is_blocked_without_dns(monkeypatch):
    with pytest.raises(ValueError, match="blocked host"):
        _validate_url_for_fetch("http://localhost:8000/admin")


# ── Fetch flow ────────────────────────────────────────────────────────────────

def _allow_all_hosts(monkeypatch):
    monkeypatch.setattr(uc, "_host_is_safe", lambda host: True)


def test_direct_fetch_reports_final_domain(monkeypatch):
    _allow_all_hosts(monkeypatch)
    monkeypatch.setattr(uc, "_fetch_once", lambda url: FakeResponse(200))
    report = check_url_sync("https://kapitalbank.uz/login")
    assert report["status"] == "ok"
    assert report["final_domain"] == "kapitalbank.uz"
    assert report["findings"] == []  # exact bank domain is fine


def test_shortener_unrolls_to_typosquat(monkeypatch):
    _allow_all_hosts(monkeypatch)
    hops = {
        "https://bit.ly/3xyz": FakeResponse(301, {"Location": "https://kap1talbank.uz/verify"}),
        "https://kap1talbank.uz/verify": FakeResponse(200),
    }
    monkeypatch.setattr(uc, "_fetch_once", lambda url: hops[url])
    report = check_url_sync("https://bit.ly/3xyz")
    assert report["status"] == "ok"
    assert report["final_domain"] == "kap1talbank.uz"
    assert any("Typo-squatting" in f for f in report["findings"])
    assert any("Shortened link" in f for f in report["findings"])


def test_redirect_to_metadata_is_blocked(monkeypatch):
    _allow_all_hosts(monkeypatch)
    safe_hosts = {"bit.ly", "93.184.216.34"}

    def selective_host_check(host):
        return host in safe_hosts

    monkeypatch.setattr(uc, "_host_is_safe", selective_host_check)
    monkeypatch.setattr(
        uc, "_fetch_once", lambda url: FakeResponse(302, {"Location": "http://169.254.169.254/latest/meta-data"})
    )
    report = check_url_sync("http://bit.ly/x")
    assert report["status"] == "blocked_redirect"
    assert any("internal" in f for f in report["findings"])


def test_redirect_loop_is_capped(monkeypatch):
    _allow_all_hosts(monkeypatch)
    monkeypatch.setattr(
        uc, "_fetch_once", lambda url: FakeResponse(302, {"Location": url})
    )
    report = check_url_sync("https://example.com/loop")
    assert report["status"] == "too_many_redirects"


def test_timeout_is_reported_neutrally(monkeypatch):
    _allow_all_hosts(monkeypatch)

    def timeout(url):
        raise uc.requests.exceptions.Timeout()

    monkeypatch.setattr(uc, "_fetch_once", timeout)
    report = check_url_sync("https://example.com/slow")
    assert report["status"] == "timeout"
    assert report["findings"] == []


# ── Integration with the text tool ────────────────────────────────────────────

def test_disabled_flag_returns_no_reports(monkeypatch):
    monkeypatch.setenv("URL_CHECK_ENABLED", "false")
    assert asyncio.run(check_urls_in_text("check https://example.com")) == []


def test_text_tool_merges_url_checker_findings(monkeypatch):
    monkeypatch.setenv("URL_CHECK_ENABLED", "true")

    async def fake_reports(_text):
        return [
            {
                "url": "https://bit.ly/x",
                "status": "ok",
                "final_domain": "kap1talbank.uz",
                "findings": ["Shortened link expands to 'kap1talbank.uz' — the visible domain hides the real one."],
            }
        ]

    monkeypatch.setattr("tools.url_checker.check_urls_in_text", fake_reports)

    def llm_stub(prompt, provider=None):
        return '{"risk_level": "low", "text_findings": [], "summary": "Looks fine."}'

    monkeypatch.setattr(text_tool, "call_text_llm", llm_stub)

    result = asyncio.run(text_tool.text_url_fraud_tool("check https://bit.ly/x"))
    assert result["risk_level"] == "high"  # elevated despite the compliant LLM
    assert any("Shortened link" in f for f in result["text_findings"])


def test_text_tool_survives_llm_failure_with_url_findings(monkeypatch):
    monkeypatch.setenv("URL_CHECK_ENABLED", "true")

    async def fake_reports(_text):
        return [{"url": "https://bit.ly/x", "status": "ok", "findings": ["Shortened link expands to 'evil.example'."]}]

    monkeypatch.setattr("tools.url_checker.check_urls_in_text", fake_reports)

    def llm_boom(prompt, provider=None):
        raise RuntimeError("provider down")

    monkeypatch.setattr(text_tool, "call_text_llm", llm_boom)

    result = asyncio.run(text_tool.text_url_fraud_tool("check https://bit.ly/x"))
    assert result["risk_level"] == "high"
    assert any("Shortened link" in f for f in result["text_findings"])


# ── Domain-age reputation (RDAP) ──────────────────────────────────────────────

class _FakeRdap:
    def __init__(self, event_date):
        self.status_code = 200
        self._event_date = event_date

    def json(self):
        return {"events": [{"eventAction": "registration", "eventDate": self._event_date}]}


def test_rdap_age_is_computed(monkeypatch):
    monkeypatch.setattr(uc, "REPUTATION_ENABLED", True)
    monkeypatch.setattr(uc.requests, "get", lambda *a, **k: _FakeRdap("2026-10-20T00:00:00Z"))
    age = uc.domain_age_days("fresh-bank.example")
    assert age is not None and age < 10


def test_rdap_old_domain_is_not_suspicious(monkeypatch):
    monkeypatch.setattr(uc, "REPUTATION_ENABLED", True)
    monkeypatch.setattr(uc.requests, "get", lambda *a, **k: _FakeRdap("2010-01-01T00:00:00Z"))
    age = uc.domain_age_days("old-bank.example")
    assert age is not None and age > 30


def test_rdap_failure_is_silent(monkeypatch):
    monkeypatch.setattr(uc, "REPUTATION_ENABLED", True)

    def boom(*a, **k):
        raise uc.requests.exceptions.ConnectionError("rdap down")

    monkeypatch.setattr(uc.requests, "get", boom)
    assert uc.domain_age_days("unreachable.example") is None


def test_fresh_domain_produces_finding(monkeypatch):
    _allow_all_hosts(monkeypatch)
    monkeypatch.setattr(uc, "_fetch_once", lambda url: FakeResponse(200))
    monkeypatch.setattr(uc, "domain_age_days", lambda domain: 3)
    report = check_url_sync("https://new-bank.example/login")
    assert any("registered only 3 days ago" in f for f in report["findings"])
    assert report["domain_age_days"] == 3


def test_tls_error_is_a_finding(monkeypatch):
    _allow_all_hosts(monkeypatch)

    def ssl_fail(url):
        raise uc.requests.exceptions.SSLError("self-signed certificate in chain")

    monkeypatch.setattr(uc, "_fetch_once", ssl_fail)
    report = check_url_sync("https://broken-tls.example")
    assert report["status"] == "tls_error"
    assert any("TLS certificate" in f for f in report["findings"])
