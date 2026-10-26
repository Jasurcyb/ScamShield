"""tools/url_checker.py — Safe server-side URL inspection with SSRF guards.

Follows shortened/redirecting links by hand and reports the FINAL domain,
so typosquatting hidden behind bit.ly-style shorteners is still detected.

Security rules (enforced before every request, including each redirect hop):
- only http/https schemes;
- the hostname is resolved via DNS and EVERY resolved IP must be public
  (loopback, private, link-local — including 169.254.169.254 cloud metadata —
  reserved and multicast addresses are rejected);
- redirects are followed manually with the same validation per hop;
- responses are streamed and capped.

Known limitation (documented in README): resolve-then-connect leaves a short
TOCTOU window for DNS-rebinding; acceptable for this MVP threat model.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

import requests

from tools.text_url_tool import _check_url_heuristics, _extract_urls

DEFAULT_TIMEOUT = float(os.getenv("URL_CHECK_TIMEOUT_SECONDS", "10"))
MAX_REDIRECTS = int(os.getenv("URL_CHECK_MAX_REDIRECTS", "5"))
MAX_BYTES = int(os.getenv("URL_CHECK_MAX_BYTES", str(64 * 1024)))
USER_AGENT = "ScamShieldBot/2.0 (+link-verification)"

# Domain-age reputation via RDAP (free, keyless). Domains younger than this
# that imitate banks are treated as a phishing indicator.
REPUTATION_ENABLED = os.getenv("URL_REPUTATION_ENABLED", "true").lower() in {"1", "true", "yes"}
SUSPICIOUS_DOMAIN_AGE_DAYS = int(os.getenv("SUSPICIOUS_DOMAIN_AGE_DAYS", "30"))
RDAP_TIMEOUT = float(os.getenv("RDAP_TIMEOUT_SECONDS", "5"))

_RDAP_CACHE: dict[str, tuple[float, float]] = {}   # domain -> (age_days, fetched_at)
_RDAP_CACHE_TTL = 6 * 3600.0
_RDAP_LOCK = threading.Lock()

SHORTENER_HOSTS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "shorturl.at", "rb.gy", "rebrand.ly", "tiny.cc", "t.me",
}


def url_check_enabled() -> bool:
    return os.getenv("URL_CHECK_ENABLED", "true").lower() in {"1", "true", "yes"}


def domain_age_days(domain: str) -> float | None:
    """Registration age in days from RDAP (keyless). None when unknown/off.

    RDAP responses are cached in-process for 6 hours to respect rate limits.
    Failures are silent: reputation is a bonus signal, never a hard gate.
    """
    if not REPUTATION_ENABLED:
        return None
    now = time.monotonic()
    with _RDAP_LOCK:
        cached = _RDAP_CACHE.get(domain)
        if cached and now - cached[1] < _RDAP_CACHE_TTL:
            return cached[0]
    try:
        response = requests.get(
            f"https://rdap.org/domain/{domain}",
            timeout=RDAP_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
        )
        if response.status_code != 200:
            return None
        events = response.json().get("events", [])
        registered = None
        for event in events:
            if event.get("eventAction") == "registration":
                registered = event.get("eventDate")
                break
        if not registered:
            return None
        parsed = datetime.fromisoformat(registered.replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - parsed).total_seconds() / 86400.0
    except Exception:
        return None
    with _RDAP_LOCK:
        _RDAP_CACHE[domain] = (age, now)
    return age


def _host_is_safe(host: str) -> bool:
    """Resolve `host` and require every address to be a public unicast IP."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return False

    addresses = {info[4][0] for info in infos}
    if not addresses:
        return False

    for address in addresses:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return False
    return True


def _validate_url_for_fetch(url: str) -> str:
    """Raise ValueError when `url` must not be fetched server-side."""
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        raise ValueError(f"non-http scheme: {parts.scheme or '(none)'}")
    host = parts.hostname
    if not host:
        raise ValueError("no hostname")
    if host == "localhost" or not _host_is_safe(host):
        raise ValueError(f"blocked host: {host}")
    return url


def _fetch_once(url: str) -> requests.Response:
    """Single GET without redirects, streaming, bounded by timeout."""
    return requests.get(
        url,
        allow_redirects=False,
        stream=True,
        timeout=DEFAULT_TIMEOUT,
        headers={"User-Agent": USER_AGENT},
    )


def check_url_sync(url: str) -> dict:
    """Fetch `url` safely, following redirects manually. Returns a report.

    The report always includes `url` and `status`; `final_domain` is present
    when the chain resolved successfully. Findings are English strings merged
    into the text agent's findings list.
    """
    report: dict = {"url": url, "status": "error", "findings": []}
    try:
        current = _validate_url_for_fetch(url)
    except ValueError as exc:
        report["status"] = "blocked"
        report["findings"].append(f"Link target was blocked by the server-side safety check ({exc}).")
        return report

    visited = 0
    try:
        while True:
            try:
                response = _fetch_once(current)
            except requests.exceptions.SSLError:
                report["status"] = "tls_error"
                report["findings"].append(
                    "The site's TLS certificate could not be validated (self-signed, expired "
                    "or mismatched) — legitimate banks never serve broken certificates."
                )
                return report

            if response.status_code in {301, 302, 303, 307, 308}:
                visited += 1
                if visited > MAX_REDIRECTS:
                    report["status"] = "too_many_redirects"
                    report["findings"].append(
                        f"Link redirects more than {MAX_REDIRECTS} times — a common trick to hide the real destination."
                    )
                    return report
                location = response.headers.get("Location", "")
                current = urljoin(current, location)
                try:
                    _validate_url_for_fetch(current)
                except ValueError:
                    report["status"] = "blocked_redirect"
                    report["findings"].append(
                        "Link redirects to an internal or otherwise blocked address — strongly suspicious."
                    )
                    return report
                response.close()
                continue

            # Final destination reached: read a bounded prefix, then drop it.
            consumed = 0
            for chunk in response.iter_content(chunk_size=8192):
                consumed += len(chunk)
                if consumed >= MAX_BYTES:
                    break
            response.close()

            final_domain = urlsplit(current).hostname or ""
            report["status"] = "ok"
            report["final_url"] = current
            report["final_domain"] = final_domain
            report["http_status"] = response.status_code

            original_domain = urlsplit(url).hostname or ""
            if original_domain != final_domain:
                if original_domain.lower() in SHORTENER_HOSTS:
                    report["findings"].append(
                        f"Shortened link expands to '{final_domain}' — the visible domain hides the real one."
                    )
                else:
                    report["findings"].append(
                        f"Link redirects from '{original_domain}' to '{final_domain}'."
                    )
            # Typosquat / punycode checks run on the FINAL domain, so attacks
            # hidden behind shorteners and redirects are still caught.
            report["findings"].extend(_check_url_heuristics(final_domain))

            # Domain-age reputation on the FINAL domain: a days-old domain
            # impersonating a service is a strong phishing indicator even when
            # the name itself has no typo.
            age = domain_age_days(final_domain)
            if age is not None and age < SUSPICIOUS_DOMAIN_AGE_DAYS:
                report["findings"].append(
                    f"Domain '{final_domain}' was registered only {int(age)} days ago "
                    f"(< {SUSPICIOUS_DOMAIN_AGE_DAYS}) — freshly registered domains are a "
                    "common phishing trait."
                )
                report["domain_age_days"] = int(age)
            return report

    except requests.exceptions.Timeout:
        report["status"] = "timeout"
        return report
    except requests.exceptions.RequestException:
        report["status"] = "unreachable"
        return report


async def check_urls_in_text(text: str) -> list[dict]:
    """Safely inspect every URL mentioned in `text` (bounded concurrency)."""
    if not url_check_enabled():
        return []
    urls = _extract_urls(text)[:5]  # cap: one message rarely needs more
    if not urls:
        return []
    reports = await asyncio.gather(
        *(asyncio.to_thread(check_url_sync, url) for url in urls),
        return_exceptions=True,
    )
    return [r for r in reports if isinstance(r, dict)]
