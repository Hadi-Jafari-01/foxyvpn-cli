"""Secure DNS Resolver using DNS-over-HTTPS (DoH).

Bypasses DNS poisoning and ISP censorship by intercepting socket.getaddrinfo
for Mozilla and Fastly services and querying trusted DoH endpoints (Cloudflare, Google, Quad9).
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)

DOH_BOOTSTRAP_IPS = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1"]

INTERCEPTED_SUFFIXES = (
    ".mozilla.org",
    ".mozilla.com",
    ".firefox.com",
    ".fastly-masque.net",
    ".fastly.net",
    ".cloudflare.com",
)

_orig_getaddrinfo = socket.getaddrinfo
_cache: dict[str, tuple[str, float]] = {}  # host -> (ip, expire_time)
_cache_lock = threading.Lock()
_installed = False


def doh_resolve_sync(hostname: str, timeout: float = 2.5) -> str | None:
    """Resolve a hostname to IPv4 using bootstrap DoH servers synchronously."""
    now = time.time()
    with _cache_lock:
        if hostname in _cache:
            ip, exp = _cache[hostname]
            if exp > now:
                return ip

    for ip_endpoint in DOH_BOOTSTRAP_IPS:
        try:
            url = f"https://{ip_endpoint}/dns-query?name={hostname}&type=A"
            resp = httpx.get(
                url,
                headers={"accept": "application/dns-json"},
                timeout=timeout,
                trust_env=False,
            )
            if resp.status_code == 200:
                data = resp.json()
                for ans in data.get("Answer", []):
                    if ans.get("type") == 1 and ans.get("data"):
                        resolved_ip = ans["data"]
                        ttl = max(60, min(ans.get("TTL", 300), 3600))
                        with _cache_lock:
                            _cache[hostname] = (resolved_ip, now + ttl)
                        return resolved_ip
        except Exception:
            continue
    return None


def secure_getaddrinfo(host: Any, port: Any, *args: Any, **kwargs: Any) -> Any:
    """Secure replacement for socket.getaddrinfo preventing DNS poisoning."""
    h = host.decode("ascii") if isinstance(host, bytes) else (str(host) if host else "")

    # 1. Check if domain matches intercepted suffixes
    should_intercept = any(
        h.endswith(suffix) or h == suffix.lstrip(".") for suffix in INTERCEPTED_SUFFIXES
    )
    if should_intercept:
        clean_ip = doh_resolve_sync(h)
        if clean_ip:
            return _orig_getaddrinfo(clean_ip, port, *args, **kwargs)

    # 2. Try default resolver
    results = None
    try:
        results = _orig_getaddrinfo(host, port, *args, **kwargs)
    except Exception:
        results = None

    # 3. Detect DNS poisoning (100.64.0.0/10 CGNAT or localhost returned for public domains)
    if results:
        first_ip = results[0][4][0]
        if first_ip.startswith("100.64.") or (
            first_ip.startswith("127.") and "." in h and not h.endswith(".localhost")
        ):
            clean_ip = doh_resolve_sync(h)
            if clean_ip:
                return _orig_getaddrinfo(clean_ip, port, *args, **kwargs)
        return results

    # 4. If default failed completely, try DoH fallback for domain names
    if "." in h:
        clean_ip = doh_resolve_sync(h)
        if clean_ip:
            return _orig_getaddrinfo(clean_ip, port, *args, **kwargs)

    if results is not None:
        return results
    raise socket.gaierror(socket.EAI_NONAME, f"Name or service not known: {host}")


def enable_secure_dns() -> None:
    """Enable secure DoH resolver globally in this process."""
    global _installed
    if not _installed:
        socket.getaddrinfo = secure_getaddrinfo
        _installed = True
        logger.info("Secure DoH DNS interception enabled.")


def disable_secure_dns() -> None:
    """Restore original system DNS resolver."""
    global _installed
    if _installed:
        socket.getaddrinfo = _orig_getaddrinfo
        _installed = False
        logger.info("Secure DoH DNS interception disabled.")
