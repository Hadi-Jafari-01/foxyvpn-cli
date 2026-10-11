"""Exit node verification module.

Checks tunnel egress IP and geolocation using Cloudflare's /cdn-cgi/trace
endpoint routed over the local SOCKS5 proxy.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

DEFAULT_TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
DEFAULT_TIMEOUT = 15.0


def parse_trace(text: str) -> dict[str, str]:
    """Parse key=value lines from Cloudflare trace endpoint into a dict."""
    details: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        key, val = line.split("=", 1)
        details[key.strip()] = val.strip()
    return details


class ExitChecker:
    """Verifies that egress traffic is exiting through the expected VPN tunnel location."""

    def __init__(
        self,
        trace_url: str = DEFAULT_TRACE_URL,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.trace_url = trace_url
        self.timeout = timeout

    @staticmethod
    def parse_trace(text: str) -> dict[str, str]:
        """Parse key=value trace output."""
        return parse_trace(text)

    async def check_exit(
        self,
        socks_host: str = "127.0.0.1",
        socks_port: int = 10808,
        expected_country: str | None = None,
    ) -> dict[str, Any]:
        """Connect to Cloudflare trace endpoint via SOCKS5 proxy and verify exit node.

        Args:
            socks_host: Local SOCKS5 proxy IP/host.
            socks_port: Local SOCKS5 proxy port.
            expected_country: Two-letter ISO country code (e.g. "US", "DE") or "REC".
                              If provided and != "REC", verifies that loc == expected_country.

        Returns:
            Dict containing:
                "ip": Egress IP address string,
                "country": Two-letter ISO location code (loc),
                "verified": Boolean indicating verification status,
                "details": Full dictionary of parsed trace fields.
        """
        proxy_url = f"socks5://{socks_host}:{socks_port}"
        logger.debug("Running exit check via %s to %s", proxy_url, self.trace_url)

        async with httpx.AsyncClient(proxy=proxy_url, timeout=self.timeout, trust_env=False) as client:
            resp = await client.get(self.trace_url)
            resp.raise_for_status()
            text = resp.text

        details = parse_trace(text)
        ip = details.get("ip", "")
        loc = details.get("loc", "")

        if expected_country is not None and expected_country.strip().upper() != "REC":
            verified = bool(loc and loc.strip().upper() == expected_country.strip().upper())
        else:
            verified = bool(loc)

        return {
            "ip": ip,
            "country": loc,
            "verified": verified,
            "details": details,
        }


async def check_exit(
    socks_host: str = "127.0.0.1",
    socks_port: int = 10808,
    expected_country: str | None = None,
    trace_url: str = DEFAULT_TRACE_URL,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Module-level convenience wrapper for ExitChecker.check_exit."""
    checker = ExitChecker(trace_url=trace_url, timeout=timeout)
    return await checker.check_exit(
        socks_host=socks_host,
        socks_port=socks_port,
        expected_country=expected_country,
    )
