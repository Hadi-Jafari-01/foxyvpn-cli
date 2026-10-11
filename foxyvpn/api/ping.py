"""TCP handshake latency prober for VPN proxy servers."""

from __future__ import annotations

import asyncio
import time

from foxyvpn.api.models import ProxyCandidate


async def ping_server(
    host: str,
    port: int = 443,
    timeout: float = 3.0,
) -> float | None:
    """
    Measure TCP handshake latency to host:port in milliseconds.
    Returns float latency in milliseconds, or None if connection fails or times out.
    """
    try:
        start = time.perf_counter()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return round(elapsed_ms, 2)
    except Exception:
        return None


async def ping_candidates(
    candidates: list[ProxyCandidate],
    timeout: float = 3.0,
) -> list[ProxyCandidate]:
    """
    Concurrently ping all candidates and sort them by ping_ms (lowest latency first).
    Candidates where ping fails (ping_ms is None) are placed at the end.
    """
    if not candidates:
        return []

    async def _probe(candidate: ProxyCandidate) -> ProxyCandidate:
        ping = await ping_server(candidate.host, candidate.port, timeout=timeout)
        candidate.ping_ms = ping
        return candidate

    results = await asyncio.gather(*[_probe(c) for c in candidates])

    def _sort_key(c: ProxyCandidate) -> tuple[int, float]:
        if c.ping_ms is None:
            return (1, float("inf"))
        return (0, c.ping_ms)

    return sorted(results, key=_sort_key)
