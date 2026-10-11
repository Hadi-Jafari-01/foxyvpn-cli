"""DNS-over-HTTPS (DoH) Client implementation.

Supports Cloudflare, Google, and Quad9 DoH resolvers using both
application/dns-json and RFC 8484 DNS wire format (application/dns-message).
"""

from __future__ import annotations

import base64
import logging
import random
import socket
import struct
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# Standard DoH Endpoints
ENDPOINTS: dict[str, str] = {
    "cloudflare": "https://1.1.1.1/dns-query",
    "google": "https://8.8.8.8/dns-query",
    "quad9": "https://9.9.9.9/dns-query",
}

CLOUDFLARE_DOH = ENDPOINTS["cloudflare"]
GOOGLE_DOH = ENDPOINTS["google"]
QUAD9_DOH = ENDPOINTS["quad9"]

DNS_JSON_MEDIA_TYPE = "application/dns-json"
DNS_MESSAGE_MEDIA_TYPE = "application/dns-message"

# DNS Record Types
TYPE_A = 1
TYPE_AAAA = 28
RECORD_TYPES: dict[str, int] = {
    "A": TYPE_A,
    "AAAA": TYPE_AAAA,
}


def build_wire_query(hostname: str, record_type: str | int = "A", query_id: int | None = None) -> bytes:
    """Build an RFC 1035 / RFC 8484 DNS query packet in binary wire format."""
    if query_id is None:
        query_id = random.randint(1, 65535)

    qtype = RECORD_TYPES.get(record_type.upper(), TYPE_A) if isinstance(record_type, str) else record_type

    # Header: ID, Flags (RD=1), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)

    # QNAME: label format (length byte followed by label ASCII)
    parts = hostname.strip(".").split(".")
    qname_parts = []
    for part in parts:
        encoded = part.encode("idna")
        qname_parts.append(bytes([len(encoded)]) + encoded)
    qname = b"".join(qname_parts) + b"\x00"

    # QTYPE and QCLASS (1 = IN)
    question = qname + struct.pack("!HH", qtype, 1)
    return header + question


def parse_wire_response(data: bytes, record_type: str | int = "A") -> list[str]:
    """Parse an RFC 1035 DNS response packet and extract resolved IP addresses."""
    if len(data) < 12:
        return []

    target_qtype = (
        RECORD_TYPES.get(record_type.upper(), TYPE_A) if isinstance(record_type, str) else record_type
    )

    qdcount, ancount = struct.unpack("!HH", data[4:8])
    offset = 12

    # Skip question section
    for _ in range(qdcount):
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if (length & 0xC0) == 0xC0:
                offset += 2
                break
            offset += 1 + length
        offset += 4  # skip qtype (2) + qclass (2)

    results: list[str] = []

    # Parse answer section
    for _ in range(ancount):
        if offset >= len(data):
            break

        # Skip name field (handles pointers and labels)
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if (length & 0xC0) == 0xC0:
                offset += 2
                break
            offset += 1 + length

        if offset + 10 > len(data):
            break

        rtype, _rclass, _ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10

        if offset + rdlength > len(data):
            break

        rdata = data[offset : offset + rdlength]
        offset += rdlength

        if rtype == TYPE_A and rdlength == 4:
            if target_qtype == TYPE_A:
                results.append(socket.inet_ntoa(rdata))
        elif rtype == TYPE_AAAA and rdlength == 16:
            if target_qtype == TYPE_AAAA:
                results.append(socket.inet_ntop(socket.AF_INET6, rdata))

    return results


def parse_json_response(data: dict[str, Any], record_type: str | int = "A") -> list[str]:
    """Extract resolved IP addresses from an RFC 8427 / Google DNS JSON response."""
    target_qtype = (
        RECORD_TYPES.get(record_type.upper(), TYPE_A) if isinstance(record_type, str) else record_type
    )

    answers = data.get("Answer", [])
    results: list[str] = []

    for item in answers:
        item_type = item.get("type")
        if item_type == target_qtype:
            val = item.get("data")
            if val:
                results.append(str(val).strip())

    return results


class DohClient:
    """DNS-over-HTTPS client supporting Cloudflare, Google, and Quad9."""

    def __init__(
        self,
        client: httpx.AsyncClient | None = None,
        timeout: float = 6.0,
    ) -> None:
        self._custom_client = client
        self.timeout = timeout
        self._owned_client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._custom_client is not None:
            return self._custom_client
        if self._owned_client is None or self._owned_client.is_closed:
            self._owned_client = httpx.AsyncClient(http2=True, timeout=self.timeout, trust_env=False)
        return self._owned_client

    async def close(self) -> None:
        """Close the underlying HTTP client if created internally."""
        if self._owned_client is not None and not self._owned_client.is_closed:
            await self._owned_client.aclose()
            self._owned_client = None

    async def __aenter__(self) -> DohClient:
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()

    async def resolve(
        self,
        hostname: str,
        record_type: str = "A",
        provider: str = "automatic",
    ) -> list[str]:
        """Resolve hostname to a list of IP addresses using DoH.

        Args:
            hostname: Target domain name (e.g. "example.com").
            record_type: DNS record type ("A" for IPv4, "AAAA" for IPv6).
            provider: Provider name ("cloudflare", "google", "quad9", or "automatic"),
                      or a custom DoH endpoint URL.

        Returns:
            List of resolved IP address strings.
        """
        provider_key = provider.strip().lower()

        if provider_key == "automatic":
            # Cloudflare -> Google -> Quad9 fallback chain
            for cand in ["cloudflare", "google", "quad9"]:
                try:
                    ips = await self._query_provider(cand, ENDPOINTS[cand], hostname, record_type)
                    if ips:
                        return ips
                except Exception as exc:
                    logger.debug("DoH query via %s failed: %s", cand, exc)
                    continue
            return []

        endpoint_url = ENDPOINTS.get(provider_key, provider)
        return await self._query_provider(provider_key, endpoint_url, hostname, record_type)

    async def _query_provider(
        self,
        provider_name: str,
        endpoint_url: str,
        hostname: str,
        record_type: str,
    ) -> list[str]:
        client = await self._get_client()

        # Try JSON first for Cloudflare or when explicitly requested
        if provider_name == "cloudflare" or "json" in endpoint_url:
            try:
                resp = await client.get(
                    endpoint_url,
                    params={"name": hostname, "type": record_type},
                    headers={"accept": DNS_JSON_MEDIA_TYPE},
                )
                if resp.status_code == 200:
                    ct = resp.headers.get("content-type", "")
                    if "json" in ct or resp.text.startswith("{"):
                        data = resp.json()
                        ips = parse_json_response(data, record_type)
                        if ips:
                            return ips
            except Exception as exc:
                logger.debug("DoH JSON query to %s failed: %s", endpoint_url, exc)

        # Wire format query (RFC 8484 POST)
        wire_data = build_wire_query(hostname, record_type)
        try:
            resp = await client.post(
                endpoint_url,
                content=wire_data,
                headers={
                    "content-type": DNS_MESSAGE_MEDIA_TYPE,
                    "accept": DNS_MESSAGE_MEDIA_TYPE,
                },
            )
            if resp.status_code == 200:
                return parse_wire_response(resp.content, record_type)
        except Exception as exc:
            logger.debug("DoH wire query to %s failed: %s", endpoint_url, exc)

        # Wire format fallback: GET with base64url parameter
        try:
            b64_wire = base64.urlsafe_b64encode(wire_data).rstrip(b"=").decode("ascii")
            resp = await client.get(
                f"{endpoint_url}?dns={b64_wire}",
                headers={"accept": DNS_MESSAGE_MEDIA_TYPE},
            )
            if resp.status_code == 200:
                return parse_wire_response(resp.content, record_type)
        except Exception as exc:
            logger.debug("DoH wire GET query to %s failed: %s", endpoint_url, exc)

        return []
