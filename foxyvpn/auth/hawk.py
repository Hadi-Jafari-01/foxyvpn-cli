"""Hawk Authentication header generator for Firefox Accounts.

Implements the Hawk HTTP authentication scheme as used by Mozilla Firefox Accounts API.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import time
import urllib.parse


def generate_hawk_header(
    method: str,
    url: str,
    token_id: str,
    hmac_key: bytes,
    body: bytes | str = b"",
    ts: str | None = None,
    nonce: str | None = None,
) -> str:
    """Generate Hawk Authorization header for an HTTP request.

    Args:
        method: HTTP method (GET, POST, etc.)
        url: Full request URL
        token_id: Hawk token ID (hex string)
        hmac_key: Hawk HMAC secret key (bytes)
        body: Request body (bytes or str, default empty)
        ts: Optional timestamp override (seconds as string)
        nonce: Optional nonce override

    Returns:
        Formatted Authorization header string: Hawk id="...", ts="...", ...
    """
    if ts is None:
        ts = str(int(time.time()))
    if nonce is None:
        nonce = base64.urlsafe_b64encode(os.urandom(6)).decode("ascii").rstrip("=")

    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    port = str(parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80))
    path_and_query = parsed.path or "/"
    if parsed.query:
        path_and_query += f"?{parsed.query}"

    if isinstance(body, str):
        body = body.encode("utf-8")

    payload_hash = ""
    if body:
        digest = hashlib.sha256(b"hawk.1.payload\napplication/json\n" + body + b"\n").digest()
        payload_hash = base64.b64encode(digest).decode("ascii")

    normalized = (
        f"hawk.1.header\n"
        f"{ts}\n"
        f"{nonce}\n"
        f"{method.upper()}\n"
        f"{path_and_query}\n"
        f"{host}\n"
        f"{port}\n"
        f"{payload_hash}\n\n"
    )

    mac = base64.b64encode(
        hmac.new(hmac_key, normalized.encode("utf-8"), hashlib.sha256).digest()
    ).decode("ascii")

    header = f'Hawk id="{token_id}", ts="{ts}", nonce="{nonce}", mac="{mac}"'
    if payload_hash:
        header += f', hash="{payload_hash}"'
    return header


def parse_hawk_header(header: str) -> dict[str, str]:
    """Parse key-value pairs from a Hawk Authorization header."""
    if not header.startswith("Hawk "):
        return {}
    content = header[5:]
    pairs = re.findall(r'(\w+)="([^"]*)"', content)
    return dict(pairs)


def verify_hawk_header(
    header: str,
    method: str,
    url: str,
    hmac_key: bytes,
    body: bytes | str = b"",
) -> bool:
    """Verify a Hawk Authorization header against the request and HMAC key."""
    attrs = parse_hawk_header(header)
    token_id = attrs.get("id")
    ts = attrs.get("ts")
    nonce = attrs.get("nonce")
    mac = attrs.get("mac")
    given_hash = attrs.get("hash", "")

    if not all([token_id, ts, nonce, mac]):
        return False

    expected_header = generate_hawk_header(
        method=method,
        url=url,
        token_id=token_id,
        hmac_key=hmac_key,
        body=body,
        ts=ts,
        nonce=nonce,
    )
    expected_attrs = parse_hawk_header(expected_header)

    mac_matches = hmac.compare_digest(mac, expected_attrs.get("mac", ""))
    if given_hash:
        hash_matches = hmac.compare_digest(given_hash, expected_attrs.get("hash", ""))
        return mac_matches and hash_matches
    return mac_matches
