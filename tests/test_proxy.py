"""Unit tests for Local SOCKS5 Proxy Server, DoH Resolver, and Exit Verifier."""

from __future__ import annotations

import asyncio
import socket
import struct
from typing import Any

import httpx
import pytest

from foxyvpn.proxy.doh import (
    CLOUDFLARE_DOH,
    GOOGLE_DOH,
    QUAD9_DOH,
    DohClient,
    build_wire_query,
    parse_json_response,
    parse_wire_response,
)
from foxyvpn.proxy.exit_check import ExitChecker, check_exit, parse_trace
from foxyvpn.proxy.socks5 import (
    ATYP_DOMAIN,
    ATYP_IPV4,
    ATYP_IPV6,
    CMD_BIND,
    CMD_CONNECT,
    CMD_UDP_ASSOCIATE,
    REP_ATYP_NOT_SUPPORTED,
    REP_CMD_NOT_SUPPORTED,
    REP_CONNECTION_REFUSED,
    REP_HOST_UNREACHABLE,
    REP_SUCCESS,
    LocalSocks5Server,
    SimpleTunneledStream,
    make_socks5_reply,
)

# ---------------------------------------------------------------------------
# Helpers & Mocks for SOCKS5 testing
# ---------------------------------------------------------------------------


class MockDuplexStream:
    """In-memory duplex stream implementing reader and writer interfaces."""

    def __init__(self) -> None:
        self.in_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self.out_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self.closed = False

    async def read(self, n: int = -1) -> bytes:
        if self.closed and self.in_queue.empty():
            return b""
        return await self.in_queue.get()

    def write(self, data: bytes) -> None:
        if not self.closed:
            self.out_queue.put_nowait(data)

    async def drain(self) -> None:
        pass

    async def close(self) -> None:
        self.closed = True
        self.in_queue.put_nowait(b"")


class MockUpstreamSession:
    """Mock UpstreamSession that routes to in-memory duplex streams or records calls."""

    def __init__(self, failure_exc: Exception | None = None) -> None:
        self.failure_exc = failure_exc
        self.opened_targets: list[tuple[str, int]] = []
        self.stream: MockDuplexStream | None = None
        self.is_connected = True

    async def open_stream(self, target_host: str, target_port: int) -> SimpleTunneledStream:
        self.opened_targets.append((target_host, target_port))
        if self.failure_exc is not None:
            raise self.failure_exc

        stream = MockDuplexStream()
        self.stream = stream
        return SimpleTunneledStream(reader=stream, writer=stream, close_func=stream.close)


async def perform_greeting(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, methods: list[int]) -> bytes:
    """Send SOCKS5 greeting and return server response."""
    writer.write(bytes([0x05, len(methods)] + methods))
    await writer.drain()
    return await reader.readexactly(2)


# ---------------------------------------------------------------------------
# SOCKS5 Handshake & Server Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_socks5_greeting_success() -> None:
    session = MockUpstreamSession()
    server = LocalSocks5Server(bind_address="127.0.0.1", port=0, session_provider=lambda: session)

    async with server:
        reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
        resp = await perform_greeting(reader, writer, [0x00])  # NO AUTH
        assert resp == b"\x05\x00"
        writer.close()
        await writer.wait_closed()


@pytest.mark.asyncio
async def test_socks5_greeting_unsupported_version() -> None:
    server = LocalSocks5Server(bind_address="127.0.0.1", port=0)

    async with server:
        reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
        writer.write(b"\x04\x01\x00")  # SOCKS4
        await writer.drain()
        resp = await reader.read(2)
        assert resp == b"\x05\xff"  # Rejected
        writer.close()
        await writer.wait_closed()


@pytest.mark.asyncio
async def test_socks5_greeting_no_acceptable_auth() -> None:
    server = LocalSocks5Server(bind_address="127.0.0.1", port=0)

    async with server:
        reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
        resp = await perform_greeting(reader, writer, [0x02])  # Username/Password only
        assert resp == b"\x05\xff"
        writer.close()
        await writer.wait_closed()


@pytest.mark.asyncio
async def test_socks5_unsupported_command() -> None:
    session = MockUpstreamSession()
    server = LocalSocks5Server(bind_address="127.0.0.1", port=0, session_provider=lambda: session)

    async with server:
        reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
        await perform_greeting(reader, writer, [0x00])

        # Send CMD_UDP_ASSOCIATE (0x03)
        req = bytes([0x05, CMD_UDP_ASSOCIATE, 0x00, ATYP_IPV4, 127, 0, 0, 1]) + struct.pack("!H", 53)
        writer.write(req)
        await writer.drain()

        resp = await reader.readexactly(10)
        assert resp[0] == 0x05
        assert resp[1] == REP_CMD_NOT_SUPPORTED  # 0x07
        writer.close()
        await writer.wait_closed()


@pytest.mark.asyncio
async def test_socks5_unsupported_atyp() -> None:
    session = MockUpstreamSession()
    server = LocalSocks5Server(bind_address="127.0.0.1", port=0, session_provider=lambda: session)

    async with server:
        reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
        await perform_greeting(reader, writer, [0x00])

        # Send invalid ATYP 0x02
        req = bytes([0x05, CMD_CONNECT, 0x00, 0x02, 127, 0, 0, 1]) + struct.pack("!H", 80)
        writer.write(req)
        await writer.drain()

        resp = await reader.readexactly(10)
        assert resp[0] == 0x05
        assert resp[1] == REP_ATYP_NOT_SUPPORTED  # 0x08
        writer.close()
        await writer.wait_closed()


@pytest.mark.asyncio
async def test_socks5_connect_ipv4() -> None:
    session = MockUpstreamSession()
    server = LocalSocks5Server(bind_address="127.0.0.1", port=0, session_provider=lambda: session)

    async with server:
        reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
        await perform_greeting(reader, writer, [0x00])

        # Connect to 1.2.3.4:80
        req = bytes([0x05, CMD_CONNECT, 0x00, ATYP_IPV4, 1, 2, 3, 4]) + struct.pack("!H", 80)
        writer.write(req)
        await writer.drain()

        resp = await reader.readexactly(10)
        assert resp[0] == 0x05
        assert resp[1] == REP_SUCCESS  # 0x00
        assert session.opened_targets == [("1.2.3.4", 80)]

        writer.close()
        await writer.wait_closed()


@pytest.mark.asyncio
async def test_socks5_connect_domain() -> None:
    session = MockUpstreamSession()
    server = LocalSocks5Server(bind_address="127.0.0.1", port=0, session_provider=lambda: session)

    async with server:
        reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
        await perform_greeting(reader, writer, [0x00])

        # Connect to domain "example.com:443"
        domain = b"example.com"
        req = (
            bytes([0x05, CMD_CONNECT, 0x00, ATYP_DOMAIN, len(domain)])
            + domain
            + struct.pack("!H", 443)
        )
        writer.write(req)
        await writer.drain()

        resp = await reader.readexactly(10)
        assert resp[0] == 0x05
        assert resp[1] == REP_SUCCESS  # 0x00
        assert session.opened_targets == [("example.com", 443)]

        writer.close()
        await writer.wait_closed()


@pytest.mark.asyncio
async def test_socks5_connect_ipv6() -> None:
    session = MockUpstreamSession()
    server = LocalSocks5Server(bind_address="127.0.0.1", port=0, session_provider=lambda: session)

    async with server:
        reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
        await perform_greeting(reader, writer, [0x00])

        # Connect to IPv6 ::1:8080
        ipv6_bytes = socket.inet_pton(socket.AF_INET6, "::1")
        req = bytes([0x05, CMD_CONNECT, 0x00, ATYP_IPV6]) + ipv6_bytes + struct.pack("!H", 8080)
        writer.write(req)
        await writer.drain()

        resp = await reader.readexactly(10)
        assert resp[0] == 0x05
        assert resp[1] == REP_SUCCESS
        assert session.opened_targets == [("::1", 8080)]

        writer.close()
        await writer.wait_closed()


@pytest.mark.asyncio
async def test_socks5_no_session_provider() -> None:
    # No session returned
    server = LocalSocks5Server(bind_address="127.0.0.1", port=0, session_provider=lambda: None)

    async with server:
        reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
        await perform_greeting(reader, writer, [0x00])

        req = bytes([0x05, CMD_CONNECT, 0x00, ATYP_IPV4, 10, 0, 0, 1]) + struct.pack("!H", 80)
        writer.write(req)
        await writer.drain()

        resp = await reader.readexactly(10)
        assert resp[0] == 0x05
        assert resp[1] == REP_CONNECTION_REFUSED  # 0x05

        writer.close()
        await writer.wait_closed()


@pytest.mark.asyncio
async def test_socks5_upstream_rejected() -> None:
    session = MockUpstreamSession(failure_exc=ConnectionRefusedError("Edge refused destination"))
    server = LocalSocks5Server(bind_address="127.0.0.1", port=0, session_provider=lambda: session)

    async with server:
        reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
        await perform_greeting(reader, writer, [0x00])

        req = bytes([0x05, CMD_CONNECT, 0x00, ATYP_IPV4, 10, 0, 0, 1]) + struct.pack("!H", 80)
        writer.write(req)
        await writer.drain()

        resp = await reader.readexactly(10)
        assert resp[0] == 0x05
        assert resp[1] == REP_CONNECTION_REFUSED

        writer.close()
        await writer.wait_closed()


@pytest.mark.asyncio
async def test_socks5_upstream_timeout_unreachable() -> None:
    session = MockUpstreamSession(failure_exc=TimeoutError("Connection timed out to destination"))
    server = LocalSocks5Server(bind_address="127.0.0.1", port=0, session_provider=lambda: session)

    async with server:
        reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
        await perform_greeting(reader, writer, [0x00])

        req = bytes([0x05, CMD_CONNECT, 0x00, ATYP_IPV4, 10, 0, 0, 1]) + struct.pack("!H", 80)
        writer.write(req)
        await writer.drain()

        resp = await reader.readexactly(10)
        assert resp[0] == 0x05
        assert resp[1] == REP_HOST_UNREACHABLE  # 0x04

        writer.close()
        await writer.wait_closed()


@pytest.mark.asyncio
async def test_socks5_bidirectional_relay_and_stats() -> None:
    stats_history: list[tuple[int, int]] = []

    def on_stats(sent: int, received: int) -> None:
        stats_history.append((sent, received))

    session = MockUpstreamSession()
    server = LocalSocks5Server(
        bind_address="127.0.0.1",
        port=0,
        session_provider=lambda: session,
        on_stats_update=on_stats,
    )

    async with server:
        reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
        await perform_greeting(reader, writer, [0x00])

        # Connect
        req = bytes([0x05, CMD_CONNECT, 0x00, ATYP_IPV4, 8, 8, 8, 8]) + struct.pack("!H", 53)
        writer.write(req)
        await writer.drain()
        resp = await reader.readexactly(10)
        assert resp[1] == REP_SUCCESS

        stream = session.stream
        assert stream is not None

        # Test Client -> Upstream
        payload_upload = b"HELLO UPSTREAM FROM CLIENT!"
        writer.write(payload_upload)
        await writer.drain()

        # Upstream reads what client sent
        received_by_upstream = await stream.out_queue.get()
        assert received_by_upstream == payload_upload

        # Test Upstream -> Client
        payload_download = b"HELLO CLIENT FROM UPSTREAM!"
        stream.in_queue.put_nowait(payload_download)

        received_by_client = await reader.read(len(payload_download))
        assert received_by_client == payload_download

        # Verify stats tracking
        assert server.total_bytes_sent >= len(payload_upload)
        assert server.total_bytes_received >= len(payload_download)
        assert len(stats_history) >= 2

        # Clean shutdown
        writer.close()
        await writer.wait_closed()


# ---------------------------------------------------------------------------
# DoH Resolver Tests
# ---------------------------------------------------------------------------


def test_build_wire_query_a() -> None:
    query = build_wire_query("example.com", "A", query_id=0x1234)
    # Header: ID 0x1234, Flags 0x0100, QDCOUNT=1
    assert query[:4] == b"\x12\x34\x01\x00"
    # QNAME: \x07example\x03com\x00
    expected_qname = b"\x07example\x03com\x00"
    assert expected_qname in query
    # Ends with QTYPE 1 (A) and QCLASS 1 (IN)
    assert query.endswith(struct.pack("!HH", 1, 1))


def test_build_wire_query_aaaa() -> None:
    query = build_wire_query("example.com", "AAAA", query_id=0x5678)
    assert query[:4] == b"\x56\x78\x01\x00"
    assert query.endswith(struct.pack("!HH", 28, 1))


def test_parse_wire_response_a() -> None:
    # Build simulated DNS answer packet for "example.com" -> 93.184.215.14
    header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    qname = b"\x07example\x03com\x00"
    question = qname + struct.pack("!HH", 1, 1)

    # Answer: pointer to qname (0xc0 0x0c), type 1 (A), class 1, ttl 300, len 4, IP 93.184.215.14
    ip_bytes = socket.inet_aton("93.184.215.14")
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + ip_bytes
    packet = header + question + answer

    ips = parse_wire_response(packet, "A")
    assert ips == ["93.184.215.14"]


def test_parse_wire_response_aaaa() -> None:
    header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    qname = b"\x07example\x03com\x00"
    question = qname + struct.pack("!HH", 28, 1)

    ipv6_str = "2606:2800:220:1:248:1893:25c8:1946"
    ip_bytes = socket.inet_pton(socket.AF_INET6, ipv6_str)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, 300, 16) + ip_bytes
    packet = header + question + answer

    ips = parse_wire_response(packet, "AAAA")
    assert ips == [ipv6_str]


def test_parse_json_response() -> None:
    json_data = {
        "Status": 0,
        "Answer": [
            {"name": "cloudflare.com", "type": 1, "TTL": 60, "data": "104.16.132.229"},
            {"name": "cloudflare.com", "type": 1, "TTL": 60, "data": "104.16.133.229"},
            {"name": "cloudflare.com", "type": 28, "TTL": 60, "data": "2606:4700::6810:84e5"},
        ],
    }

    a_records = parse_json_response(json_data, "A")
    assert a_records == ["104.16.132.229", "104.16.133.229"]

    aaaa_records = parse_json_response(json_data, "AAAA")
    assert aaaa_records == ["2606:4700::6810:84e5"]


@pytest.mark.asyncio
async def test_doh_client_mock_json() -> None:
    mock_json = {
        "Status": 0,
        "Answer": [
            {"name": "example.org", "type": 1, "data": "93.184.216.34"},
        ],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=mock_json, headers={"content-type": "application/dns-json"})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as mock_http:
        doh = DohClient(client=mock_http)
        ips = await doh.resolve("example.org", record_type="A", provider="cloudflare")
        assert ips == ["93.184.216.34"]


@pytest.mark.asyncio
async def test_doh_client_mock_wire() -> None:
    header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    qname = b"\x07example\x03org\x00"
    question = qname + struct.pack("!HH", 1, 1)
    ip_bytes = socket.inet_aton("93.184.216.34")
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + ip_bytes
    wire_response = header + question + answer

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=wire_response,
            headers={"content-type": "application/dns-message"},
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as mock_http:
        doh = DohClient(client=mock_http)
        ips = await doh.resolve("example.org", record_type="A", provider="google")
        assert ips == ["93.184.216.34"]


@pytest.mark.asyncio
async def test_doh_client_automatic_fallback() -> None:
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if "1.1.1.1" in str(request.url):
            return httpx.Response(500, text="Internal Server Error")
        # Google resolves successfully via wire
        header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
        qname = b"\x03foo\x03com\x00"
        question = qname + struct.pack("!HH", 1, 1)
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + socket.inet_aton("1.2.3.4")
        return httpx.Response(200, content=header + question + answer)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as mock_http:
        doh = DohClient(client=mock_http)
        ips = await doh.resolve("foo.com", record_type="A", provider="automatic")
        assert ips == ["1.2.3.4"]
        assert any("1.1.1.1" in c for c in calls)
        assert any("8.8.8.8" in c for c in calls)


# ---------------------------------------------------------------------------
# Exit Checker Tests
# ---------------------------------------------------------------------------


def test_parse_trace_fields() -> None:
    sample_trace = """
fl=1005f40
h=www.cloudflare.com
ip=198.51.100.42
ts=1728667000.123
visit_scheme=https
uag=python-httpx/0.28.1
colo=FRA
loc=DE
warp=off
"""
    parsed = parse_trace(sample_trace)
    assert parsed["ip"] == "198.51.100.42"
    assert parsed["loc"] == "DE"
    assert parsed["colo"] == "FRA"
    assert parsed["warp"] == "off"
    assert parsed["ts"] == "1728667000.123"


@pytest.mark.asyncio
async def test_exit_check_verification_success() -> None:
    trace_body = "ip=203.0.113.1\nloc=US\nwarp=off\n"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=trace_body)

    # Use custom transport on ExitChecker by mocking httpx.AsyncClient or trace_url
    checker = ExitChecker(trace_url="https://mock-trace/cdn-cgi/trace")

    # Mock the AsyncClient in ExitChecker
    orig_client = httpx.AsyncClient

    def mocked_client(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs.pop("proxy", None)
        return orig_client(transport=httpx.MockTransport(handler), **kwargs)

    httpx.AsyncClient = mocked_client  # type: ignore[assignment]
    try:
        # Verified matching expected country
        result = await checker.check_exit(expected_country="US")
        assert result["ip"] == "203.0.113.1"
        assert result["country"] == "US"
        assert result["verified"] is True
        assert result["details"]["warp"] == "off"

        # Verified with "REC" (recommended wildcard)
        res_rec = await checker.check_exit(expected_country="REC")
        assert res_rec["verified"] is True

        # Verified with None
        res_none = await checker.check_exit(expected_country=None)
        assert res_none["verified"] is True
    finally:
        httpx.AsyncClient = orig_client  # type: ignore[assignment]


@pytest.mark.asyncio
async def test_exit_check_country_mismatch() -> None:
    trace_body = "ip=203.0.113.1\nloc=DE\nwarp=off\n"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=trace_body)

    checker = ExitChecker(trace_url="https://mock-trace/cdn-cgi/trace")
    orig_client = httpx.AsyncClient

    def mocked_client(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs.pop("proxy", None)
        return orig_client(transport=httpx.MockTransport(handler), **kwargs)

    httpx.AsyncClient = mocked_client  # type: ignore[assignment]
    try:
        result = await checker.check_exit(expected_country="FR")
        assert result["country"] == "DE"
        assert result["verified"] is False
    finally:
        httpx.AsyncClient = orig_client  # type: ignore[assignment]


@pytest.mark.asyncio
async def test_end_to_end_httpx_through_socks5_server() -> None:
    """Full end-to-end integration test: httpx -> LocalSocks5Server -> upstream TCP server."""
    # 1. Spin up a dummy HTTP server
    async def dummy_http_handler(
        r: asyncio.StreamReader,
        w: asyncio.StreamWriter,
    ) -> None:
        req = await r.readuntil(b"\r\n\r\n")
        if b"/cdn-cgi/trace" in req:
            body = "fl=1a\nh=trace\nip=198.51.100.99\nloc=DE\nwarp=on\n"
        else:
            body = "Hello from upstream!"
        content_bytes = body.encode("utf-8")
        resp = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            + f"Content-Length: {len(content_bytes)}\r\n\r\n".encode("ascii")
            + content_bytes
        )
        w.write(resp)
        await w.drain()
        w.close()
        await w.wait_closed()

    http_server = await asyncio.start_server(dummy_http_handler, "127.0.0.1", 0)
    http_port = http_server.sockets[0].getsockname()[1]

    # 2. Upstream session that dials destinations via standard TCP
    class DirectTcpUpstreamSession:
        async def open_stream(self, host: str, port: int) -> SimpleTunneledStream:
            reader, writer = await asyncio.open_connection(host, port)
            return SimpleTunneledStream(reader=reader, writer=writer)

    # 3. Start SOCKS5 Server
    socks_server = LocalSocks5Server(
        bind_address="127.0.0.1",
        port=0,
        session_provider=lambda: DirectTcpUpstreamSession(),
    )

    try:
        async with socks_server:
            # 4. Use httpx through SOCKS5 proxy
            proxy_url = f"socks5://127.0.0.1:{socks_server.port}"
            async with httpx.AsyncClient(proxy=proxy_url, timeout=5.0) as client:
                res = await client.get(f"http://127.0.0.1:{http_port}/test")
                assert res.status_code == 200
                assert res.text == "Hello from upstream!"

            assert socks_server.total_bytes_sent > 0
            assert socks_server.total_bytes_received > 0

            # 5. Run ExitChecker through this SOCKS5 proxy
            checker = ExitChecker(
                trace_url=f"http://127.0.0.1:{http_port}/cdn-cgi/trace",
                timeout=5.0,
            )
            exit_res = await checker.check_exit(
                socks_host="127.0.0.1",
                socks_port=socks_server.port,
                expected_country="DE",
            )
            assert exit_res["verified"] is True
            assert exit_res["ip"] == "198.51.100.99"
            assert exit_res["country"] == "DE"
            assert exit_res["details"]["warp"] == "on"

            # Check mismatch on same proxy
            mismatch_res = await checker.check_exit(
                socks_host="127.0.0.1",
                socks_port=socks_server.port,
                expected_country="US",
            )
            assert mismatch_res["verified"] is False
    finally:
        http_server.close()
        await http_server.wait_closed()

