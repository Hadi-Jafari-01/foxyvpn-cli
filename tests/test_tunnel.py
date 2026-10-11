"""Unit tests for HTTP/2 Upstream Tunneling Session and UpstreamSession interface."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import h2.config
import h2.connection
import h2.events
import h2.settings
import pytest

from foxyvpn.tunnel.h2_session import (
    HTTP2_DEFAULT_WINDOW_SIZE,
    HTTP2_FLOW_CONTROL_WINDOW_BYTES,
    HTTP2_MAX_FRAME_SIZE_BYTES,
    KEEPALIVE_PING_PAYLOAD,
    H2UpstreamSession,
    TunneledStreamWriter,
)
from foxyvpn.tunnel.upstream import (
    ProxyType,
    TunneledStream,
    UpstreamConnectRejectedException,
    UpstreamConnectTimeoutException,
    UpstreamProxyConfig,
    UpstreamSession,
)


# ---------------------------------------------------------------------------
# Test helpers: Mock H2 Server
# ---------------------------------------------------------------------------

class MockH2Server:
    """A lightweight in-process HTTP/2 server for testing client sessions."""

    def __init__(self, initial_settings: dict[int, int] | None = None) -> None:
        self.config = h2.config.H2Configuration(client_side=False)
        self.h2_conn = h2.connection.H2Connection(config=self.config)
        self.h2_conn.initiate_connection()
        if initial_settings:
            self.h2_conn.update_settings(initial_settings)

        self.server: asyncio.Server | None = None
        self.port: int = 0
        self.client_reader: asyncio.StreamReader | None = None
        self.client_writer: asyncio.StreamWriter | None = None
        self.received_requests: list[tuple[int, dict[bytes, bytes]]] = []
        self.received_data: list[tuple[int, bytes]] = []
        self.remote_settings: dict[int, int] = {}
        self.window_updates: list[tuple[int, int]] = []
        self.pings_received: list[bytes] = []
        self.ping_acks: list[bytes] = []

        self.req_received_event = asyncio.Event()
        self.data_received_event = asyncio.Event()
        self.settings_received_event = asyncio.Event()
        self.ping_received_event = asyncio.Event()
        self.ping_ack_event = asyncio.Event()

        # Custom handler overrides
        self.auto_respond_status: int | None = 200
        self.auto_ack_data: bool = True
        self.ignore_pings: bool = False
        self.active_writers: set[asyncio.StreamWriter] = set()

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self.client_reader = reader
        self.client_writer = writer

        # Send initial server preface
        writer.write(self.h2_conn.data_to_send())
        await writer.drain()

        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break

                events = self.h2_conn.receive_data(data)
                for ev in events:
                    if isinstance(ev, h2.events.RequestReceived):
                        headers_dict = dict(ev.headers)
                        self.received_requests.append((ev.stream_id, headers_dict))
                        self.req_received_event.set()

                        if self.auto_respond_status is not None:
                            self.h2_conn.send_headers(
                                ev.stream_id,
                                [(":status", str(self.auto_respond_status))],
                                end_stream=False,
                            )

                    elif isinstance(ev, h2.events.DataReceived):
                        self.received_data.append((ev.stream_id, ev.data))
                        self.data_received_event.set()
                        if self.auto_ack_data:
                            try:
                                self.h2_conn.acknowledge_received_data(
                                    ev.flow_controlled_length, ev.stream_id
                                )
                            except Exception:
                                pass

                    elif isinstance(ev, h2.events.RemoteSettingsChanged):
                        for k, v in ev.changed_settings.items():
                            self.remote_settings[k] = v.new_value
                        self.settings_received_event.set()

                    elif isinstance(ev, h2.events.WindowUpdated):
                        self.window_updates.append((ev.stream_id, ev.delta))

                    elif isinstance(ev, h2.events.PingReceived):
                        self.pings_received.append(ev.ping_data)
                        self.ping_received_event.set()
                        if self.ignore_pings:
                            self.h2_conn.data_to_send()

                    elif isinstance(ev, h2.events.PingAckReceived):
                        self.ping_acks.append(ev.ping_data)
                        self.ping_ack_event.set()

                    elif isinstance(ev, h2.events.StreamEnded):
                        try:
                            self.h2_conn.end_stream(ev.stream_id)
                        except Exception:
                            pass

                to_send = self.h2_conn.data_to_send()
                if to_send:
                    writer.write(to_send)
                    await writer.drain()
        except asyncio.CancelledError:
            pass
        except Exception:
            pass
        finally:
            self.active_writers.discard(writer)

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle_client, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        for w in list(self.active_writers):
            try:
                w.close()
            except Exception:
                pass
        self.active_writers.clear()
        if self.client_writer and not self.client_writer.is_closing():
            try:
                self.client_writer.close()
            except Exception:
                pass
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    async def flush(self) -> None:
        to_send = self.h2_conn.data_to_send()
        if to_send and self.client_writer and not self.client_writer.is_closing():
            self.client_writer.write(to_send)
            await self.client_writer.drain()


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------

class TestUpstreamDataStructures:
    def test_proxy_config_and_types(self) -> None:
        cfg1 = UpstreamProxyConfig(type=ProxyType.SOCKS5, host="127.0.0.1", port=1080)
        assert cfg1.type == ProxyType.SOCKS5
        assert cfg1.host == "127.0.0.1"
        assert cfg1.port == 1080
        assert cfg1.username is None

        cfg2 = UpstreamProxyConfig(
            type="http",
            host="proxy.corp",
            port=8080,
            username="user",
            password="secret",
        )
        assert cfg2.type == ProxyType.HTTP
        assert cfg2.username == "user"
        assert cfg2.password == "secret"

    def test_exceptions(self) -> None:
        rej = UpstreamConnectRejectedException(403, "example.com:443")
        assert rej.status_code == 403
        assert rej.authority == "example.com:443"
        assert "403" in str(rej)

        cause = TimeoutError("socket timed out")
        timeout_exc = UpstreamConnectTimeoutException("target.com:80", cause=cause)
        assert timeout_exc.authority == "target.com:80"
        assert timeout_exc.cause is cause
        assert "target.com:80" in str(timeout_exc)

    @pytest.mark.asyncio
    async def test_tunneled_stream_dataclass(self) -> None:
        reader = asyncio.StreamReader()
        writer = MagicMock()
        closed = False

        def close_fn() -> None:
            nonlocal closed
            closed = True

        stream = TunneledStream(reader=reader, writer=writer, close=close_fn)
        assert stream.reader is reader
        assert stream.writer is writer
        stream.close()
        assert closed is True


class TestH2UpstreamSessionInit:
    def test_init_properties(self) -> None:
        session = H2UpstreamSession(
            upstream_host="vpn.mozilla.org",
            upstream_port=443,
            bearer_token="initial-token",
            edge_address="192.0.2.1",
        )
        assert session.upstream_host == "vpn.mozilla.org"
        assert session.upstream_port == 443
        assert session.bearer_token == "initial-token"
        assert session.is_connected is False

    def test_update_bearer_token(self) -> None:
        session = H2UpstreamSession(
            upstream_host="vpn.mozilla.org",
            bearer_token="token_v1",
        )
        assert session.bearer_token == "token_v1"
        session.update_bearer_token("token_v2")
        assert session.bearer_token == "token_v2"
        # Blank / same token should be ignored
        session.update_bearer_token("")
        assert session.bearer_token == "token_v2"
        session.update_bearer_token("token_v2")
        assert session.bearer_token == "token_v2"


@pytest.mark.asyncio
class TestH2UpstreamSessionProtocol:
    async def test_initial_frames_negotiation(self) -> None:
        """Verifies initial HTTP/2 settings and connection WINDOW_UPDATE frames."""
        server = MockH2Server()
        await server.start()
        try:
            session = H2UpstreamSession(
                upstream_host="127.0.0.1",
                upstream_port=server.port,
                bearer_token="jwt-token",
            )
            r, w = await asyncio.open_connection("127.0.0.1", server.port)
            await session.connect(reader=r, writer=w)

            # Wait for server to receive client settings
            await asyncio.wait_for(server.settings_received_event.wait(), timeout=2.0)

            # Verify initial settings
            assert server.remote_settings[h2.settings.SettingCodes.ENABLE_PUSH] == 0
            assert (
                server.remote_settings[h2.settings.SettingCodes.INITIAL_WINDOW_SIZE]
                == HTTP2_FLOW_CONTROL_WINDOW_BYTES
            )
            assert (
                server.remote_settings[h2.settings.SettingCodes.MAX_FRAME_SIZE]
                == HTTP2_MAX_FRAME_SIZE_BYTES
            )

            # Verify connection-level window update frame for 16MB total
            expected_increment = (
                HTTP2_FLOW_CONTROL_WINDOW_BYTES - HTTP2_DEFAULT_WINDOW_SIZE
            )
            assert any(
                sid == 0 and delta == expected_increment
                for sid, delta in server.window_updates
            )

            assert session.is_connected is True
            session.close()
        finally:
            await server.stop()

    async def test_open_stream_connect_headers_and_ipv6(self) -> None:
        """Verifies standard and IPv6 CONNECT request headers."""
        server = MockH2Server()
        await server.start()
        try:
            session = H2UpstreamSession(
                upstream_host="127.0.0.1",
                upstream_port=server.port,
                bearer_token="my-secret-jwt",
            )
            r, w = await asyncio.open_connection("127.0.0.1", server.port)
            await session.connect(reader=r, writer=w)

            # Open stream 1 (standard IPv4 / hostname)
            stream1 = await session.open_stream("target.internal", 8080)
            assert len(server.received_requests) == 1
            sid1, headers1 = server.received_requests[0]
            assert sid1 == 1
            assert headers1[b":method"] == b"CONNECT"
            assert headers1[b":authority"] == b"target.internal:8080"
            assert headers1[b"proxy-authorization"] == b"Bearer my-secret-jwt"
            assert headers1[b"user-agent"] == b"MozillaVPN/2.35.0 (sys:linux; iap:true)"

            # Open stream 2 (IPv6 host)
            stream2 = await session.open_stream("2001:db8::1", 443)
            assert len(server.received_requests) == 2
            sid2, headers2 = server.received_requests[1]
            assert sid2 == 3
            assert headers2[b":authority"] == b"[2001:db8::1]:443"

            stream1.close()
            stream2.close()
            session.close()
        finally:
            await server.stop()

    async def test_open_stream_rejection(self) -> None:
        """Verifies that non-2xx status code raises UpstreamConnectRejectedException."""
        server = MockH2Server()
        server.auto_respond_status = 403
        await server.start()
        try:
            session = H2UpstreamSession(
                upstream_host="127.0.0.1",
                upstream_port=server.port,
                bearer_token="bad-token",
            )
            r, w = await asyncio.open_connection("127.0.0.1", server.port)
            await session.connect(reader=r, writer=w)

            with pytest.raises(UpstreamConnectRejectedException) as exc_info:
                await session.open_stream("restricted.host", 443)

            assert exc_info.value.status_code == 403
            assert exc_info.value.authority == "restricted.host:443"

            session.close()
        finally:
            await server.stop()

    async def test_open_stream_timeout(self) -> None:
        """Verifies that an unresponsive CONNECT request raises timeout exception."""
        server = MockH2Server()
        server.auto_respond_status = None  # Do not respond to CONNECT
        await server.start()
        try:
            session = H2UpstreamSession(
                upstream_host="127.0.0.1",
                upstream_port=server.port,
                bearer_token="jwt",
            )
            r, w = await asyncio.open_connection("127.0.0.1", server.port)
            await session.connect(reader=r, writer=w)

            with patch("foxyvpn.tunnel.h2_session.OPEN_STREAM_TIMEOUT_SECONDS", 0.1):
                with pytest.raises(UpstreamConnectTimeoutException) as exc_info:
                    await session.open_stream("slow.host", 443)

            assert exc_info.value.authority == "slow.host:443"
            session.close()
        finally:
            await server.stop()

    async def test_bidirectional_data_exchange(self) -> None:
        """Verifies full duplex data transfer over the tunneled stream."""
        server = MockH2Server()
        await server.start()
        try:
            session = H2UpstreamSession(
                upstream_host="127.0.0.1",
                upstream_port=server.port,
                bearer_token="jwt",
            )
            r, w = await asyncio.open_connection("127.0.0.1", server.port)
            await session.connect(reader=r, writer=w)

            stream = await session.open_stream("echo.service", 80)

            # Send data from client to server
            test_payload = b"PING-VPN-PAYLOAD-12345"
            await stream.writer.write_all(test_payload)

            await asyncio.wait_for(server.data_received_event.wait(), timeout=2.0)
            assert len(server.received_data) == 1
            sid, received_bytes = server.received_data[0]
            assert sid == 1
            assert received_bytes == test_payload

            # Server sends reply back to client
            server_reply = b"PONG-REPLY-DATA-67890"
            server.h2_conn.send_data(sid, server_reply, end_stream=False)
            await server.flush()

            client_read = await stream.reader.read(len(server_reply))
            assert client_read == server_reply

            stream.close()
            session.close()
        finally:
            await server.stop()

    async def test_token_update_live_session(self) -> None:
        """Verifies token swapping: existing stream stays active, new stream uses new token."""
        server = MockH2Server()
        await server.start()
        try:
            session = H2UpstreamSession(
                upstream_host="127.0.0.1",
                upstream_port=server.port,
                bearer_token="token-A",
            )
            r, w = await asyncio.open_connection("127.0.0.1", server.port)
            await session.connect(reader=r, writer=w)

            # Stream 1 uses token A
            stream1 = await session.open_stream("host-a.com", 443)
            assert server.received_requests[0][1][b"proxy-authorization"] == b"Bearer token-A"

            # Swap token to token B
            session.update_bearer_token("token-B")

            # Stream 2 uses token B
            stream2 = await session.open_stream("host-b.com", 443)
            assert server.received_requests[1][1][b"proxy-authorization"] == b"Bearer token-B"

            # Verify stream 1 can still transfer data undisturbed
            await stream1.writer.write_all(b"stream1-data")
            await asyncio.wait_for(server.data_received_event.wait(), timeout=2.0)
            assert any(sid == 1 and data == b"stream1-data" for sid, data in server.received_data)

            stream1.close()
            stream2.close()
            session.close()
        finally:
            await server.stop()

    async def test_flow_control_window_throttling_and_unblocking(self) -> None:
        """Verifies outbound flow control stops when window exhausted and resumes on WINDOW_UPDATE."""
        # Restrict server initial window size to 60 bytes
        server = MockH2Server(
            initial_settings={h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 60}
        )
        server.auto_ack_data = False
        await server.start()
        try:
            session = H2UpstreamSession(
                upstream_host="127.0.0.1",
                upstream_port=server.port,
                bearer_token="jwt",
            )
            r, w = await asyncio.open_connection("127.0.0.1", server.port)
            await session.connect(reader=r, writer=w)

            # Give a small pause for settings to be received by client
            await asyncio.sleep(0.05)

            stream = await session.open_stream("flow.service", 443)

            # Client attempts to write 120 bytes (exceeds 60 bytes window)
            payload = b"X" * 120
            write_task = asyncio.create_task(stream.writer.write_all(payload))

            # Wait for first 60 bytes to be received
            await asyncio.sleep(0.1)
            total_received_so_far = sum(len(d) for sid, d in server.received_data if sid == 1)
            assert total_received_so_far == 60
            assert not write_task.done(), "Write task should be blocked waiting for window update"

            # Server unblocks by sending WINDOW_UPDATE for stream 1 (+60 bytes)
            server.h2_conn.increment_flow_control_window(60, stream_id=1)
            await server.flush()

            # Write task should complete now
            await asyncio.wait_for(write_task, timeout=2.0)
            await asyncio.sleep(0.05)
            total_received_final = sum(len(d) for sid, d in server.received_data if sid == 1)
            assert total_received_final == 120

            stream.close()
            session.close()
        finally:
            await server.stop()

    async def test_server_ping_ack_handling(self) -> None:
        """Verifies that client responds to server PING with PING ACK."""
        server = MockH2Server()
        await server.start()
        try:
            session = H2UpstreamSession(
                upstream_host="127.0.0.1",
                upstream_port=server.port,
                bearer_token="jwt",
            )
            r, w = await asyncio.open_connection("127.0.0.1", server.port)
            await session.connect(reader=r, writer=w)

            # Server sends PING to client
            ping_data = b"HEARTBEE"
            server.h2_conn.ping(ping_data)
            await server.flush()

            # Client should automatically send PingAck back
            await asyncio.wait_for(server.ping_ack_event.wait(), timeout=2.0)
            assert ping_data in server.ping_acks

            session.close()
        finally:
            await server.stop()

    async def test_client_keepalive_ping_and_ack(self) -> None:
        """Verifies client keepalive pinging and acknowledging."""
        server = MockH2Server()
        await server.start()
        try:
            session = H2UpstreamSession(
                upstream_host="127.0.0.1",
                upstream_port=server.port,
                bearer_token="jwt",
            )
            r, w = await asyncio.open_connection("127.0.0.1", server.port)

            with patch("foxyvpn.tunnel.h2_session.KEEPALIVE_CHECK_INTERVAL_SECONDS", 0.05), \
                 patch("foxyvpn.tunnel.h2_session.KEEPALIVE_IDLE_THRESHOLD_SECONDS", 0.05):
                await session.connect(reader=r, writer=w)

                # Wait for server to receive client keepalive ping
                await asyncio.wait_for(server.ping_received_event.wait(), timeout=2.0)
                assert KEEPALIVE_PING_PAYLOAD in server.pings_received

            session.close()
        finally:
            await server.stop()

    async def test_goaway_handling(self) -> None:
        """Verifies that receiving GOAWAY terminates accepting new streams."""
        server = MockH2Server()
        await server.start()
        try:
            session = H2UpstreamSession(
                upstream_host="127.0.0.1",
                upstream_port=server.port,
                bearer_token="jwt",
            )
            r, w = await asyncio.open_connection("127.0.0.1", server.port)
            await session.connect(reader=r, writer=w)

            # Server sends GOAWAY
            server.h2_conn.close_connection(error_code=0, last_stream_id=0)
            await server.flush()
            await asyncio.sleep(0.05)

            assert session.is_connected is False
            with pytest.raises(ConnectionError):
                await session.open_stream("blocked.com", 443)

            session.close()
        finally:
            await server.stop()

    async def test_remote_stream_reset(self) -> None:
        """Verifies that remote StreamReset notifies stream with EOF/reset."""
        server = MockH2Server()
        await server.start()
        try:
            session = H2UpstreamSession(
                upstream_host="127.0.0.1",
                upstream_port=server.port,
                bearer_token="jwt",
            )
            r, w = await asyncio.open_connection("127.0.0.1", server.port)
            await session.connect(reader=r, writer=w)

            stream = await session.open_stream("reset.host", 443)

            # Server resets stream 1
            server.h2_conn.reset_stream(1, error_code=8)  # CANCEL
            await server.flush()
            await asyncio.sleep(0.05)

            # Stream reader should be at EOF
            data = await stream.reader.read(10)
            assert data == b""

            session.close()
        finally:
            await server.stop()

    async def test_disable_new_streams_and_close_when_idle(self) -> None:
        """Verifies session drains active streams and closes once idle."""
        server = MockH2Server()
        await server.start()
        try:
            session = H2UpstreamSession(
                upstream_host="127.0.0.1",
                upstream_port=server.port,
                bearer_token="jwt",
            )
            r, w = await asyncio.open_connection("127.0.0.1", server.port)
            await session.connect(reader=r, writer=w)

            stream = await session.open_stream("drain.host", 443)
            session.disable_new_streams_and_close_when_idle()

            assert session.is_connected is False
            with pytest.raises(ConnectionError):
                await session.open_stream("rejected.host", 443)

            # Closing active stream should cause session to close
            stream.close()
            await asyncio.sleep(0.05)
            assert session._closed is True
        finally:
            await server.stop()

    async def test_keepalive_unanswered_timeout_closes_session(self) -> None:
        """Verifies session closes when keepalive PING is unanswered."""
        server = MockH2Server()
        server.ignore_pings = True
        await server.start()
        try:
            session = H2UpstreamSession(
                upstream_host="127.0.0.1",
                upstream_port=server.port,
                bearer_token="jwt",
            )
            r, w = await asyncio.open_connection("127.0.0.1", server.port)

            with patch("foxyvpn.tunnel.h2_session.KEEPALIVE_CHECK_INTERVAL_SECONDS", 0.05), \
                 patch("foxyvpn.tunnel.h2_session.KEEPALIVE_IDLE_THRESHOLD_SECONDS", 0.05), \
                 patch("foxyvpn.tunnel.h2_session.KEEPALIVE_PING_TIMEOUT_SECONDS", 0.1):
                await session.connect(reader=r, writer=w)

                # Wait for keepalive ping to be sent
                await asyncio.wait_for(server.ping_received_event.wait(), timeout=1.0)

                # Give time for keepalive timeout to trigger (0.1s timeout)
                for _ in range(15):
                    if session._closed:
                        break
                    await asyncio.sleep(0.05)

                assert session._closed is True

            session.close()
        finally:
            await server.stop()

    async def test_alpn_negotiation_failure(self) -> None:
        """Verifies that non-h2 ALPN negotiation raises ConnectionError."""
        mock_ssl = MagicMock()
        mock_ssl.selected_alpn_protocol.return_value = "http/1.1"

        mock_writer = MagicMock()
        mock_writer.is_closing.return_value = False
        mock_writer.get_extra_info.side_effect = lambda key: mock_ssl if key == "ssl_object" else None

        mock_reader = MagicMock()

        session = H2UpstreamSession("upstream.corp", 443)
        with pytest.raises(ConnectionError, match="Upstream did not negotiate HTTP/2 over ALPN"):
            await session.connect(reader=mock_reader, writer=mock_writer)

    async def test_max_concurrent_streams_limit(self) -> None:
        """Verifies that concurrent streams throttle to the limit announced by upstream."""
        # Announce MAX_CONCURRENT_STREAMS = 1
        server = MockH2Server(
            initial_settings={h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS: 1}
        )
        await server.start()
        try:
            session = H2UpstreamSession(
                upstream_host="127.0.0.1",
                upstream_port=server.port,
                bearer_token="jwt",
            )
            r, w = await asyncio.open_connection("127.0.0.1", server.port)
            await session.connect(reader=r, writer=w)
            await asyncio.sleep(0.05)

            # Open stream 1 (occupies 1 slot)
            stream1 = await session.open_stream("target1.org", 443)

            # Attempt to open stream 2 in task (should block waiting for slot)
            task2 = asyncio.create_task(session.open_stream("target2.org", 443))
            await asyncio.sleep(0.1)
            assert not task2.done(), "Stream 2 should be blocked waiting for concurrent slot"

            # Close stream 1 to free the slot
            stream1.close()
            await asyncio.sleep(0.05)
            stream2 = await asyncio.wait_for(task2, timeout=2.0)
            assert stream2 is not None

            stream2.close()
            session.close()
        finally:
            await server.stop()


@pytest.mark.asyncio
class TestProxyHandshakes:
    async def test_socks5_handshake_no_auth(self) -> None:
        """Verifies SOCKS5 handshake without authentication."""
        async def socks5_server(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            greet = await reader.readexactly(3)
            assert greet == b"\x05\x01\x00"
            writer.write(b"\x05\x00")  # Method: NO AUTH
            await writer.drain()

            hdr = await reader.readexactly(4)
            assert hdr[:3] == b"\x05\x01\x00"
            atyp = hdr[3]
            if atyp == 0x03:
                hlen = (await reader.readexactly(1))[0]
                host = await reader.readexactly(hlen)
                assert host == b"target.domain"
            port = await reader.readexactly(2)
            assert int.from_bytes(port, "big") == 443

            writer.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x01\xbb")
            await writer.drain()

            # Echo test
            d = await reader.read(4)
            writer.write(d)
            await writer.drain()

        server = await asyncio.start_server(socks5_server, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            proxy_cfg = UpstreamProxyConfig(type=ProxyType.SOCKS5, host="127.0.0.1", port=port)
            session = H2UpstreamSession("target.domain", 443, upstream_proxy=proxy_cfg)

            r, w = await asyncio.open_connection("127.0.0.1", port)
            await session._perform_proxy_handshake(r, w, "target.domain", 443)

            w.write(b"OKAY")
            await w.drain()
            assert await r.read(4) == b"OKAY"
            w.close()
            await w.wait_closed()
        finally:
            server.close()
            await server.wait_closed()

    async def test_socks5_handshake_with_auth(self) -> None:
        """Verifies SOCKS5 handshake with username/password authentication."""
        async def socks5_auth_server(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            greet = await reader.readexactly(4)
            assert greet == b"\x05\x02\x00\x02"
            writer.write(b"\x05\x02")  # Method: USER/PASS
            await writer.drain()

            # Subnegotiation auth
            auth_ver = (await reader.readexactly(1))[0]
            assert auth_ver == 0x01
            ulen = (await reader.readexactly(1))[0]
            user = await reader.readexactly(ulen)
            plen = (await reader.readexactly(1))[0]
            passwd = await reader.readexactly(plen)
            assert user == b"proxyuser"
            assert passwd == b"proxypass"

            writer.write(b"\x01\x00")  # Auth success
            await writer.drain()

            hdr = await reader.readexactly(4)
            atyp = hdr[3]
            if atyp == 0x03:
                hlen = (await reader.readexactly(1))[0]
                await reader.readexactly(hlen)
            await reader.readexactly(2)

            writer.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x01\xbb")
            await writer.drain()

        server = await asyncio.start_server(socks5_auth_server, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            proxy_cfg = UpstreamProxyConfig(
                type=ProxyType.SOCKS5,
                host="127.0.0.1",
                port=port,
                username="proxyuser",
                password="proxypass",
            )
            session = H2UpstreamSession("target.domain", 443, upstream_proxy=proxy_cfg)

            r, w = await asyncio.open_connection("127.0.0.1", port)
            await session._perform_proxy_handshake(r, w, "target.domain", 443)
            w.close()
            await w.wait_closed()
        finally:
            server.close()
            await server.wait_closed()

    async def test_http_proxy_handshake(self) -> None:
        """Verifies HTTP CONNECT handshake with Basic authentication."""
        async def http_server(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            lines = []
            while True:
                line = await reader.readline()
                lines.append(line)
                if line in (b"\r\n", b"\n", b""):
                    break

            assert b"CONNECT mytarget.org:443 HTTP/1.1\r\n" in lines
            assert b"Host: mytarget.org:443\r\n" in lines
            assert b"Proxy-Authorization: Basic YWRtaW46c2VjcmV0MTIz\r\n" in lines

            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()

        server = await asyncio.start_server(http_server, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            proxy_cfg = UpstreamProxyConfig(
                type=ProxyType.HTTP,
                host="127.0.0.1",
                port=port,
                username="admin",
                password="secret123",
            )
            session = H2UpstreamSession("mytarget.org", 443, upstream_proxy=proxy_cfg)

            r, w = await asyncio.open_connection("127.0.0.1", port)
            await session._perform_proxy_handshake(r, w, "mytarget.org", 443)
            w.close()
            await w.wait_closed()
        finally:
            server.close()
            await server.wait_closed()
