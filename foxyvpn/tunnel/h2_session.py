"""HTTP/2 Upstream Tunneling Session implementation using pure-Python h2."""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import logging
import ssl
from typing import Any, Iterable

import h2.config
import h2.connection
import h2.errors
import h2.events
import h2.exceptions
import h2.settings

from foxyvpn.tunnel.upstream import (
    ProxyType,
    TunneledStream,
    UpstreamConnectRejectedException,
    UpstreamConnectTimeoutException,
    UpstreamProxyConfig,
    UpstreamSession,
)

logger = logging.getLogger(__name__)

# Constants matching upstream wire protocol and Netty reference implementation
HTTP2_FLOW_CONTROL_WINDOW_BYTES = 16 * 1024 * 1024  # 16MB
HTTP2_MAX_FRAME_SIZE_BYTES = 256 * 1024  # 256KB
HTTP2_DEFAULT_WINDOW_SIZE = 65535  # RFC 7540 initial window size

KEEPALIVE_CHECK_INTERVAL_SECONDS = 3.0
KEEPALIVE_IDLE_THRESHOLD_SECONDS = 15.0
KEEPALIVE_PING_TIMEOUT_SECONDS = 10.0
# 8-byte payload representing 0x466F78795650_4EL ("\x00FoxyVPN")
KEEPALIVE_PING_PAYLOAD = (0x466F787956504E).to_bytes(8, "big")

OPEN_STREAM_TIMEOUT_SECONDS = 20.0
WRITE_BACKPRESSURE_TIMEOUT_SECONDS = 60.0
DRAIN_IDLE_TIMEOUT_SECONDS = 120.0
DRAIN_POLL_INTERVAL_SECONDS = 0.25

USER_AGENT = "MozillaVPN/2.35.0 (sys:linux; iap:true)"


class TunneledStreamWriter:
    """Async stream writer for sending data over an established HTTP/2 tunnel stream."""

    def __init__(self, session: H2UpstreamSession, stream_id: int) -> None:
        self._session = session
        self._stream_id = stream_id
        self._buffer = bytearray()
        self._closing = False
        self._closed_event = asyncio.Event()

    def write(self, data: bytes) -> None:
        """Buffer outbound data to be sent on this stream."""
        if self._closing:
            raise ConnectionResetError(f"Stream {self._stream_id} is closed")
        self._buffer.extend(data)

    def writelines(self, data: Iterable[bytes]) -> None:
        """Buffer multiple chunks of outbound data."""
        for chunk in data:
            self.write(chunk)

    async def drain(self) -> None:
        """Flush buffered data to the upstream HTTP/2 connection."""
        if self._closing:
            raise ConnectionResetError(f"Stream {self._stream_id} is closed")
        if not self._buffer:
            return
        to_send = bytes(self._buffer)
        self._buffer.clear()
        await self._session._send_stream_data(self._stream_id, to_send)

    async def write_all(self, data: bytes) -> None:
        """Convenience method to write and flush data immediately."""
        self.write(data)
        await self.drain()

    def close(self) -> None:
        """Close this stream."""
        if not self._closing:
            self._closing = True
            self._session._close_stream(self._stream_id)
            self._closed_event.set()

    async def wait_closed(self) -> None:
        """Wait until this stream is closed."""
        await self._closed_event.wait()

    def is_closing(self) -> bool:
        """Return True if this writer is closed or closing."""
        return self._closing

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        """Query transport extra information."""
        if name == "stream_id":
            return self._stream_id
        return default


class H2UpstreamSession(UpstreamSession):
    """Manages an HTTP/2 connection to an upstream proxy/VPN endpoint (e.g. Fastly)."""

    def __init__(
        self,
        upstream_host: str,
        upstream_port: int = 443,
        bearer_token: str = "",
        upstream_proxy: UpstreamProxyConfig | None = None,
        edge_address: str | None = None,
    ) -> None:
        self._upstream_host = upstream_host
        self._upstream_port = upstream_port
        self._current_bearer_token = bearer_token
        self._upstream_proxy = upstream_proxy
        self._edge_address = edge_address

        self._connect_host = (
            edge_address.strip() if edge_address and edge_address.strip() else upstream_host
        )

        # Connection / transport state
        self._tls_reader: asyncio.StreamReader | None = None
        self._tls_writer: asyncio.StreamWriter | None = None
        self._h2_conn: h2.connection.H2Connection | None = None
        self._lock = asyncio.Lock()

        # Lifecycle flags
        self._closed = False
        self._closing = False
        self._accepting_new_streams = False

        # Stream management
        self._active_streams: set[int] = set()
        self._max_concurrent_streams = 2147483647
        self._slot_available_event = asyncio.Event()
        self._slot_available_event.set()

        self._stream_readers: dict[int, asyncio.StreamReader] = {}
        self._stream_futures: dict[int, asyncio.Future[int]] = {}
        self._stream_authorities: dict[int, str] = {}
        self._stream_window_events: dict[int, asyncio.Event] = {}

        # Keepalive tracking
        self._last_activity_at = 0.0
        self._last_stream_data_at = 0.0
        self._awaiting_ping_ack = False
        self._ping_sent_at = 0.0

        # Background tasks
        self._dispatch_task: asyncio.Task[None] | None = None
        self._keepalive_task: asyncio.Task[None] | None = None
        self._drain_task: asyncio.Task[None] | None = None
        self._drain_watcher_armed = False

    @property
    def upstream_host(self) -> str:
        return self._upstream_host

    @property
    def upstream_port(self) -> int:
        return self._upstream_port

    @property
    def bearer_token(self) -> str:
        return self._current_bearer_token

    @property
    def is_connected(self) -> bool:
        """Return True if session is open and accepting new streams."""
        return (
            self._tls_writer is not None
            and not self._tls_writer.is_closing()
            and not self._closed
            and self._accepting_new_streams
        )

    @property
    def remote_ip(self) -> str | None:
        """Return the physical IP of the connected remote VPN node."""
        if self._tls_writer is not None:
            peer = self._tls_writer.get_extra_info("peername")
            if peer and isinstance(peer, (tuple, list)):
                return str(peer[0])
        return None

    def update_bearer_token(self, token: str) -> None:
        """Swap out the live bearer token; subsequent CONNECT streams use the new token."""
        if not token or token == self._current_bearer_token:
            return
        self._current_bearer_token = token
        logger.info(
            "Bearer token updated in live session; existing tunnel stays open, new streams "
            "authenticate with the new pass."
        )

    def disable_new_streams_and_close_when_idle(self) -> None:
        """Prevent new streams from opening and close the session once active streams end."""
        self._accepting_new_streams = False
        if len(self._active_streams) == 0:
            self.close()
            return

        if self._drain_watcher_armed:
            return
        self._drain_watcher_armed = True
        self._drain_task = asyncio.create_task(self._drain_watcher())

    async def _drain_watcher(self) -> None:
        try:
            loop = asyncio.get_running_loop()
            while len(self._active_streams) > 0 and not self._closed:
                await asyncio.sleep(DRAIN_POLL_INTERVAL_SECONDS)
                now = loop.time()
                if (now - self._last_stream_data_at) >= DRAIN_IDLE_TIMEOUT_SECONDS:
                    logger.warning(
                        "Draining upstream session idle for %.1fs with %d flow(s) still open; closing.",
                        DRAIN_IDLE_TIMEOUT_SECONDS,
                        len(self._active_streams),
                    )
                    break
        except asyncio.CancelledError:
            pass
        finally:
            self.close()

    def _note_activity(self) -> None:
        loop = asyncio.get_running_loop()
        self._last_activity_at = loop.time()
        if self._awaiting_ping_ack:
            self._awaiting_ping_ack = False

    def _note_stream_data(self) -> None:
        loop = asyncio.get_running_loop()
        now = loop.time()
        self._last_activity_at = now
        self._last_stream_data_at = now

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create client SSLContext configured for HTTP/2 ALPN."""
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["h2"])
        return ctx

    async def connect(
        self,
        reader: asyncio.StreamReader | None = None,
        writer: asyncio.StreamWriter | None = None,
    ) -> None:
        """Connect to the upstream server, perform TLS/ALPN handshake, and initialize HTTP/2."""
        if self._closed:
            raise ConnectionError("Cannot reuse closed H2UpstreamSession")

        loop = asyncio.get_running_loop()

        if reader is not None and writer is not None:
            # Direct injection for testing/mocking
            self._tls_reader = reader
            self._tls_writer = writer
        elif self._upstream_proxy is not None:
            # Connect via SOCKS5 or HTTP CONNECT proxy
            logger.info(
                "Connecting to upstream %s:%d through %s proxy %s:%d",
                self._connect_host,
                self._upstream_port,
                self._upstream_proxy.type,
                self._upstream_proxy.host,
                self._upstream_proxy.port,
            )
            raw_reader, raw_writer = await asyncio.open_connection(
                host=self._upstream_proxy.host,
                port=self._upstream_proxy.port,
            )
            await self._perform_proxy_handshake(
                raw_reader, raw_writer, self._connect_host, self._upstream_port
            )

            # Upgrade plain proxy transport to TLS with SNI and ALPN
            ssl_ctx = self._create_ssl_context()
            protocol = raw_writer.transport.get_protocol()
            ssl_transport = await loop.start_tls(
                raw_writer.transport,
                protocol,
                ssl_ctx,
                server_hostname=self._upstream_host,
            )
            raw_writer._transport = ssl_transport
            self._tls_reader = raw_reader
            self._tls_writer = raw_writer
        else:
            # Direct TCP + TLS connection
            ssl_ctx = self._create_ssl_context()
            if self._connect_host != self._upstream_host:
                logger.info(
                    "Custom edge address in use: TCP to %s:%d, SNI to %s",
                    self._connect_host,
                    self._upstream_port,
                    self._upstream_host,
                )
            self._tls_reader, self._tls_writer = await asyncio.open_connection(
                host=self._connect_host,
                port=self._upstream_port,
                ssl=ssl_ctx,
                server_hostname=self._upstream_host,
            )

        # Verify ALPN negotiated protocol is h2 (if ssl_object available)
        ssl_obj = self._tls_writer.get_extra_info("ssl_object")
        if ssl_obj is not None:
            negotiated = ssl_obj.selected_alpn_protocol()
            if negotiated != "h2":
                self.close()
                raise ConnectionError(
                    f"Upstream did not negotiate HTTP/2 over ALPN (got {negotiated!r})"
                )

        # Initialize H2 client connection
        h2_config = h2.config.H2Configuration(client_side=True)
        self._h2_conn = h2.connection.H2Connection(config=h2_config)
        self._h2_conn.initiate_connection()

        # Send initial settings
        self._h2_conn.update_settings(
            {
                h2.settings.SettingCodes.ENABLE_PUSH: 0,
                h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: HTTP2_FLOW_CONTROL_WINDOW_BYTES,
                h2.settings.SettingCodes.MAX_FRAME_SIZE: HTTP2_MAX_FRAME_SIZE_BYTES,
            }
        )

        # Send connection-level WINDOW_UPDATE for 16MB total window
        self._h2_conn.increment_flow_control_window(
            HTTP2_FLOW_CONTROL_WINDOW_BYTES - HTTP2_DEFAULT_WINDOW_SIZE
        )

        # Flush initial frames to transport
        init_data = self._h2_conn.data_to_send()
        if init_data:
            self._tls_writer.write(init_data)
            await self._tls_writer.drain()

        now = loop.time()
        self._last_activity_at = now
        self._last_stream_data_at = now
        self._accepting_new_streams = True

        # Start background dispatch and keepalive loops
        self._dispatch_task = asyncio.create_task(self._read_dispatch_loop())
        self._keepalive_task = asyncio.create_task(self._keepalive_loop())

    async def _perform_proxy_handshake(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        target_host: str,
        target_port: int,
    ) -> None:
        """Perform SOCKS5 or HTTP CONNECT handshake to upstream proxy."""
        assert self._upstream_proxy is not None
        proxy = self._upstream_proxy

        if proxy.type == ProxyType.SOCKS5:
            # SOCKS5 Handshake (RFC 1928)
            has_auth = bool(proxy.username)
            if has_auth:
                writer.write(b"\x05\x02\x00\x02")  # NO AUTH, USER/PASS
            else:
                writer.write(b"\x05\x01\x00")  # NO AUTH
            await writer.drain()

            ver, method = await reader.readexactly(2)
            if ver != 0x05:
                raise ConnectionError(f"Invalid SOCKS version received: {ver}")

            if method == 0x02 and has_auth:
                # Username / password authentication (RFC 1929)
                u = proxy.username.encode("utf-8") if proxy.username else b""
                p = proxy.password.encode("utf-8") if proxy.password else b""
                auth_req = bytes([0x01, len(u)]) + u + bytes([len(p)]) + p
                writer.write(auth_req)
                await writer.drain()

                auth_ver, auth_status = await reader.readexactly(2)
                if auth_status != 0x00:
                    raise PermissionError(
                        f"SOCKS5 proxy authentication failed with status {auth_status}"
                    )
            elif method == 0x00:
                pass
            else:
                raise PermissionError(
                    f"SOCKS5 proxy rejected authentication methods (method={method:#x})"
                )

            # SOCKS5 CONNECT request
            port_bytes = target_port.to_bytes(2, "big")
            try:
                ip = ipaddress.ip_address(target_host)
                if ip.version == 4:
                    atyp = 0x01
                    addr_bytes = ip.packed
                else:
                    atyp = 0x04
                    addr_bytes = ip.packed
            except ValueError:
                # Domain name
                atyp = 0x03
                host_encoded = target_host.encode("idna")
                addr_bytes = bytes([len(host_encoded)]) + host_encoded

            req = bytes([0x05, 0x01, 0x00, atyp]) + addr_bytes + port_bytes
            writer.write(req)
            await writer.drain()

            ver, rep, rsv, resp_atyp = await reader.readexactly(4)
            if rep != 0x00:
                raise ConnectionError(f"SOCKS5 CONNECT request failed with reply code {rep}")

            # Drain bound address and port
            if resp_atyp == 0x01:
                await reader.readexactly(4 + 2)
            elif resp_atyp == 0x04:
                await reader.readexactly(16 + 2)
            elif resp_atyp == 0x03:
                bnd_len = (await reader.readexactly(1))[0]
                await reader.readexactly(bnd_len + 2)
            else:
                raise ConnectionError(f"Unknown SOCKS5 address type: {resp_atyp}")

        elif proxy.type == ProxyType.HTTP:
            # HTTP CONNECT Handshake
            headers = [
                f"CONNECT {target_host}:{target_port} HTTP/1.1",
                f"Host: {target_host}:{target_port}",
                f"User-Agent: {USER_AGENT}",
            ]
            if proxy.username:
                creds = f"{proxy.username}:{proxy.password or ''}"
                b64_creds = base64.b64encode(creds.encode("utf-8")).decode("ascii")
                headers.append(f"Proxy-Authorization: Basic {b64_creds}")
            headers.append("\r\n")

            writer.write("\r\n".join(headers).encode("utf-8"))
            await writer.drain()

            # Read HTTP response status line
            status_line = await reader.readline()
            status_parts = status_line.decode("utf-8", "replace").strip().split(maxsplit=2)
            if len(status_parts) < 2:
                raise ConnectionError(f"Malformed HTTP proxy response: {status_line!r}")
            try:
                code = int(status_parts[1])
            except ValueError:
                raise ConnectionError(f"Invalid HTTP proxy status code: {status_parts[1]}")

            if not (200 <= code <= 299):
                raise ConnectionError(f"HTTP proxy rejected CONNECT: {status_line.decode().strip()}")

            # Drain remaining HTTP headers until empty line
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
        else:
            raise ValueError(f"Unsupported proxy type: {proxy.type}")

    async def _read_dispatch_loop(self) -> None:
        """Continuously reads from TLS socket and dispatches HTTP/2 frames."""
        try:
            while not self._closed and self._tls_reader is not None:
                data = await self._tls_reader.read(65536)
                if not data:
                    logger.debug("Upstream connection reached EOF")
                    break

                self._note_activity()

                async with self._lock:
                    if self._h2_conn is None:
                        break
                    try:
                        events = self._h2_conn.receive_data(data)
                    except Exception as e:
                        logger.error("Error receiving HTTP/2 frame data: %s", e, exc_info=True)
                        break

                    for event in events:
                        self._handle_event(event)

                    to_send = self._h2_conn.data_to_send()
                    if to_send and self._tls_writer and not self._tls_writer.is_closing():
                        self._tls_writer.write(to_send)
                        await self._tls_writer.drain()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            if not self._closing and not self._closed:
                logger.warning("Upstream read loop error: %s", e)
        finally:
            self._handle_connection_lost()

    def _handle_event(self, event: h2.events.Event) -> None:
        """Process incoming HTTP/2 events under connection lock."""
        assert self._h2_conn is not None

        if isinstance(event, h2.events.ResponseReceived):
            stream_id = event.stream_id
            fut = self._stream_futures.get(stream_id)
            if fut is not None and not fut.done():
                headers_dict: dict[str, str] = {}
                for k, v in event.headers:
                    k_str = k.decode("utf-8", "replace") if isinstance(k, bytes) else k
                    v_str = v.decode("utf-8", "replace") if isinstance(v, bytes) else v
                    headers_dict[k_str] = v_str

                status_str = headers_dict.get(":status")
                authority = self._stream_authorities.get(stream_id, "unknown")
                status_code: int | None = None
                if status_str is not None:
                    try:
                        status_code = int(status_str.strip())
                    except ValueError:
                        pass

                if status_code is not None and 200 <= status_code <= 299:
                    fut.set_result(status_code)
                else:
                    fut.set_exception(
                        UpstreamConnectRejectedException(
                            status_code=status_code,
                            authority=authority,
                            message=(
                                f"Upstream rejected CONNECT to {authority}: "
                                f"status={status_str or '<missing>'}"
                            ),
                        )
                    )

        elif isinstance(event, h2.events.DataReceived):
            self._note_stream_data()
            stream_id = event.stream_id
            reader = self._stream_readers.get(stream_id)
            if reader is not None:
                reader.feed_data(event.data)

            # Replenish stream and connection flow control windows to prevent starvation
            try:
                self._h2_conn.acknowledge_received_data(
                    event.flow_controlled_length, stream_id
                )
            except Exception as e:
                logger.debug("Failed acknowledging received data for stream %d: %s", stream_id, e)

        elif isinstance(event, h2.events.StreamEnded):
            stream_id = event.stream_id
            reader = self._stream_readers.get(stream_id)
            if reader is not None:
                reader.feed_eof()

        elif isinstance(event, h2.events.StreamReset):
            stream_id = event.stream_id
            err_msg = f"Upstream reset stream {stream_id} (errorCode={event.error_code})"
            logger.debug(err_msg)

            fut = self._stream_futures.get(stream_id)
            if fut is not None and not fut.done():
                fut.set_exception(ConnectionResetError(err_msg))

            reader = self._stream_readers.get(stream_id)
            if reader is not None:
                reader.feed_eof()

            self._close_stream(stream_id)

        elif isinstance(event, h2.events.ConnectionTerminated):
            self._accepting_new_streams = False
            logger.warning(
                "Upstream sent GOAWAY: errorCode=%s lastStreamId=%s additionalData=%r",
                event.error_code,
                event.last_stream_id,
                event.additional_data,
            )
            # Fail pending streams opened after last_stream_id
            for sid, fut in list(self._stream_futures.items()):
                if sid > event.last_stream_id and not fut.done():
                    fut.set_exception(
                        ConnectionResetError(
                            f"Upstream sent GOAWAY (errorCode={event.error_code}, "
                            f"lastStreamId={event.last_stream_id})"
                        )
                    )

        elif isinstance(event, h2.events.PingReceived):
            self._note_activity()
            # In h2, receiving a ping automatically queues a PingAck in data_to_send()

        elif isinstance(event, h2.events.PingAckReceived):
            self._note_activity()
            if event.ping_data == KEEPALIVE_PING_PAYLOAD:
                self._awaiting_ping_ack = False

        elif isinstance(event, h2.events.RemoteSettingsChanged):
            self._note_activity()
            announced_max = event.changed_settings.get(
                h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS
            )
            if announced_max is not None:
                self._max_concurrent_streams = max(1, announced_max.new_value)
                logger.info(
                    "Upstream announced max concurrent streams: %d",
                    self._max_concurrent_streams,
                )

        elif isinstance(event, h2.events.WindowUpdated):
            stream_id = event.stream_id
            if stream_id == 0:
                # Connection-level window updated: wake all waiting streams
                for ev in self._stream_window_events.values():
                    ev.set()
            else:
                ev = self._stream_window_events.get(stream_id)
                if ev is not None:
                    ev.set()

    def _handle_connection_lost(self) -> None:
        """Handle transport disconnection, notifying all pending streams."""
        self._accepting_new_streams = False

        # Fail pending handshake futures
        for sid, fut in list(self._stream_futures.items()):
            if not fut.done():
                fut.set_exception(ConnectionResetError("Upstream connection dropped"))

        # Feed EOF to active streams
        for sid, reader in list(self._stream_readers.items()):
            reader.feed_eof()

        # Wake up any blocked writers
        for ev in self._stream_window_events.values():
            ev.set()

        self._active_streams.clear()
        self._slot_available_event.set()

    async def _keepalive_loop(self) -> None:
        """Sends periodic HTTP/2 PING frames when connection is idle."""
        loop = asyncio.get_running_loop()
        try:
            while not self._closed:
                await asyncio.sleep(KEEPALIVE_CHECK_INTERVAL_SECONDS)
                if self._closed or not self.is_connected:
                    break

                now = loop.time()
                idle_for = now - self._last_activity_at

                if self._awaiting_ping_ack and (now - self._ping_sent_at) >= KEEPALIVE_PING_TIMEOUT_SECONDS:
                    logger.warning(
                        "Keepalive PING went unanswered for %.1fs; closing dead upstream session",
                        now - self._ping_sent_at,
                    )
                    self.close()
                    break
                elif not self._awaiting_ping_ack and idle_for >= KEEPALIVE_IDLE_THRESHOLD_SECONDS:
                    self._awaiting_ping_ack = True
                    self._ping_sent_at = now
                    async with self._lock:
                        if self._closed or self._h2_conn is None:
                            break
                        self._h2_conn.ping(KEEPALIVE_PING_PAYLOAD)
                        to_send = self._h2_conn.data_to_send()
                        if to_send and self._tls_writer and not self._tls_writer.is_closing():
                            self._tls_writer.write(to_send)
                            await self._tls_writer.drain()
        except asyncio.CancelledError:
            pass

    async def _reserve_stream_slot(self, authority: str) -> None:
        """Wait for a concurrent stream slot to be available."""
        while len(self._active_streams) >= self._max_concurrent_streams:
            if not self.is_connected:
                raise ConnectionError("H2UpstreamSession closed while waiting for stream slot")
            self._slot_available_event.clear()
            try:
                await asyncio.wait_for(
                    self._slot_available_event.wait(),
                    timeout=OPEN_STREAM_TIMEOUT_SECONDS,
                )
            except asyncio.TimeoutError as e:
                raise UpstreamConnectTimeoutException(
                    authority=authority,
                    message=(
                        f"Timed out waiting for upstream stream slot "
                        f"(max={self._max_concurrent_streams})"
                    ),
                    cause=e,
                )

    def _get_or_create_stream_window_event(self, stream_id: int) -> asyncio.Event:
        if stream_id not in self._stream_window_events:
            self._stream_window_events[stream_id] = asyncio.Event()
        return self._stream_window_events[stream_id]

    async def open_stream(self, target_host: str, target_port: int) -> TunneledStream:
        """Create an HTTP/2 CONNECT stream to target_host:target_port."""
        if not self.is_connected or self._h2_conn is None:
            raise ConnectionError("H2UpstreamSession is not connected or shutting down")

        # Format authority header per RFC
        if ":" in target_host and not target_host.startswith("["):
            authority = f"[{target_host}]:{target_port}"
        else:
            authority = f"{target_host}:{target_port}"

        await self._reserve_stream_slot(authority)

        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader()
        response_fut = loop.create_future()

        async with self._lock:
            if not self.is_connected or self._h2_conn is None:
                raise ConnectionError("H2UpstreamSession is not connected")

            stream_id = self._h2_conn.get_next_available_stream_id()
            self._active_streams.add(stream_id)
            self._stream_readers[stream_id] = reader
            self._stream_futures[stream_id] = response_fut
            self._stream_authorities[stream_id] = authority
            self._get_or_create_stream_window_event(stream_id)

            headers = [
                (":method", "CONNECT"),
                (":authority", authority),
                ("proxy-authorization", f"Bearer {self._current_bearer_token}"),
                ("user-agent", USER_AGENT),
            ]

            self._h2_conn.send_headers(stream_id, headers, end_stream=False)
            to_send = self._h2_conn.data_to_send()
            if to_send and self._tls_writer and not self._tls_writer.is_closing():
                self._tls_writer.write(to_send)
                await self._tls_writer.drain()

        # Await HTTP 2xx response headers from upstream
        try:
            await asyncio.wait_for(response_fut, timeout=OPEN_STREAM_TIMEOUT_SECONDS)
        except asyncio.TimeoutError as e:
            self._close_stream(stream_id)
            raise UpstreamConnectTimeoutException(
                authority=authority,
                message=(
                    f"Timed out waiting for CONNECT response from {self._upstream_host}:"
                    f"{self._upstream_port} ({authority})"
                ),
                cause=e,
            )
        except Exception:
            self._close_stream(stream_id)
            raise

        writer = TunneledStreamWriter(self, stream_id)
        return TunneledStream(
            reader=reader,
            writer=writer,
            close=writer.close,
        )

    async def _send_stream_data(self, stream_id: int, data: bytes) -> None:
        """Send data chunks on a stream, respecting HTTP/2 flow control limits."""
        offset = 0
        total = len(data)

        while offset < total and not self._closed:
            if stream_id not in self._active_streams:
                raise ConnectionResetError(f"Stream {stream_id} is closed")

            async with self._lock:
                if stream_id not in self._active_streams or self._h2_conn is None:
                    raise ConnectionResetError(f"Stream {stream_id} is closed")

                window = self._h2_conn.local_flow_control_window(stream_id)
                max_frame = self._h2_conn.max_outbound_frame_size

                if window > 0:
                    chunk_size = min(total - offset, window, max_frame)
                    chunk = data[offset : offset + chunk_size]
                    offset += chunk_size

                    self._h2_conn.send_data(stream_id, chunk, end_stream=False)
                    to_send = self._h2_conn.data_to_send()
                    if to_send and self._tls_writer and not self._tls_writer.is_closing():
                        self._tls_writer.write(to_send)
                        await self._tls_writer.drain()
                    self._note_stream_data()
                    continue
                else:
                    # Flow control window exhausted; wait for WindowUpdated
                    window_event = self._get_or_create_stream_window_event(stream_id)
                    window_event.clear()

            # Wait outside lock so reader loop can process incoming WindowUpdated frames
            try:
                await asyncio.wait_for(
                    window_event.wait(), timeout=WRITE_BACKPRESSURE_TIMEOUT_SECONDS
                )
            except asyncio.TimeoutError:
                raise TimeoutError(
                    f"Upstream stream {stream_id} flow control window wait timed out"
                )

    def _close_stream(self, stream_id: int) -> None:
        """Close an individual stream and release its slot."""
        self._stream_readers.pop(stream_id, None)
        fut = self._stream_futures.pop(stream_id, None)
        if fut is not None and not fut.done():
            fut.set_exception(ConnectionResetError(f"Stream {stream_id} closed"))

        self._stream_authorities.pop(stream_id, None)
        ev = self._stream_window_events.pop(stream_id, None)
        if ev is not None:
            ev.set()

        if self._h2_conn is not None:
            try:
                self._h2_conn.reset_stream(stream_id, error_code=h2.errors.ErrorCodes.CANCEL)
                to_send = self._h2_conn.data_to_send()
                if to_send and self._tls_writer and not self._tls_writer.is_closing():
                    self._tls_writer.write(to_send)
            except (h2.exceptions.H2Error, KeyError):
                pass

        if stream_id in self._active_streams:
            self._active_streams.discard(stream_id)
            self._slot_available_event.set()

            if len(self._active_streams) == 0 and not self._accepting_new_streams:
                self.close()

    def close(self) -> None:
        """Close the upstream session, cancelling background tasks and sockets."""
        if self._closed:
            return
        self._closed = True
        self._closing = True
        self._accepting_new_streams = False

        if self._keepalive_task is not None and not self._keepalive_task.done():
            self._keepalive_task.cancel()
        if self._drain_task is not None and not self._drain_task.done():
            self._drain_task.cancel()
        if self._dispatch_task is not None and not self._dispatch_task.done():
            self._dispatch_task.cancel()

        for reader in list(self._stream_readers.values()):
            reader.feed_eof()
        for fut in list(self._stream_futures.values()):
            if not fut.done():
                fut.set_exception(ConnectionResetError("H2UpstreamSession closed"))
        for ev in list(self._stream_window_events.values()):
            ev.set()

        self._stream_readers.clear()
        self._stream_futures.clear()
        self._stream_authorities.clear()
        self._stream_window_events.clear()
        self._active_streams.clear()
        self._slot_available_event.set()

        if self._h2_conn is not None:
            try:
                self._h2_conn.close_connection()
                to_send = self._h2_conn.data_to_send()
                if to_send and self._tls_writer and not self._tls_writer.is_closing():
                    self._tls_writer.write(to_send)
            except Exception:
                pass

        if self._tls_writer is not None and not self._tls_writer.is_closing():
            try:
                self._tls_writer.close()
            except Exception:
                pass
