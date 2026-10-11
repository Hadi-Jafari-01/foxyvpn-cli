"""Local SOCKS5 proxy server implementation.

RFC 1928 compliant SOCKS5 server that bridges local clients to upstream
tunnel sessions with bi-directional streaming and traffic stats monitoring.
"""

from __future__ import annotations

import asyncio
import inspect
import ipaddress
import logging
import socket
import struct
from collections.abc import Callable
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)

# SOCKS5 Protocol Constants (RFC 1928)
SOCKS5_VERSION = 0x05

# Authentication methods
AUTH_NO_AUTH = 0x00
AUTH_NO_ACCEPTABLE = 0xFF

# Commands
CMD_CONNECT = 0x01
CMD_BIND = 0x02
CMD_UDP_ASSOCIATE = 0x03

# Address types
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

# Reply codes
REP_SUCCESS = 0x00
REP_GENERAL_FAILURE = 0x01
REP_CONNECTION_NOT_ALLOWED = 0x02
REP_NETWORK_UNREACHABLE = 0x03
REP_HOST_UNREACHABLE = 0x04
REP_CONNECTION_REFUSED = 0x05
REP_TTL_EXPIRED = 0x06
REP_CMD_NOT_SUPPORTED = 0x07
REP_ATYP_NOT_SUPPORTED = 0x08

BUFFER_SIZE = 32 * 1024


@runtime_checkable
class TunneledStream(Protocol):
    """Protocol for an active upstream tunneled stream."""

    reader: Any
    writer: Any

    async def close(self) -> None:
        """Close the tunneled stream."""
        ...


class SimpleTunneledStream:
    """Concrete wrapper for a tunneled stream with reader/writer."""

    def __init__(
        self,
        reader: Any,
        writer: Any,
        close_func: Callable[[], Any] | None = None,
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.close_func = close_func

    async def close(self) -> None:
        if self.close_func is not None:
            res = self.close_func()
            if inspect.isawaitable(res):
                await res
        elif hasattr(self.writer, "close"):
            try:
                self.writer.close()
                if hasattr(self.writer, "wait_closed"):
                    await self.writer.wait_closed()
            except Exception:
                pass


@runtime_checkable
class UpstreamSession(Protocol):
    """Protocol for an upstream VPN tunnel session."""

    async def open_stream(self, target_host: str, target_port: int) -> TunneledStream:
        """Open a multiplexed or tunneled stream to target_host:target_port."""
        ...


def make_socks5_reply(
    reply_code: int,
    bind_ip: str = "0.0.0.0",
    bind_port: int = 0,
) -> bytes:
    """Build a standard SOCKS5 reply message."""
    try:
        ip_obj = ipaddress.ip_address(bind_ip)
        if ip_obj.version == 6:
            atyp = ATYP_IPV6
            addr_bytes = ip_obj.packed
        else:
            atyp = ATYP_IPV4
            addr_bytes = ip_obj.packed
    except ValueError:
        atyp = ATYP_IPV4
        addr_bytes = b"\x00\x00\x00\x00"

    port_bytes = struct.pack("!H", bind_port)
    return bytes([SOCKS5_VERSION, reply_code, 0x00, atyp]) + addr_bytes + port_bytes


class CallableInt(int):
    """An integer that can also be called as a zero-argument function returning itself."""

    def __call__(self) -> int:
        return int(self)


class LocalSocks5Server:
    """Local SOCKS5 proxy server.

    Accepts inbound SOCKS5 connections from local applications, parses
    greeting and request messages (CONNECT), dials destinations via the
    active UpstreamSession, and pipes bidirectional traffic while tracking
    sent/received byte statistics.
    """

    def __init__(
        self,
        bind_address: str = "127.0.0.1",
        port: int = 10808,
        session_provider: Callable[[], UpstreamSession | None] | None = None,
        on_stats_update: Callable[[int, int], None] | None = None,
        upstream_session: UpstreamSession | None = None,
        bind_host: str | None = None,
    ) -> None:
        self.bind_address = bind_host or bind_address
        self.port = port
        if session_provider is not None:
            self.session_provider = session_provider
        elif upstream_session is not None:
            self.session_provider = lambda: upstream_session
        else:
            self.session_provider = lambda: None
        self.on_stats_update = on_stats_update

        self._server: asyncio.Server | None = None
        self._active_tasks: set[asyncio.Task[Any]] = set()
        self._bytes_sent: int = 0
        self._bytes_received: int = 0
        self._is_closing: bool = False

    @property
    def is_running(self) -> bool:
        """True if the server is actively listening for connections."""
        return self._server is not None and self._server.is_serving()

    @property
    def bytes_sent(self) -> int:
        """Cumulative total bytes relayed from client to upstream."""
        return self._bytes_sent

    @property
    def bytes_received(self) -> int:
        """Cumulative total bytes relayed from upstream to client."""
        return self._bytes_received

    @property
    def total_bytes_sent(self) -> CallableInt:
        """Alias for bytes_sent (can be accessed as int or called as func)."""
        return CallableInt(self._bytes_sent)

    @property
    def total_bytes_received(self) -> CallableInt:
        """Alias for bytes_received (can be accessed as int or called as func)."""
        return CallableInt(self._bytes_received)

    async def start(self) -> None:
        """Start listening on the configured bind_address and port."""
        self._is_closing = False
        self._server = await asyncio.start_server(
            self._on_client_connected,
            host=self.bind_address,
            port=self.port,
        )
        # Update port in case port 0 was passed for dynamic allocation
        if self._server.sockets:
            sock_name = self._server.sockets[0].getsockname()
            self.port = sock_name[1]
        logger.info("LocalSocks5Server listening on %s:%d", self.bind_address, self.port)

    async def stop(self) -> None:
        """Stop listening and cleanly terminate all active client connections."""
        self._is_closing = True
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        # Cancel remaining active connection tasks
        for task in list(self._active_tasks):
            task.cancel()
        if self._active_tasks:
            await asyncio.gather(*self._active_tasks, return_exceptions=True)
        self._active_tasks.clear()
        logger.info("LocalSocks5Server stopped")

    async def __aenter__(self) -> LocalSocks5Server:
        await self.start()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.stop()

    def _on_client_connected(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        task = asyncio.create_task(self._handle_client(client_reader, client_writer))
        self._active_tasks.add(task)
        task.add_done_callback(self._active_tasks.discard)

    async def _handle_client(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        tunneled_stream: Any = None
        try:
            # 1. Greeting Handshake
            # Client sends: VER (1B) + NMETHODS (1B) + METHODS (NMETHODS B)
            try:
                header = await client_reader.readexactly(2)
            except (asyncio.IncompleteReadError, ConnectionResetError):
                return

            ver, nmethods = header[0], header[1]
            if ver != SOCKS5_VERSION:
                logger.debug("Unsupported SOCKS version: %s", ver)
                client_writer.write(bytes([SOCKS5_VERSION, AUTH_NO_ACCEPTABLE]))
                await client_writer.drain()
                return

            try:
                methods = await client_reader.readexactly(nmethods)
            except (asyncio.IncompleteReadError, ConnectionResetError):
                return

            if AUTH_NO_AUTH not in methods:
                logger.debug("No supported auth method in %s", methods)
                client_writer.write(bytes([SOCKS5_VERSION, AUTH_NO_ACCEPTABLE]))
                await client_writer.drain()
                return

            # Respond with NO AUTH
            client_writer.write(bytes([SOCKS5_VERSION, AUTH_NO_AUTH]))
            await client_writer.drain()

            # 2. Request Handshake
            # Client sends: VER (1B) + CMD (1B) + RSV (1B) + ATYP (1B)
            try:
                req_hdr = await client_reader.readexactly(4)
            except (asyncio.IncompleteReadError, ConnectionResetError):
                return

            req_ver, cmd, _rsv, atyp = req_hdr[0], req_hdr[1], req_hdr[2], req_hdr[3]
            if req_ver != SOCKS5_VERSION:
                client_writer.write(make_socks5_reply(REP_GENERAL_FAILURE))
                await client_writer.drain()
                return

            if cmd != CMD_CONNECT:
                logger.debug("Unsupported SOCKS5 command: 0x%02x", cmd)
                client_writer.write(make_socks5_reply(REP_CMD_NOT_SUPPORTED))
                await client_writer.drain()
                return

            # Parse target host based on ATYP
            if atyp == ATYP_IPV4:
                try:
                    raw_ip = await client_reader.readexactly(4)
                except (asyncio.IncompleteReadError, ConnectionResetError):
                    return
                target_host = socket.inet_ntoa(raw_ip)
            elif atyp == ATYP_DOMAIN:
                try:
                    len_byte = await client_reader.readexactly(1)
                    domain_len = len_byte[0]
                    if domain_len == 0:
                        client_writer.write(make_socks5_reply(REP_ATYP_NOT_SUPPORTED))
                        await client_writer.drain()
                        return
                    domain_bytes = await client_reader.readexactly(domain_len)
                except (asyncio.IncompleteReadError, ConnectionResetError):
                    return
                try:
                    target_host = domain_bytes.decode("idna")
                except Exception:
                    target_host = domain_bytes.decode("utf-8", errors="replace")
            elif atyp == ATYP_IPV6:
                try:
                    raw_ip = await client_reader.readexactly(16)
                except (asyncio.IncompleteReadError, ConnectionResetError):
                    return
                target_host = socket.inet_ntop(socket.AF_INET6, raw_ip)
            else:
                logger.debug("Unsupported ATYP: 0x%02x", atyp)
                client_writer.write(make_socks5_reply(REP_ATYP_NOT_SUPPORTED))
                await client_writer.drain()
                return

            # Read 2 bytes port (big-endian)
            try:
                port_bytes = await client_reader.readexactly(2)
            except (asyncio.IncompleteReadError, ConnectionResetError):
                return
            target_port = struct.unpack("!H", port_bytes)[0]

            logger.debug("SOCKS5 CONNECT request for %s:%d", target_host, target_port)

            # 3. Obtain Upstream Session & Open Stream
            upstream_session = self.session_provider()
            if upstream_session is None or (
                hasattr(upstream_session, "is_connected") and not upstream_session.is_connected
            ):
                logger.debug("No active upstream session available for %s:%d", target_host, target_port)
                client_writer.write(make_socks5_reply(REP_CONNECTION_REFUSED))
                await client_writer.drain()
                return

            try:
                stream_res = upstream_session.open_stream(target_host, target_port)
                if inspect.isawaitable(stream_res):
                    tunneled_stream = await stream_res
                else:
                    tunneled_stream = stream_res
            except Exception as exc:
                err_str = str(exc).lower()
                is_unreachable = (
                    isinstance(exc, (TimeoutError, asyncio.TimeoutError))
                    or "timeout" in err_str
                    or "unreachable" in err_str
                    or "timed out" in err_str
                )
                rep = REP_HOST_UNREACHABLE if is_unreachable else REP_CONNECTION_REFUSED
                logger.debug(
                    "Opening upstream stream to %s:%d failed (%s), replying 0x%02x",
                    target_host,
                    target_port,
                    exc,
                    rep,
                )
                client_writer.write(make_socks5_reply(rep))
                await client_writer.drain()
                return

            if tunneled_stream is None:
                client_writer.write(make_socks5_reply(REP_CONNECTION_REFUSED))
                await client_writer.drain()
                return

            # Send Success response (0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0)
            client_writer.write(make_socks5_reply(REP_SUCCESS))
            await client_writer.drain()

            # 4. Bi-directional relay loop
            await self._relay_loop(client_reader, client_writer, tunneled_stream)

        except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as exc:
            logger.debug("Unexpected error handling SOCKS5 client: %s", exc)
        finally:
            # Clean shutdown of tunneled stream and client writer
            if tunneled_stream is not None:
                await self._close_stream(tunneled_stream)
            try:
                client_writer.close()
                await client_writer.wait_closed()
            except Exception:
                pass

    async def _relay_loop(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        tunneled_stream: Any,
    ) -> None:
        """Concurrently pipe client -> upstream and upstream -> client."""
        upstream_reader = getattr(tunneled_stream, "reader", tunneled_stream)
        upstream_writer = getattr(tunneled_stream, "writer", tunneled_stream)

        async def pipe(reader: Any, writer: Any, is_upload: bool) -> None:
            try:
                while not self._is_closing:
                    if hasattr(reader, "read"):
                        res = reader.read(BUFFER_SIZE)
                        chunk = await res if inspect.isawaitable(res) else res
                    else:
                        break

                    if not chunk:
                        # EOF from reader
                        if hasattr(writer, "write_eof"):
                            try:
                                writer.write_eof()
                            except Exception:
                                pass
                        break

                    if hasattr(writer, "write"):
                        w_res = writer.write(chunk)
                        if inspect.isawaitable(w_res):
                            await w_res
                    if hasattr(writer, "drain"):
                        d_res = writer.drain()
                        if inspect.isawaitable(d_res):
                            await d_res

                    length = len(chunk)
                    if is_upload:
                        self._bytes_sent += length
                    else:
                        self._bytes_received += length

                    if self.on_stats_update is not None:
                        try:
                            stat_res = self.on_stats_update(self._bytes_sent, self._bytes_received)
                            if inspect.isawaitable(stat_res):
                                await stat_res
                        except Exception:
                            pass
            except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
                pass
            except Exception as e:
                logger.debug("Pipe error (%s): %s", "upload" if is_upload else "download", e)

        client_to_upstream = asyncio.create_task(pipe(client_reader, upstream_writer, True))
        upstream_to_client = asyncio.create_task(pipe(upstream_reader, client_writer, False))

        done, pending = await asyncio.wait(
            [client_to_upstream, upstream_to_client],
            return_when=asyncio.FIRST_COMPLETED,
        )

        for task in pending:
            if not task.done():
                task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    async def _close_stream(self, stream: Any) -> None:
        """Safely close any stream representation."""
        if hasattr(stream, "close"):
            try:
                res = stream.close()
                if inspect.isawaitable(res):
                    await res
            except Exception:
                pass
        writer = getattr(stream, "writer", None)
        if writer is not None and hasattr(writer, "close"):
            try:
                w_res = writer.close()
                if inspect.isawaitable(w_res):
                    await w_res
                if hasattr(writer, "wait_closed"):
                    await writer.wait_closed()
            except Exception:
                pass
