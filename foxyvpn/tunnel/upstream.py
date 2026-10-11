"""Abstract upstream session interface and data structures for VPN tunneling."""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable


class ProxyType(str, Enum):
    """Supported upstream proxy protocol types."""

    SOCKS5 = "SOCKS5"
    HTTP = "HTTP"


@dataclass
class UpstreamProxyConfig:
    """Configuration for connecting through an upstream proxy."""

    type: ProxyType | str
    host: str
    port: int
    username: str | None = None
    password: str | None = None

    def __post_init__(self) -> None:
        if isinstance(self.type, str):
            self.type = ProxyType(self.type.upper())


class UpstreamConnectRejectedException(Exception):
    """Raised when the upstream proxy rejects a CONNECT request with a non-2xx status code."""

    def __init__(
        self,
        status_code: int | None,
        authority: str,
        message: str | None = None,
    ) -> None:
        self.status_code = status_code
        self.authority = authority
        super().__init__(
            message
            or f"Upstream rejected CONNECT to {authority}: status={status_code or '<missing>'}"
        )


class UpstreamConnectTimeoutException(Exception):
    """Raised when opening a stream or connecting to the upstream times out."""

    def __init__(
        self,
        authority: str,
        message: str | None = None,
        cause: Exception | None = None,
    ) -> None:
        self.authority = authority
        self.cause = cause
        super().__init__(message or f"Upstream CONNECT to {authority} timed out")


@dataclass
class TunneledStream:
    """An established bidirectional tunneled stream through the upstream session.

    Attributes:
        reader: Async stream reader to receive inbound data.
        writer: Async stream writer to send outbound data.
        close: Synchronous callback to close the stream.
    """

    reader: asyncio.StreamReader
    writer: Any
    close: Callable[[], None]


class UpstreamSession(ABC):
    """Abstract interface for managing an upstream tunneling session (e.g. HTTP/2)."""

    @abstractmethod
    async def connect(self) -> None:
        """Establish the underlying transport connection to the upstream server."""
        raise NotImplementedError

    @abstractmethod
    async def open_stream(self, target_host: str, target_port: int) -> TunneledStream:
        """Open a new bidirectional tunneled stream to target_host:target_port."""
        raise NotImplementedError

    @abstractmethod
    def update_bearer_token(self, token: str) -> None:
        """Update the bearer token used for authenticating subsequent streams."""
        raise NotImplementedError

    @abstractmethod
    def close(self) -> None:
        """Close the upstream session and all associated streams."""
        raise NotImplementedError

    @abstractmethod
    def disable_new_streams_and_close_when_idle(self) -> None:
        """Stop accepting new streams and close the session once active streams finish."""
        raise NotImplementedError

    @property
    @abstractmethod
    def is_connected(self) -> bool:
        """Return True if the upstream session is connected and accepting new streams."""
        raise NotImplementedError

    async def aclose(self) -> None:
        """Asynchronously close the upstream session."""
        self.close()

    async def __aenter__(self) -> UpstreamSession:
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.aclose()
