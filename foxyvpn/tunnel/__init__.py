"""VPN upstream tunneling modules and protocols."""

from foxyvpn.tunnel.h2_session import (
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

__all__ = [
    "H2UpstreamSession",
    "TunneledStreamWriter",
    "ProxyType",
    "TunneledStream",
    "UpstreamConnectRejectedException",
    "UpstreamConnectTimeoutException",
    "UpstreamProxyConfig",
    "UpstreamSession",
]
