"""Proxy package for local SOCKS5 server, DoH resolver, and exit verifier."""

from foxyvpn.proxy.doh import (
    CLOUDFLARE_DOH,
    ENDPOINTS,
    GOOGLE_DOH,
    QUAD9_DOH,
    DohClient,
    build_wire_query,
    parse_json_response,
    parse_wire_response,
)
from foxyvpn.proxy.exit_check import ExitChecker, check_exit, parse_trace
from foxyvpn.proxy.socks5 import (
    LocalSocks5Server,
    SimpleTunneledStream,
    TunneledStream,
    UpstreamSession,
    make_socks5_reply,
)

__all__ = [
    "CLOUDFLARE_DOH",
    "DohClient",
    "ENDPOINTS",
    "ExitChecker",
    "GOOGLE_DOH",
    "LocalSocks5Server",
    "QUAD9_DOH",
    "SimpleTunneledStream",
    "TunneledStream",
    "UpstreamSession",
    "build_wire_query",
    "check_exit",
    "make_socks5_reply",
    "parse_json_response",
    "parse_trace",
    "parse_wire_response",
]
