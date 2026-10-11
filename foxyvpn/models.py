"""Root re-export of FoxyVPN data models."""

from foxyvpn.api.models import (
    ConnectionState,
    Entitlement,
    LoginStepState,
    ProxyCandidate,
    ProxyPass,
    RuntimeAuth,
    VpnCity,
    VpnCountry,
    VpnProtocol,
    VpnServerNode,
)

__all__ = [
    "ConnectionState",
    "Entitlement",
    "LoginStepState",
    "ProxyCandidate",
    "ProxyPass",
    "RuntimeAuth",
    "VpnCity",
    "VpnCountry",
    "VpnProtocol",
    "VpnServerNode",
]
