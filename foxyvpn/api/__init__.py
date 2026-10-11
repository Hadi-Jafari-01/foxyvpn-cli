"""API package for FoxyVPN."""

from foxyvpn.api.fastly import FastlyChallengeError, FastlyChallengeSolver
from foxyvpn.api.guardian import (
    GUARDIAN_ENDPOINT_DEFAULT,
    GuardianClient,
    GuardianError,
    GuardianHttpError,
    QuotaExceededError,
    TokenInvalidError,
    jwt_expiry_epoch_seconds,
)
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
from foxyvpn.api.ping import ping_candidates, ping_server
from foxyvpn.api.server_list import (
    RECOMMENDED_COUNTRY_CODE,
    REMOTE_SETTINGS_URL,
    ServerListClient,
    candidates_for_city,
    candidates_for_country,
    default_connect_target,
    get_recommended_candidate,
)

__all__ = [
    "GUARDIAN_ENDPOINT_DEFAULT",
    "RECOMMENDED_COUNTRY_CODE",
    "REMOTE_SETTINGS_URL",
    "ConnectionState",
    "Entitlement",
    "FastlyChallengeError",
    "FastlyChallengeSolver",
    "GuardianClient",
    "GuardianError",
    "GuardianHttpError",
    "LoginStepState",
    "ProxyCandidate",
    "ProxyPass",
    "QuotaExceededError",
    "RuntimeAuth",
    "ServerListClient",
    "TokenInvalidError",
    "VpnCity",
    "VpnCountry",
    "VpnProtocol",
    "VpnServerNode",
    "candidates_for_city",
    "candidates_for_country",
    "default_connect_target",
    "get_recommended_candidate",
    "jwt_expiry_epoch_seconds",
    "ping_candidates",
    "ping_server",
]
