"""Firefox Accounts authentication package."""

from foxyvpn.auth.challenge import (
    FastlyChallengeError,
    FastlyChallengeSolver,
    solve_pow,
)
from foxyvpn.auth.crypto import (
    PROTOCOL_VERSION,
    derive_auth_pw,
    derive_hawk_credentials,
    derive_quick_stretch,
)
from foxyvpn.auth.fxa import (
    FIREFOX_CLIENT_ID,
    FXA_AUTH_SERVER,
    OAUTH_SCOPE,
    USER_AGENT,
    FxaApiError,
    FxaAuthRepository,
    FxaRefreshFailure,
    RuntimeAuth,
)
from foxyvpn.auth.hawk import (
    generate_hawk_header,
    parse_hawk_header,
    verify_hawk_header,
)

__all__ = [
    "PROTOCOL_VERSION",
    "derive_quick_stretch",
    "derive_auth_pw",
    "derive_hawk_credentials",
    "generate_hawk_header",
    "parse_hawk_header",
    "verify_hawk_header",
    "FastlyChallengeSolver",
    "FastlyChallengeError",
    "solve_pow",
    "FxaAuthRepository",
    "RuntimeAuth",
    "FxaApiError",
    "FxaRefreshFailure",
    "FXA_AUTH_SERVER",
    "FIREFOX_CLIENT_ID",
    "OAUTH_SCOPE",
    "USER_AGENT",
]
