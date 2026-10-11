"""Firefox Accounts (FxA) cryptographic key derivation.

Implements PICL v1 key derivation (PBKDF2-HMAC-SHA256 and HKDF-SHA256)
for Firefox Accounts authentication and Hawk credentials.
"""

from __future__ import annotations

import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PROTOCOL_VERSION = "identity.mozilla.com/picl/v1/"
PBKDF2_ROUNDS = 1000
STRETCHED_PW_LEN = 32
HKDF_LEN = 32


def derive_quick_stretch(email: str, password: str) -> bytes:
    """Derive quickStretch key using PBKDF2-HMAC-SHA256.

    Salt: (PROTOCOL_VERSION + "quickStretch:" + email).encode('utf-8')
    Iterations: 1000
    Length: 32 bytes
    """
    salt = f"{PROTOCOL_VERSION}quickStretch:{email}".encode("utf-8")
    password_bytes = password.encode("utf-8")
    return hashlib.pbkdf2_hmac(
        "sha256",
        password_bytes,
        salt,
        PBKDF2_ROUNDS,
        dklen=STRETCHED_PW_LEN,
    )


def derive_auth_pw(email: str, password: str) -> str:
    """Derive authPW hex string using HKDF-SHA256 from quick_stretch.

    IKM: quick_stretch (32 bytes)
    Salt: 32 zero bytes
    Info: (PROTOCOL_VERSION + "authPW").encode('utf-8')
    Length: 32 bytes
    Returns: hex-encoded string (64 characters)
    """
    quick_stretch = derive_quick_stretch(email, password)
    info = f"{PROTOCOL_VERSION}authPW".encode("utf-8")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=HKDF_LEN,
        salt=b"\x00" * 32,
        info=info,
    )
    derived = hkdf.derive(quick_stretch)
    return derived.hex()


def derive_hawk_credentials(session_token_hex: str) -> tuple[str, bytes]:
    """Derive Hawk token_id and hmac_key from session token hex string.

    IKM: bytes.fromhex(session_token_hex)
    Salt: 32 zero bytes
    Info: (PROTOCOL_VERSION + "sessionToken").encode('utf-8')
    Length: 64 bytes
    Returns: (token_id_hex: str, hmac_key_bytes: bytes)
    """
    session_token_bytes = bytes.fromhex(session_token_hex)
    info = f"{PROTOCOL_VERSION}sessionToken".encode("utf-8")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=b"\x00" * 32,
        info=info,
    )
    expanded = hkdf.derive(session_token_bytes)
    token_id = expanded[:32].hex()
    hmac_key = expanded[32:64]
    return token_id, hmac_key
