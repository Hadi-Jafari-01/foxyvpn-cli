"""Firefox Accounts (FxA) Authentication Repository.

Handles FxA credentials authentication, two-factor verification,
token exchange, token refresh, and Fastly anti-bot challenge solving.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

import httpx

from foxyvpn.auth.challenge import FastlyChallengeSolver
from foxyvpn.auth.crypto import derive_auth_pw, derive_hawk_credentials
from foxyvpn.auth.hawk import generate_hawk_header
from foxyvpn.core.models import RuntimeAuth

FXA_AUTH_SERVER = "https://api.accounts.firefox.com/v1"
FIREFOX_CLIENT_ID = "5882386c6d801776"
OAUTH_SCOPE = "profile https://identity.mozilla.com/apps/vpn"
USER_AGENT = "MozillaVPN/2.35.0 (sys:linux; iap:true)"

VERIFICATION_METHOD_EMAIL_2FA = "email-2fa"
FXA_ERRNO_INVALID_PARAMETER = 107
FXA_MAX_CHALLENGE_ATTEMPTS = 5
DEFAULT_ACCESS_TOKEN_TTL_SECONDS = 24 * 60 * 60


class FxaApiError(Exception):
    """Raised when the Firefox Accounts API returns an error response."""

    def __init__(
        self,
        message: str,
        errno: int | None = None,
        status_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.errno = errno
        self.status_code = status_code


class FxaRefreshFailure(Exception):
    """Raised when token renewal fails."""

    def __init__(
        self,
        message: str,
        permanent: bool = False,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.permanent = permanent
        self.cause = cause


class FxaAuthRepository:
    """Manages Firefox Accounts authentication and session tokens."""

    def __init__(
        self,
        client: httpx.AsyncClient | None = None,
        challenge_solver: FastlyChallengeSolver | None = None,
        token_store: Any | None = None,
        auth_server: str = FXA_AUTH_SERVER,
        client_id: str = FIREFOX_CLIENT_ID,
        oauth_scope: str = OAUTH_SCOPE,
    ) -> None:
        self._external_client = client is not None
        self.client = client or httpx.AsyncClient(timeout=30.0, trust_env=False)
        self.challenge_solver = challenge_solver or FastlyChallengeSolver(cookies=self.client.cookies)
        self.token_store = token_store
        self.auth_server = auth_server
        self.client_id = client_id
        self.oauth_scope = oauth_scope
        self.pending_session_token: str | None = None

    async def __aenter__(self) -> FxaAuthRepository:
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()

    async def close(self) -> None:
        """Close the underlying HTTP client if internally created."""
        if not self._external_client:
            await self.client.aclose()

    async def fxa_do(
        self,
        method: str,
        path: str,
        session_token: str | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Perform an HTTP request against the FxA server with Hawk auth and challenge handling."""
        url = f"{self.auth_server}{path}"
        body_bytes = json.dumps(json_body or {}).encode("utf-8")

        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        token_id: str | None = None
        hmac_key: bytes | None = None
        if session_token is not None:
            token_id, hmac_key = derive_hawk_credentials(session_token)
            headers["Authorization"] = generate_hawk_header(method, url, token_id, hmac_key, body_bytes)

        response = await self.client.request(
            method=method,
            url=url,
            headers=headers,
            content=body_bytes,
        )

        attempts = 1
        while response.status_code == 406 and attempts < FXA_MAX_CHALLENGE_ATTEMPTS:
            await self.challenge_solver.solve_and_install(self.client)
            if session_token is not None and token_id is not None and hmac_key is not None:
                headers["Authorization"] = generate_hawk_header(method, url, token_id, hmac_key, body_bytes)
            response = await self.client.request(
                method=method,
                url=url,
                headers=headers,
                content=body_bytes,
            )
            attempts += 1

        if response.status_code >= 400:
            try:
                error_body = response.json()
            except Exception:
                error_body = {}
            errno = error_body.get("errno") if isinstance(error_body, dict) else None
            message = (
                error_body.get("message")
                if isinstance(error_body, dict) and error_body.get("message")
                else (response.text or f"HTTP {response.status_code}")
            )
            raise FxaApiError(message, errno=errno, status_code=response.status_code)

        if not response.text:
            return {}
        return response.json()

    async def _login_attempt(
        self,
        email: str,
        password: str,
        with_verification_method: bool = False,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "email": email,
            "authPW": derive_auth_pw(email, password),
        }
        if with_verification_method:
            body["verificationMethod"] = VERIFICATION_METHOD_EMAIL_2FA

        try:
            return await self.fxa_do("POST", "/account/login", json_body=body)
        except FxaApiError as e:
            if e.errno == FXA_ERRNO_INVALID_PARAMETER and with_verification_method:
                return await self._login_attempt(email, password, with_verification_method=False)
            raise

    async def login(
        self,
        email: str,
        password: str,
        force_verification_method: bool = False,
    ) -> tuple[bool, str | RuntimeAuth]:
        """Authenticate with email and password.

        Returns:
            (True, session_token) if 2FA code verification is required by the account.
            (False, RuntimeAuth) if sign-in is complete directly.
        """
        data = await self._login_attempt(
            email, password, with_verification_method=force_verification_method
        )
        session_token = data.get("sessionToken", "")
        self.pending_session_token = session_token
        self.verification_method = data.get("verificationMethod", "email-2fa")
        verified = bool(data.get("verified", False))

        if not verified:
            return True, session_token
        else:
            auth = await self._complete_login(session_token, email=email)
            return False, auth

    async def submit_2fa(self, session_token: str | None = None, code: str = "") -> RuntimeAuth:
        """Submit two-factor authentication code and complete login.

        Args:
            session_token: Pending session token (uses self.pending_session_token if omitted).
            code: 2FA verification code.

        Returns:
            RuntimeAuth credentials.
        """
        target_session = session_token or self.pending_session_token
        if not target_session:
            raise ValueError("No session token provided or pending. Start sign-in again.")

        await self.fxa_do(
            "POST",
            "/session/verify_code",
            session_token=target_session,
            json_body={"code": code},
        )
        return await self._complete_login(target_session)

    async def refresh_access_token(self, refresh_token: str) -> RuntimeAuth:
        """Renew the access token using a refresh token grant.

        Args:
            refresh_token: The OAuth refresh token.

        Returns:
            Renewed RuntimeAuth credentials.
        """
        body = {
            "client_id": self.client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": self.oauth_scope,
        }

        try:
            token_data = await self.fxa_do("POST", "/oauth/token", json_body=body)
        except FxaApiError as rejected:
            permanent = rejected.status_code in (400, 401, 403)
            raise FxaRefreshFailure(
                rejected.message or "FxA rejected the refresh token",
                permanent=permanent,
                cause=rejected,
            ) from rejected
        except Exception as transport:
            raise FxaRefreshFailure(
                str(transport) or "Could not reach the Firefox Accounts server",
                permanent=False,
                cause=transport,
            ) from transport

        access_token = token_data.get("access_token")
        if not access_token:
            raise FxaRefreshFailure(
                "FxA returned no access token for the refresh grant",
                permanent=False,
            )

        new_refresh_token = token_data.get("refresh_token") or refresh_token
        expires_at = self._expiry_from(token_data)
        renewed = RuntimeAuth(
            access_token=access_token,
            refresh_token=new_refresh_token,
            expires_at_epoch_seconds=expires_at,
        )
        if self.token_store is not None:
            try:
                self.token_store.save_auth(renewed)
            except Exception:
                pass
        return renewed

    async def ensure_fresh_access_token(self, force: bool = False) -> RuntimeAuth:
        """Ensure token store contains an unexpired access token, refreshing if needed."""
        if self.token_store is None:
            raise FxaRefreshFailure("No TokenStore configured", permanent=True)
        current = self.token_store.load_auth()
        if current is None:
            raise FxaRefreshFailure("Not signed in", permanent=True)
        if not force and self.token_store.has_valid_access_token():
            return current
        if not current.refresh_token:
            raise FxaRefreshFailure("The stored session has no refresh token; sign in again.", permanent=True)
        return await self.refresh_access_token(current.refresh_token)

    async def current_access_token(self) -> str | None:
        """Return a valid access token or None if sign-in is required."""
        try:
            auth = await self.ensure_fresh_access_token()
            return auth.access_token
        except Exception:
            return None

    async def restore_session(self) -> str:
        """Check and refresh stored session. Returns 'ACTIVE', 'NEEDS_LOGIN', or 'UNREACHABLE'."""
        if self.token_store is None:
            return "NEEDS_LOGIN"
        stored = self.token_store.load_auth()
        if stored is None:
            return "NEEDS_LOGIN"
        if not stored.refresh_token and not self.token_store.has_valid_access_token():
            self.token_store.clear()
            return "NEEDS_LOGIN"
        if self.token_store.has_valid_access_token():
            return "ACTIVE"
        try:
            await self.ensure_fresh_access_token()
            return "ACTIVE"
        except FxaRefreshFailure as failure:
            if failure.permanent:
                self.token_store.clear()
                return "NEEDS_LOGIN"
            return "UNREACHABLE"
        except Exception:
            return "UNREACHABLE"

    async def _complete_login(self, session_token: str, email: str | None = None) -> RuntimeAuth:
        token_data = await self._oauth_token(session_token)
        self.pending_session_token = None
        access_token = token_data.get("access_token", "")
        refresh_token = token_data.get("refresh_token") or None
        expires_at = self._expiry_from(token_data)
        auth = RuntimeAuth(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_at_epoch_seconds=expires_at,
            email=email,
        )
        if self.token_store is not None:
            try:
                self.token_store.save_auth(auth)
            except Exception:
                pass
        return auth

    async def _oauth_token(self, session_token: str) -> dict[str, Any]:
        body = {
            "client_id": self.client_id,
            "grant_type": "fxa-credentials",
            "scope": self.oauth_scope,
            "access_type": "offline",
        }
        return await self.fxa_do("POST", "/oauth/token", session_token=session_token, json_body=body)

    def _expiry_from(self, token_data: dict[str, Any]) -> int:
        expires_in = token_data.get("expires_in")
        ttl = int(expires_in) if expires_in and int(expires_in) > 0 else DEFAULT_ACCESS_TOKEN_TTL_SECONDS
        return int(time.time()) + ttl
