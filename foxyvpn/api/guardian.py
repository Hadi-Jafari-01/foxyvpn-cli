"""Mozilla Guardian API client implementation."""

from __future__ import annotations

import base64
import inspect
import json
import logging
from typing import Any

import httpx

from foxyvpn.api.fastly import FastlyChallengeError, FastlyChallengeSolver
from foxyvpn.api.models import Entitlement, ProxyPass

logger = logging.getLogger(__name__)

GUARDIAN_ENDPOINT_DEFAULT = "https://vpn.mozilla.org"
MOZILLA_VPN_USER_AGENT = "MozillaVPN/2.35.0 (sys:linux; iap:true)"
ACCEPT_HEADER = "application/json"


class GuardianError(Exception):
    """Base exception for Guardian API errors."""
    pass


class GuardianHttpError(GuardianError):
    """Raised when Guardian API returns an HTTP error."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.statusCode = status_code


class TokenInvalidError(GuardianHttpError):
    """Raised when access token was rejected by Guardian (HTTP 401 or 403)."""

    def __init__(
        self,
        message: str = "access token was rejected by Guardian",
        status_code: int = 401,
    ) -> None:
        super().__init__(message, status_code)


class QuotaExceededError(GuardianHttpError):
    """Raised when account proxy quota is exceeded (HTTP 429)."""

    def __init__(
        self,
        message: str = "account proxy quota exceeded",
        status_code: int = 429,
    ) -> None:
        super().__init__(message, status_code)


def jwt_expiry_epoch_seconds(token: str) -> int | None:
    """
    Extract the exp claim from a JWT payload as epoch seconds.
    Returns None if missing, malformed, or non-positive.
    """
    if not token or not isinstance(token, str):
        return None
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        payload_b64 = parts[1]
        remainder = len(payload_b64) % 4
        if remainder != 0:
            payload_b64 += "=" * (4 - remainder)
        payload_bytes = base64.urlsafe_b64decode(payload_b64.encode("ascii"))
        payload_json = json.loads(payload_bytes.decode("utf-8"))
        exp = payload_json.get("exp")
        if exp is not None:
            exp_int = int(exp)
            if exp_int > 0:
                return exp_int
        return None
    except Exception:
        return None


class GuardianClient:
    """Client for Mozilla Guardian VPN API."""

    def __init__(
        self,
        client: httpx.AsyncClient | None = None,
        challenge_solver: Any | None = None,
    ) -> None:
        self._client = client
        self._owns_client = client is None
        self.challenge_solver = challenge_solver

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                follow_redirects=True,
                timeout=30.0,
                trust_env=False,
            )
            self._owns_client = True
        return self._client

    async def close(self) -> None:
        if self._owns_client and self._client is not None and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> GuardianClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    def _normalize_args(self, access_token: str, endpoint: str) -> tuple[str, str]:
        """Support both (token, endpoint) and (endpoint, token) positional calls."""
        if access_token.startswith(("http://", "https://")) and not endpoint.startswith(("http://", "https://")):
            return endpoint, access_token
        return access_token, endpoint

    async def _send_single_request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        access_token: str,
    ) -> httpx.Response:
        headers = {
            "User-Agent": MOZILLA_VPN_USER_AGENT,
            "Accept": ACCEPT_HEADER,
            "Content-Type": "application/json",
            "Authorization": f"Bearer {access_token}",
        }
        if method.upper() == "POST":
            return await client.post(url, headers=headers, content=b"")
        return await client.get(url, headers=headers)

    async def _authorized_request(
        self,
        method: str,
        url: str,
        access_token: str,
    ) -> httpx.Response:
        client = await self._get_client()
        resp = await self._send_single_request(client, method, url, access_token)

        if resp.status_code == 406 and self.challenge_solver is not None:
            solver_fn = getattr(self.challenge_solver, "solve_and_install", None)
            if callable(solver_fn):
                try:
                    res = solver_fn(client=client)
                except TypeError:
                    res = solver_fn()
                if inspect.isawaitable(res):
                    await res
            elif callable(self.challenge_solver):
                res = self.challenge_solver(client)
                if inspect.isawaitable(res):
                    await res

            # Retry request once after solving challenge
            resp = await self._send_single_request(client, method, url, access_token)

        return resp

    async def fetch_proxy_pass(
        self,
        access_token: str,
        endpoint: str = GUARDIAN_ENDPOINT_DEFAULT,
    ) -> ProxyPass:
        """
        Fetch proxy authentication token from Guardian API.
        GET /api/v1/fpn/token
        """
        access_token, endpoint = self._normalize_args(access_token, endpoint)
        url = f"{endpoint.rstrip('/')}/api/v1/fpn/token"
        resp = await self._authorized_request("GET", url, access_token)

        # Handle unactivated accounts: Guardian returns 401/403 until /activate is called
        if resp.status_code in (401, 403):
            logger.info("Proxy pass returned HTTP %d. Attempting Guardian entitlement activation...", resp.status_code)
            try:
                await self.activate_guardian(access_token, endpoint)
                resp = await self._authorized_request("GET", url, access_token)
            except Exception as act_err:
                logger.debug("Guardian auto-activation attempt failed: %s", act_err)

        if resp.status_code in (401, 403):
            detail = resp.text.strip()[:300] if resp.text else ""
            msg = f"access token was rejected by Guardian (HTTP {resp.status_code}: {detail})" if detail else "access token was rejected by Guardian"
            raise TokenInvalidError(msg, resp.status_code)
        if resp.status_code == 429:
            raise QuotaExceededError("account proxy quota exceeded", resp.status_code)
        if resp.status_code != 200:
            raise GuardianHttpError(
                f"failed to fetch proxy pass: HTTP {resp.status_code}: {resp.text[:2048]}",
                resp.status_code,
            )

        try:
            body = resp.json()
        except Exception as exc:
            raise GuardianHttpError(
                f"failed to parse proxy pass JSON response: {exc}",
                resp.status_code,
            ) from exc

        token = body.get("token")
        if not token:
            raise GuardianHttpError("proxy pass response did not contain a token", resp.status_code)

        expires_at_val = body.get("expires_at")
        expires_at: int | None = None
        if expires_at_val is not None:
            try:
                parsed_exp = int(expires_at_val)
                if parsed_exp > 0:
                    expires_at = parsed_exp
            except (ValueError, TypeError):
                expires_at = None

        if expires_at is None:
            expires_at = jwt_expiry_epoch_seconds(token)

        def _header_int(key: str) -> int | None:
            val = resp.headers.get(key)
            if val is not None:
                try:
                    return int(val)
                except (ValueError, TypeError):
                    return None
            return None

        quota_max = _header_int("X-Quota-Limit")
        quota_remaining = _header_int("X-Quota-Remaining")
        quota_reset = _header_int("X-Quota-Reset")

        return ProxyPass(
            token=token,
            expires_at_epoch_seconds=expires_at,
            quota_max=quota_max,
            quota_remaining=quota_remaining,
            quota_reset=quota_reset,
        )

    async def fetch_user_info(
        self,
        access_token: str,
        endpoint: str = GUARDIAN_ENDPOINT_DEFAULT,
    ) -> Entitlement:
        """
        Fetch account entitlement info from Guardian API.
        GET /api/v1/fpn/status
        If limited_bandwidth is true, also fetches ProxyPass to populate quota_remaining.
        """
        access_token, endpoint = self._normalize_args(access_token, endpoint)
        url = f"{endpoint.rstrip('/')}/api/v1/fpn/status"
        resp = await self._authorized_request("GET", url, access_token)

        # Handle unactivated accounts on status endpoint
        if resp.status_code in (401, 403):
            try:
                await self.activate_guardian(access_token, endpoint)
                resp = await self._authorized_request("GET", url, access_token)
            except Exception:
                pass

        if resp.status_code in (401, 403):
            detail = resp.text.strip()[:300] if resp.text else ""
            msg = f"access token was rejected by Guardian (HTTP {resp.status_code}: {detail})" if detail else "access token was rejected by Guardian"
            raise TokenInvalidError(msg, resp.status_code)
        if resp.status_code == 429:
            raise QuotaExceededError("account proxy quota exceeded", resp.status_code)
        if resp.status_code != 200:
            raise GuardianHttpError(
                f"failed to fetch account info: HTTP {resp.status_code}: {resp.text[:2048]}",
                resp.status_code,
            )

        try:
            body = resp.json()
        except Exception as exc:
            raise GuardianHttpError(
                f"failed to parse account info JSON response: {exc}",
                resp.status_code,
            ) from exc

        entitlement = self._parse_entitlement(body)

        if entitlement.limited_bandwidth:
            try:
                pass_data = await self.fetch_proxy_pass(access_token, endpoint)
                if pass_data.quota_remaining is not None:
                    entitlement.quota_remaining = pass_data.quota_remaining
            except Exception:
                pass

        return entitlement

    async def activate_guardian(
        self,
        access_token: str,
        endpoint: str = GUARDIAN_ENDPOINT_DEFAULT,
    ) -> Entitlement:
        """
        Activate Guardian entitlement for account.
        POST /api/v1/fpn/activate
        """
        access_token, endpoint = self._normalize_args(access_token, endpoint)
        url = f"{endpoint.rstrip('/')}/api/v1/fpn/activate"
        resp = await self._authorized_request("POST", url, access_token)

        if resp.status_code in (401, 403):
            raise TokenInvalidError("access token was rejected by Guardian", resp.status_code)
        if resp.status_code == 429:
            raise QuotaExceededError("account proxy quota exceeded", resp.status_code)
        if resp.status_code != 200:
            raise GuardianHttpError(
                f"failed to activate guardian entitlement: HTTP {resp.status_code}: {resp.text[:2048]}",
                resp.status_code,
            )

        try:
            body = resp.json()
        except Exception as exc:
            raise GuardianHttpError(
                f"failed to parse activate JSON response: {exc}",
                resp.status_code,
            ) from exc

        return self._parse_entitlement(body)

    @staticmethod
    def _parse_entitlement(body: dict[str, Any]) -> Entitlement:
        subscribed = bool(body.get("subscribed", False))
        uid = str(body.get("uid", ""))

        max_bytes_val = body.get("maxBytes")
        if max_bytes_val is None:
            max_bytes_val = body.get("max_bytes")

        max_bytes: int | None = None
        if max_bytes_val is not None:
            try:
                parsed = int(max_bytes_val)
                if parsed >= 0:
                    max_bytes = parsed
            except (ValueError, TypeError):
                max_bytes = None

        limited_bandwidth = bool(
            body.get("limited_bandwidth", body.get("limitedBandwidth", False))
        )

        return Entitlement(
            subscribed=subscribed,
            uid=uid,
            max_bytes=max_bytes,
            limited_bandwidth=limited_bandwidth,
        )
