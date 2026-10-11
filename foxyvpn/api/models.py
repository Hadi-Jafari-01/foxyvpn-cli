"""Data models for FoxyVPN API and server list."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ConnectionState(str, Enum):
    DISCONNECTED = "DISCONNECTED"
    CONNECTING = "CONNECTING"
    CONNECTED = "CONNECTED"


class LoginStepState(str, Enum):
    CREDENTIALS = "CREDENTIALS"
    TWO_FACTOR = "TWO_FACTOR"


@dataclass
class VpnProtocol:
    name: str
    host: str = ""
    port: int = 0
    scheme: str = ""
    template_string: str = ""

    def __init__(
        self,
        name: str,
        host: str = "",
        port: int = 0,
        scheme: str = "",
        template_string: str = "",
        templateString: str | None = None,
    ) -> None:
        self.name = name
        self.host = host
        self.port = port
        self.scheme = scheme
        self.template_string = templateString if templateString is not None else template_string

    @property
    def templateString(self) -> str:
        return self.template_string


@dataclass
class VpnServerNode:
    hostname: str
    port: int = 0
    quarantined: bool = False
    protocols: list[VpnProtocol] = field(default_factory=list)


@dataclass
class VpnCity:
    name: str
    code: str
    servers: list[VpnServerNode] = field(default_factory=list)


@dataclass
class VpnCountry:
    name: str
    code: str
    cities: list[VpnCity] = field(default_factory=list)


@dataclass
class ProxyCandidate:
    host: str
    port: int
    country_code: str = ""
    country_name: str = ""
    city_code: str = ""
    ping_ms: float | None = None

    def __init__(
        self,
        host: str,
        port: int,
        country_code: str = "",
        country_name: str = "",
        city_code: str = "",
        ping_ms: float | None = None,
        countryCode: str | None = None,
        countryName: str | None = None,
        cityCode: str | None = None,
        pingMs: float | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.country_code = countryCode if countryCode is not None else country_code
        self.country_name = countryName if countryName is not None else country_name
        self.city_code = cityCode if cityCode is not None else city_code
        self.ping_ms = pingMs if pingMs is not None else ping_ms

    @property
    def authority(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def countryCode(self) -> str:
        return self.country_code

    @property
    def countryName(self) -> str:
        return self.country_name

    @property
    def cityCode(self) -> str:
        return self.city_code

    @property
    def pingMs(self) -> float | None:
        return self.ping_ms


@dataclass
class ProxyPass:
    token: str
    expires_at_epoch_seconds: int | None = None
    quota_max: int | None = None
    quota_remaining: int | None = None
    quota_reset: int | None = None

    def __init__(
        self,
        token: str,
        expires_at_epoch_seconds: int | None = None,
        quota_max: int | None = None,
        quota_remaining: int | None = None,
        quota_reset: int | None = None,
        expiresAtEpochSeconds: int | None = None,
        quotaMax: int | None = None,
        quotaRemaining: int | None = None,
        quotaReset: int | None = None,
    ) -> None:
        self.token = token
        self.expires_at_epoch_seconds = (
            expiresAtEpochSeconds if expiresAtEpochSeconds is not None else expires_at_epoch_seconds
        )
        self.quota_max = quotaMax if quotaMax is not None else quota_max
        self.quota_remaining = quotaRemaining if quotaRemaining is not None else quota_remaining
        self.quota_reset = quotaReset if quotaReset is not None else quota_reset

    @property
    def expiresAtEpochSeconds(self) -> int | None:
        return self.expires_at_epoch_seconds

    @property
    def quotaMax(self) -> int | None:
        return self.quota_max

    @property
    def quotaRemaining(self) -> int | None:
        return self.quota_remaining

    @property
    def quotaReset(self) -> int | None:
        return self.quota_reset


@dataclass
class Entitlement:
    subscribed: bool
    uid: str
    max_bytes: int | None = None
    limited_bandwidth: bool = False
    quota_remaining: int | None = None

    def __init__(
        self,
        subscribed: bool,
        uid: str,
        max_bytes: int | None = None,
        limited_bandwidth: bool = False,
        quota_remaining: int | None = None,
        maxBytes: int | None = None,
        limitedBandwidth: bool | None = None,
        quotaRemaining: int | None = None,
    ) -> None:
        self.subscribed = subscribed
        self.uid = uid
        self.max_bytes = maxBytes if maxBytes is not None else max_bytes
        self.limited_bandwidth = limitedBandwidth if limitedBandwidth is not None else limited_bandwidth
        self.quota_remaining = quotaRemaining if quotaRemaining is not None else quota_remaining

    @property
    def maxBytes(self) -> int | None:
        return self.max_bytes

    @property
    def limitedBandwidth(self) -> bool:
        return self.limited_bandwidth

    @property
    def quotaRemaining(self) -> int | None:
        return self.quota_remaining


@dataclass
class RuntimeAuth:
    access_token: str
    refresh_token: str | None = None
    expires_at_epoch_seconds: int = 0

    def __init__(
        self,
        access_token: str,
        refresh_token: str | None = None,
        expires_at_epoch_seconds: int = 0,
        accessToken: str | None = None,
        refreshToken: str | None = None,
        expiresAtEpochSeconds: int | None = None,
    ) -> None:
        self.access_token = accessToken if accessToken is not None else access_token
        self.refresh_token = refreshToken if refreshToken is not None else refresh_token
        self.expires_at_epoch_seconds = (
            expiresAtEpochSeconds if expiresAtEpochSeconds is not None else expires_at_epoch_seconds
        )

    @property
    def accessToken(self) -> str:
        return self.access_token

    @property
    def refreshToken(self) -> str | None:
        return self.refresh_token

    @property
    def expiresAtEpochSeconds(self) -> int:
        return self.expires_at_epoch_seconds

    def is_expired(self, skew_seconds: int = 60) -> bool:
        """Check if access token is expired or within skew seconds window."""
        if not self.expires_at_epoch_seconds:
            return False
        return time.time() >= (self.expires_at_epoch_seconds - skew_seconds)
