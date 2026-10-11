"""Core domain models for FoxyVPN CLI.

Provides dataclasses and serialization for authentication, proxy credentials,
server hierarchies, candidates, and connection state.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field, is_dataclass
from typing import Any, TypeVar

T = TypeVar("T")


@dataclass
class RuntimeAuth:
    """Runtime authentication session containing tokens and expiration timestamp."""

    access_token: str
    refresh_token: str | None = None
    expires_at_epoch_seconds: int = 0
    email: str | None = None

    def is_expired(self, skew_seconds: int = 60) -> bool:
        """Check if access token is expired or within skew seconds window."""
        if not self.expires_at_epoch_seconds:
            return False
        return time.time() >= (self.expires_at_epoch_seconds - skew_seconds)

    @property
    def accessToken(self) -> str:
        return self.access_token

    @property
    def refreshToken(self) -> str | None:
        return self.refresh_token

    @property
    def expiresAtEpochSeconds(self) -> int:
        return self.expires_at_epoch_seconds

    def to_dict(self) -> dict[str, Any]:
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "expires_at_epoch_seconds": self.expires_at_epoch_seconds,
            "email": self.email,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RuntimeAuth:
        access_token = data.get("access_token") or data.get("accessToken") or ""
        refresh_token = data.get("refresh_token") if "refresh_token" in data else data.get("refreshToken")
        expires_at = data.get("expires_at_epoch_seconds")
        if expires_at is None:
            expires_at = data.get("expiresAtEpochSeconds", 0)
        email = data.get("email")
        return cls(
            access_token=str(access_token),
            refresh_token=str(refresh_token) if refresh_token is not None else None,
            expires_at_epoch_seconds=int(expires_at),
            email=str(email) if email is not None else None,
        )


@dataclass
class ProxyPass:
    """Guardian proxy credentials / pass details."""

    token: str
    expires_at_epoch_seconds: int | None = None
    quota_max: int | None = None
    quota_remaining: int | None = None
    quota_reset: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "token": self.token,
            "expires_at_epoch_seconds": self.expires_at_epoch_seconds,
            "quota_max": self.quota_max,
            "quota_remaining": self.quota_remaining,
            "quota_reset": self.quota_reset,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProxyPass:
        token = data.get("token") or ""
        expires_at = data.get("expires_at_epoch_seconds")
        if expires_at is None:
            expires_at = data.get("expiresAtEpochSeconds")
        quota_max = data.get("quota_max") if "quota_max" in data else data.get("quotaMax")
        quota_remaining = data.get("quota_remaining") if "quota_remaining" in data else data.get("quotaRemaining")
        quota_reset = data.get("quota_reset") if "quota_reset" in data else data.get("quotaReset")
        return cls(
            token=str(token),
            expires_at_epoch_seconds=int(expires_at) if expires_at is not None else None,
            quota_max=int(quota_max) if quota_max is not None else None,
            quota_remaining=int(quota_remaining) if quota_remaining is not None else None,
            quota_reset=int(quota_reset) if quota_reset is not None else None,
        )


@dataclass
class Entitlement:
    """User subscription and bandwidth entitlement status."""

    subscribed: bool
    uid: str
    max_bytes: int | None
    limited_bandwidth: bool
    quota_remaining: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "subscribed": self.subscribed,
            "uid": self.uid,
            "max_bytes": self.max_bytes,
            "limited_bandwidth": self.limited_bandwidth,
            "quota_remaining": self.quota_remaining,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Entitlement:
        subscribed = bool(data.get("subscribed", False))
        uid = str(data.get("uid", ""))
        max_bytes = data.get("max_bytes") if "max_bytes" in data else data.get("maxBytes")
        limited_bandwidth = data.get("limited_bandwidth") if "limited_bandwidth" in data else data.get("limitedBandwidth", False)
        quota_remaining = data.get("quota_remaining") if "quota_remaining" in data else data.get("quotaRemaining")
        return cls(
            subscribed=subscribed,
            uid=uid,
            max_bytes=int(max_bytes) if max_bytes is not None else None,
            limited_bandwidth=bool(limited_bandwidth),
            quota_remaining=int(quota_remaining) if quota_remaining is not None else None,
        )


@dataclass
class VpnProtocol:
    """Protocol endpoint configuration on a VPN node."""

    name: str
    host: str = ""
    port: int = 0
    scheme: str = ""
    template_string: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "host": self.host,
            "port": self.port,
            "scheme": self.scheme,
            "template_string": self.template_string,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VpnProtocol:
        template = data.get("template_string") if "template_string" in data else data.get("templateString", "")
        return cls(
            name=str(data.get("name", "")),
            host=str(data.get("host", "")),
            port=int(data.get("port", 0)),
            scheme=str(data.get("scheme", "")),
            template_string=str(template or ""),
        )


@dataclass
class VpnServerNode:
    """Specific server node in a city."""

    hostname: str
    port: int = 0
    quarantined: bool = False
    protocols: list[VpnProtocol] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "port": self.port,
            "quarantined": self.quarantined,
            "protocols": [p.to_dict() if hasattr(p, "to_dict") else p for p in self.protocols],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VpnServerNode:
        raw_protocols = data.get("protocols", [])
        protocols = [
            VpnProtocol.from_dict(p) if isinstance(p, dict) else p
            for p in raw_protocols
        ]
        return cls(
            hostname=str(data.get("hostname", "")),
            port=int(data.get("port", 0)),
            quarantined=bool(data.get("quarantined", False)),
            protocols=protocols,
        )


@dataclass
class VpnCity:
    """City location containing VPN server nodes."""

    name: str
    code: str
    servers: list[VpnServerNode] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "code": self.code,
            "servers": [s.to_dict() if hasattr(s, "to_dict") else s for s in self.servers],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VpnCity:
        raw_servers = data.get("servers", [])
        servers = [
            VpnServerNode.from_dict(s) if isinstance(s, dict) else s
            for s in raw_servers
        ]
        return cls(
            name=str(data.get("name", "")),
            code=str(data.get("code", "")),
            servers=servers,
        )


@dataclass
class VpnCountry:
    """Country containing cities with VPN servers."""

    name: str
    code: str
    cities: list[VpnCity] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "code": self.code,
            "cities": [c.to_dict() if hasattr(c, "to_dict") else c for c in self.cities],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VpnCountry:
        raw_cities = data.get("cities", [])
        cities = [
            VpnCity.from_dict(c) if isinstance(c, dict) else c
            for c in raw_cities
        ]
        return cls(
            name=str(data.get("name", "")),
            code=str(data.get("code", "")),
            cities=cities,
        )


@dataclass
class ProxyCandidate:
    """Resolved candidate server for proxy connection."""

    host: str
    port: int
    country_code: str
    country_name: str
    city_code: str = ""
    ping_ms: float | None = None
    edge_ip: str | None = None

    @property
    def authority(self) -> str:
        return f"{self.host}:{self.port}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "country_code": self.country_code,
            "country_name": self.country_name,
            "city_code": self.city_code,
            "ping_ms": self.ping_ms,
            "edge_ip": self.edge_ip,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProxyCandidate:
        country_code = data.get("country_code") if "country_code" in data else data.get("countryCode", "")
        country_name = data.get("country_name") if "country_name" in data else data.get("countryName", "")
        city_code = data.get("city_code") if "city_code" in data else data.get("cityCode", "")
        ping_ms = data.get("ping_ms") if "ping_ms" in data else data.get("pingMs")
        edge_ip = data.get("edge_ip") if "edge_ip" in data else data.get("edgeIp")
        return cls(
            host=str(data.get("host", "")),
            port=int(data.get("port", 0)),
            country_code=str(country_code or ""),
            country_name=str(country_name or ""),
            city_code=str(city_code or ""),
            ping_ms=float(ping_ms) if ping_ms is not None else None,
            edge_ip=str(edge_ip) if edge_ip else None,
        )


@dataclass
class UpstreamProxyConfig:
    """Upstream chained proxy configuration (SOCKS5 / HTTP)."""

    type: str
    host: str
    port: int
    username: str | None = None
    password: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "password": self.password,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> UpstreamProxyConfig:
        return cls(
            type=str(data.get("type", "socks5")),
            host=str(data.get("host", "")),
            port=int(data.get("port", 1080)),
            username=data.get("username"),
            password=data.get("password"),
        )


@dataclass
class ConnectionState:
    """Live or persisted status of the VPN proxy connection."""

    status: str
    location: str | None = None
    edge_ip: str | None = None
    server_hostname: str | None = None
    socks_port: int = 10808
    bytes_sent: int = 0
    bytes_received: int = 0
    start_time: float | None = None
    tun_mode: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "location": self.location,
            "edge_ip": self.edge_ip,
            "server_hostname": self.server_hostname,
            "socks_port": self.socks_port,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "start_time": self.start_time,
            "tun_mode": self.tun_mode,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ConnectionState:
        edge_ip = data.get("edge_ip") if "edge_ip" in data else data.get("edgeIp")
        server_hostname = data.get("server_hostname") if "server_hostname" in data else data.get("serverHostname")
        socks_port = data.get("socks_port") if "socks_port" in data else data.get("socksPort", 10808)
        bytes_sent = data.get("bytes_sent") if "bytes_sent" in data else data.get("bytesSent", 0)
        bytes_received = data.get("bytes_received") if "bytes_received" in data else data.get("bytesReceived", 0)
        start_time = data.get("start_time") if "start_time" in data else data.get("startTime")
        tun_mode = bool(data.get("tun_mode", False))
        return cls(
            status=str(data.get("status", "disconnected")),
            location=data.get("location"),
            edge_ip=edge_ip,
            server_hostname=server_hostname,
            socks_port=int(socks_port),
            bytes_sent=int(bytes_sent),
            bytes_received=int(bytes_received),
            start_time=float(start_time) if start_time is not None else None,
            tun_mode=tun_mode,
        )


def to_dict(obj: Any) -> Any:
    """Serialize any model, dataclass, list, or dict into a JSON-compatible dictionary/value."""
    if hasattr(obj, "to_dict") and callable(obj.to_dict):
        return obj.to_dict()
    if is_dataclass(obj) and not isinstance(obj, type):
        return asdict(obj)
    if isinstance(obj, list):
        return [to_dict(item) for item in obj]
    if isinstance(obj, dict):
        return {k: to_dict(v) for k, v in obj.items()}
    return obj


def from_dict(cls: type[T], data: dict[str, Any]) -> T:
    """Deserialize a dictionary into the target dataclass model."""
    if hasattr(cls, "from_dict") and callable(cls.from_dict):
        return cls.from_dict(data)
    return cls(**data)  # type: ignore[call-arg]
