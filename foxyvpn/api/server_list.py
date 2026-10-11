"""Client and utilities for Mozilla VPN Remote Settings server list."""

from __future__ import annotations

from typing import Any

import httpx

from foxyvpn.api.models import (
    ProxyCandidate,
    VpnCity,
    VpnCountry,
    VpnProtocol,
    VpnServerNode,
)

REMOTE_SETTINGS_URL = (
    "https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist/records"
)
MOZILLA_VPN_USER_AGENT = "MozillaVPN/2.35.0 (sys:linux; iap:true)"
ACCEPT_HEADER = "application/json"
RECOMMENDED_COUNTRY_CODE = "REC"
EXCLUDED_COUNTRY_NAMES = frozenset(["CatchAll Anycast"])


def default_connect_target(server: VpnServerNode) -> tuple[str, int] | None:
    """
    Select target host and port for HTTP connect proxy.
    Returns (host, port) from 'connect' protocol or server hostname:port if no protocols defined.
    Returns None if server defines protocols but none is 'connect'.
    """
    for proto in server.protocols:
        if proto.name == "connect":
            host = proto.host.strip() if proto.host and proto.host.strip() else server.hostname
            port = proto.port if proto.port != 0 else server.port
            return (host, port)
    if not server.protocols:
        return (server.hostname, server.port)
    return None


def candidates_for_country(
    countries: list[VpnCountry],
    country_code: str,
) -> list[ProxyCandidate]:
    """Filter proxy candidates for a country code (case-insensitive)."""
    out: list[ProxyCandidate] = []
    target_code = country_code.strip().lower()
    for country in countries:
        if country.code.strip().lower() != target_code:
            continue
        for city in country.cities:
            for server in city.servers:
                if server.quarantined:
                    continue
                target = default_connect_target(server)
                if not target:
                    continue
                host, port = target
                out.append(
                    ProxyCandidate(
                        host=host,
                        port=port,
                        country_code=country.code,
                        country_name=country.name,
                        city_code=city.code,
                    )
                )
    return out


def candidates_for_city(
    countries: list[VpnCountry],
    country_code: str,
    city_code: str,
) -> list[ProxyCandidate]:
    """Filter proxy candidates for a specific city code within a country."""
    candidates = candidates_for_country(countries, country_code)
    target_city = city_code.strip().lower()
    return [c for c in candidates if c.city_code.strip().lower() == target_city]


def get_recommended_candidate(countries: list[VpnCountry]) -> ProxyCandidate | None:
    """
    Get recommended proxy candidate.
    First checks country code 'REC'. If not found, falls back to the first available candidate.
    """
    rec_candidates = candidates_for_country(countries, RECOMMENDED_COUNTRY_CODE)
    if rec_candidates:
        return rec_candidates[0]
    for country in countries:
        candidates = candidates_for_country(countries, country.code)
        if candidates:
            return candidates[0]
    return None


class ServerListClient:
    """Client for fetching and parsing Mozilla VPN server list from Remote Settings."""

    REMOTE_SETTINGS_URL = REMOTE_SETTINGS_URL
    RECOMMENDED_COUNTRY_CODE = RECOMMENDED_COUNTRY_CODE

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client
        self._owns_client = client is None

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

    async def __aenter__(self) -> ServerListClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    async def fetch_countries(self, url: str = REMOTE_SETTINGS_URL) -> list[VpnCountry]:
        """
        Fetch remote settings JSON records.
        Parses countries, cities, servers, and protocols.
        Excludes quarantined servers and 'CatchAll Anycast' country.
        """
        client = await self._get_client()
        headers = {
            "User-Agent": MOZILLA_VPN_USER_AGENT,
            "Accept": ACCEPT_HEADER,
        }
        resp = await client.get(url, headers=headers)
        if resp.status_code != 200:
            raise httpx.HTTPStatusError(
                f"Remote Settings fetch failed: HTTP {resp.status_code}",
                request=resp.request,
                response=resp,
            )

        data = resp.json()
        records = data.get("data", [])
        countries: list[VpnCountry] = []

        for record in records:
            country_json = (
                record.get("country")
                if isinstance(record.get("country"), dict)
                else record
            )
            country = self.parse_country(country_json)
            is_excluded = any(
                country.name.strip().lower() == excluded.lower()
                for excluded in EXCLUDED_COUNTRY_NAMES
            )
            if country.code.strip() and country.cities and not is_excluded:
                countries.append(country)

        return countries

    @classmethod
    def parse_country(cls, json_data: dict[str, Any]) -> VpnCountry:
        cities = [
            cls.parse_city(c)
            for c in json_data.get("cities", [])
            if isinstance(c, dict)
        ]
        return VpnCountry(
            name=str(json_data.get("name", "")),
            code=str(json_data.get("code", "")),
            cities=cities,
        )

    @classmethod
    def parse_city(cls, json_data: dict[str, Any]) -> VpnCity:
        servers = [
            cls.parse_server(s)
            for s in json_data.get("servers", [])
            if isinstance(s, dict) and not s.get("quarantined", False)
        ]
        return VpnCity(
            name=str(json_data.get("name", "")),
            code=str(json_data.get("code", "")),
            servers=servers,
        )

    @classmethod
    def parse_server(cls, json_data: dict[str, Any]) -> VpnServerNode:
        protocols = [
            cls.parse_protocol(p)
            for p in json_data.get("protocols", [])
            if isinstance(p, dict)
        ]
        return VpnServerNode(
            hostname=str(json_data.get("hostname", "")),
            port=int(json_data.get("port", 0)),
            quarantined=bool(json_data.get("quarantined", False)),
            protocols=protocols,
        )

    @classmethod
    def parse_protocol(cls, json_data: dict[str, Any]) -> VpnProtocol:
        template = json_data.get("templateString") or json_data.get("template_string") or ""
        return VpnProtocol(
            name=str(json_data.get("name", "")),
            host=str(json_data.get("host", "")),
            port=int(json_data.get("port", 0)),
            scheme=str(json_data.get("scheme", "")),
            template_string=str(template),
        )

    # Class-level delegates for Kotlin companion object compatibility
    default_connect_target = staticmethod(default_connect_target)
    candidates_for_country = staticmethod(candidates_for_country)
    candidates_for_city = staticmethod(candidates_for_city)
    get_recommended_candidate = staticmethod(get_recommended_candidate)
