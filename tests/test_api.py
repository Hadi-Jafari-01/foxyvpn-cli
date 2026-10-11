"""Comprehensive unit tests for FoxyVPN Guardian API client, Server List client, and Ping prober."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from foxyvpn.api.fastly import FastlyChallengeError, client_metrics_answer, solve_pow
from foxyvpn.api.guardian import (
    GUARDIAN_ENDPOINT_DEFAULT,
    GuardianClient,
    GuardianHttpError,
    QuotaExceededError,
    TokenInvalidError,
    jwt_expiry_epoch_seconds,
)
from foxyvpn.api.models import (
    Entitlement,
    ProxyCandidate,
    ProxyPass,
    VpnCity,
    VpnCountry,
    VpnProtocol,
    VpnServerNode,
)
from foxyvpn.api.ping import ping_candidates, ping_server
from foxyvpn.api.server_list import (
    RECOMMENDED_COUNTRY_CODE,
    ServerListClient,
    candidates_for_city,
    candidates_for_country,
    default_connect_target,
    get_recommended_candidate,
)


def make_jwt(payload: dict, secret: str = "secret") -> str:
    """Create an unsigned dummy JWT for testing."""
    header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode("ascii").rstrip("=")
    payload_b64 = (
        base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8"))
        .decode("ascii")
        .rstrip("=")
    )
    return f"{header}.{payload_b64}.dummy_signature"


# ============================================================================
# 1. JWT Expiry Epoch Seconds Tests
# ============================================================================


def test_jwt_expiry_valid() -> None:
    token = make_jwt({"exp": 1780000000, "uid": "test_user"})
    exp = jwt_expiry_epoch_seconds(token)
    assert exp == 1780000000


def test_jwt_expiry_with_padding() -> None:
    # Ensure tokens that require '=' base64 padding decode properly
    payload_bytes = json.dumps({"exp": 1750000001, "a": "1"}).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode("ascii")  # might have '='
    token = f"header.{payload_b64.rstrip('=')}.sig"
    assert jwt_expiry_epoch_seconds(token) == 1750000001


def test_jwt_expiry_missing_exp() -> None:
    token = make_jwt({"uid": "test_user"})
    assert jwt_expiry_epoch_seconds(token) is None


def test_jwt_expiry_non_positive_or_invalid() -> None:
    assert jwt_expiry_epoch_seconds(make_jwt({"exp": 0})) is None
    assert jwt_expiry_epoch_seconds(make_jwt({"exp": -500})) is None
    assert jwt_expiry_epoch_seconds(make_jwt({"exp": "not-a-number"})) is None


def test_jwt_expiry_malformed_token() -> None:
    assert jwt_expiry_epoch_seconds("") is None
    assert jwt_expiry_epoch_seconds("single_part_token") is None
    assert jwt_expiry_epoch_seconds("invalid!base64.invalid!base64.sig") is None
    assert jwt_expiry_epoch_seconds("header.bm90LWpzb24=.sig") is None  # 'not-json' in b64
    assert jwt_expiry_epoch_seconds(None) is None  # type: ignore[arg-type]


# ============================================================================
# 2. Guardian Client Tests
# ============================================================================


@pytest.mark.asyncio
async def test_guardian_fetch_proxy_pass_success() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/api/v1/fpn/token"
        assert request.headers["Authorization"] == "Bearer mock_access_token"
        assert "MozillaVPN" in request.headers["User-Agent"]
        assert request.headers["Accept"] == "application/json"

        headers = {
            "Content-Type": "application/json",
            "X-Quota-Limit": "10737418240",
            "X-Quota-Remaining": "5368709120",
            "X-Quota-Reset": "1780005000",
        }
        body = {
            "token": "guardian_proxy_token_xyz",
            "expires_at": 1780009999,
        }
        return httpx.Response(200, json=body, headers=headers)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        client = GuardianClient(client=http_client)
        pass_data = await client.fetch_proxy_pass("mock_access_token")

        assert isinstance(pass_data, ProxyPass)
        assert pass_data.token == "guardian_proxy_token_xyz"
        assert pass_data.expires_at_epoch_seconds == 1780009999
        assert pass_data.quota_max == 10737418240
        assert pass_data.quota_remaining == 5368709120
        assert pass_data.quota_reset == 1780005000

        # Verify camelCase aliases
        assert pass_data.expiresAtEpochSeconds == 1780009999
        assert pass_data.quotaMax == 10737418240
        assert pass_data.quotaRemaining == 5368709120
        assert pass_data.quotaReset == 1780005000


@pytest.mark.asyncio
async def test_guardian_fetch_proxy_pass_fallback_jwt_exp() -> None:
    jwt_tok = make_jwt({"exp": 1799999999})

    def handler(request: httpx.Request) -> httpx.Response:
        # Body does not contain expires_at, so client falls back to JWT extraction
        body = {"token": jwt_tok}
        return httpx.Response(200, json=body)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        client = GuardianClient(client=http_client)
        pass_data = await client.fetch_proxy_pass("mock_token")
        assert pass_data.token == jwt_tok
        assert pass_data.expires_at_epoch_seconds == 1799999999


@pytest.mark.asyncio
async def test_guardian_fetch_proxy_pass_missing_token() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"message": "ok but no token"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        client = GuardianClient(client=http_client)
        with pytest.raises(GuardianHttpError) as exc_info:
            await client.fetch_proxy_pass("mock_token")
        assert "did not contain a token" in str(exc_info.value)


@pytest.mark.asyncio
async def test_guardian_fetch_proxy_pass_token_invalid_401_403() -> None:
    for code in [401, 403]:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(code, text="Unauthorized")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
            client = GuardianClient(client=http_client)
            with pytest.raises(TokenInvalidError) as exc_info:
                await client.fetch_proxy_pass("bad_token")
            assert exc_info.value.status_code == code
            assert isinstance(exc_info.value, GuardianHttpError)


@pytest.mark.asyncio
async def test_guardian_fetch_proxy_pass_quota_exceeded_429() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, text="Quota exceeded")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        client = GuardianClient(client=http_client)
        with pytest.raises(QuotaExceededError) as exc_info:
            await client.fetch_proxy_pass("mock_token")
        assert exc_info.value.status_code == 429
        assert isinstance(exc_info.value, GuardianHttpError)


@pytest.mark.asyncio
async def test_guardian_fetch_proxy_pass_http_500() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="Internal Server Error")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        client = GuardianClient(client=http_client)
        with pytest.raises(GuardianHttpError) as exc_info:
            await client.fetch_proxy_pass("mock_token")
        assert exc_info.value.status_code == 500


@pytest.mark.asyncio
async def test_guardian_fetch_proxy_pass_fastly_406_retry() -> None:
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(406, text="Fastly challenge required")
        return httpx.Response(200, json={"token": "token_after_challenge", "expires_at": 1780000000})

    mock_solver = AsyncMock()
    mock_solver.solve_and_install = AsyncMock(return_value=None)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        client = GuardianClient(client=http_client, challenge_solver=mock_solver)
        pass_data = await client.fetch_proxy_pass("mock_token")
        assert attempts == 2
        mock_solver.solve_and_install.assert_awaited_once()
        assert pass_data.token == "token_after_challenge"


@pytest.mark.asyncio
async def test_guardian_fetch_proxy_pass_fastly_406_without_solver() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(406, text="Fastly challenge required")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        client = GuardianClient(client=http_client, challenge_solver=None)
        with pytest.raises(GuardianHttpError) as exc_info:
            await client.fetch_proxy_pass("mock_token")
        assert exc_info.value.status_code == 406


@pytest.mark.asyncio
async def test_guardian_argument_order_swapping() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "vpn.custom.org"
        assert request.headers["Authorization"] == "Bearer swapped_token"
        return httpx.Response(200, json={"token": "tok_ok", "expires_at": 12345})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        client = GuardianClient(client=http_client)
        # Call with (endpoint, token) instead of (token, endpoint)
        pass_data = await client.fetch_proxy_pass("https://vpn.custom.org", "swapped_token")
        assert pass_data.token == "tok_ok"


@pytest.mark.asyncio
async def test_guardian_fetch_user_info_unlimited() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/fpn/status"
        return httpx.Response(
            200,
            json={
                "subscribed": True,
                "uid": "user_id_12345",
                "maxBytes": 10737418240,
                "limited_bandwidth": False,
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        client = GuardianClient(client=http_client)
        ent = await client.fetch_user_info("mock_token")
        assert isinstance(ent, Entitlement)
        assert ent.subscribed is True
        assert ent.uid == "user_id_12345"
        assert ent.max_bytes == 10737418240
        assert ent.limited_bandwidth is False
        assert ent.quota_remaining is None

        # Verify camelCase aliases
        assert ent.maxBytes == 10737418240
        assert ent.limitedBandwidth is False


@pytest.mark.asyncio
async def test_guardian_fetch_user_info_limited_bandwidth_populates_quota() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/fpn/status":
            return httpx.Response(
                200,
                json={
                    "subscribed": True,
                    "uid": "user_limited",
                    "maxBytes": 5242880000,
                    "limited_bandwidth": True,
                },
            )
        elif request.url.path == "/api/v1/fpn/token":
            return httpx.Response(
                200,
                json={"token": "tok_limited", "expires_at": 1780000000},
                headers={"X-Quota-Remaining": "2621440000"},
            )
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        client = GuardianClient(client=http_client)
        ent = await client.fetch_user_info("mock_token")
        assert ent.subscribed is True
        assert ent.limited_bandwidth is True
        assert ent.quota_remaining == 2621440000
        assert ent.quotaRemaining == 2621440000


@pytest.mark.asyncio
async def test_guardian_activate_guardian() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/api/v1/fpn/activate"
        assert request.content == b""
        return httpx.Response(
            200,
            json={
                "subscribed": True,
                "uid": "user_activated",
                "maxBytes": None,
                "limited_bandwidth": False,
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        client = GuardianClient(client=http_client)
        ent = await client.activate_guardian("mock_token")
        assert ent.subscribed is True
        assert ent.uid == "user_activated"
        assert ent.max_bytes is None


# ============================================================================
# 3. Server List Client Tests
# ============================================================================

MOCK_SERVER_LIST_DATA = {
    "data": [
        {
            "country": {
                "name": "United States",
                "code": "US",
                "cities": [
                    {
                        "name": "New York",
                        "code": "NYC",
                        "servers": [
                            {
                                "hostname": "nyc1.vpn.mozilla.org",
                                "port": 443,
                                "quarantined": False,
                                "protocols": [
                                    {
                                        "name": "connect",
                                        "host": "nyc1-proxy.vpn.mozilla.org",
                                        "port": 8443,
                                        "scheme": "https",
                                    },
                                    {
                                        "name": "wireguard",
                                        "host": "nyc1-wg.vpn.mozilla.org",
                                        "port": 51820,
                                    },
                                ],
                            },
                            {
                                "hostname": "nyc2-quarantined.vpn.mozilla.org",
                                "port": 443,
                                "quarantined": True,
                                "protocols": [
                                    {"name": "connect", "host": "", "port": 0}
                                ],
                            },
                        ],
                    },
                    {
                        "name": "Los Angeles",
                        "code": "LAX",
                        "servers": [
                            {
                                "hostname": "lax1.vpn.mozilla.org",
                                "port": 443,
                                "quarantined": False,
                                "protocols": [],  # empty protocols -> fallback to server hostname:port
                            }
                        ],
                    },
                ],
            }
        },
        # Flat format (record directly has name, code, cities)
        {
            "name": "Germany",
            "code": "DE",
            "cities": [
                {
                    "name": "Frankfurt",
                    "code": "FRA",
                    "servers": [
                        {
                            "hostname": "fra1.vpn.mozilla.org",
                            "port": 443,
                            "quarantined": False,
                            "protocols": [
                                {
                                    "name": "connect",
                                    "host": "",  # blank host -> uses server hostname
                                    "port": 0,   # 0 port -> uses server port
                                }
                            ],
                        },
                        {
                            "hostname": "fra2-wg-only.vpn.mozilla.org",
                            "port": 51820,
                            "quarantined": False,
                            "protocols": [
                                {"name": "wireguard", "host": "fra2.wg", "port": 51820}
                            ],
                        },
                    ],
                }
            ],
        },
        # Excluded CatchAll Anycast
        {
            "name": "CatchAll Anycast",
            "code": "ALL",
            "cities": [
                {
                    "name": "Anycast",
                    "code": "ANY",
                    "servers": [
                        {"hostname": "anycast.vpn.mozilla.org", "port": 443}
                    ],
                }
            ],
        },
        # Empty cities country -> should be excluded
        {
            "name": "Empty Country",
            "code": "EMP",
            "cities": [],
        },
    ]
}


@pytest.mark.asyncio
async def test_server_list_fetch_countries() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert "MozillaVPN" in request.headers["User-Agent"]
        return httpx.Response(200, json=MOCK_SERVER_LIST_DATA)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        client = ServerListClient(client=http_client)
        countries = await client.fetch_countries()

        country_codes = [c.code for c in countries]
        assert "US" in country_codes
        assert "DE" in country_codes
        assert "ALL" not in country_codes  # CatchAll Anycast excluded
        assert "EMP" not in country_codes  # Empty cities excluded

        us = next(c for c in countries if c.code == "US")
        assert len(us.cities) == 2

        nyc = next(city for city in us.cities if city.code == "NYC")
        # Quarantined server must be excluded from parsed servers
        assert len(nyc.servers) == 1
        assert nyc.servers[0].hostname == "nyc1.vpn.mozilla.org"
        assert not nyc.servers[0].quarantined


def test_candidates_for_country_connect_protocols() -> None:
    countries = [
        ServerListClient.parse_country(c["country"] if "country" in c else c)
        for c in MOCK_SERVER_LIST_DATA["data"]
    ]

    # Test US candidates
    us_candidates = candidates_for_country(countries, "US")
    assert len(us_candidates) == 2

    nyc_candidate = next(c for c in us_candidates if c.city_code == "NYC")
    # Protocol 'connect' had custom host and port
    assert nyc_candidate.host == "nyc1-proxy.vpn.mozilla.org"
    assert nyc_candidate.port == 8443
    assert nyc_candidate.authority == "nyc1-proxy.vpn.mozilla.org:8443"
    assert nyc_candidate.country_code == "US"
    assert nyc_candidate.country_name == "United States"

    lax_candidate = next(c for c in us_candidates if c.city_code == "LAX")
    # Empty protocols -> uses server hostname and port
    assert lax_candidate.host == "lax1.vpn.mozilla.org"
    assert lax_candidate.port == 443

    # Test Germany candidates
    de_candidates = candidates_for_country(countries, "de")  # Case-insensitive
    assert len(de_candidates) == 1
    fra_candidate = de_candidates[0]
    # Blank host/0 port in connect protocol -> uses server hostname and port
    assert fra_candidate.host == "fra1.vpn.mozilla.org"
    assert fra_candidate.port == 443
    # Server with only wireguard protocol is excluded


def test_candidates_for_city() -> None:
    countries = [
        ServerListClient.parse_country(c["country"] if "country" in c else c)
        for c in MOCK_SERVER_LIST_DATA["data"]
    ]
    nyc_candidates = candidates_for_city(countries, "US", "NYC")
    assert len(nyc_candidates) == 1
    assert nyc_candidates[0].city_code == "NYC"

    lax_candidates = candidates_for_city(countries, "US", "lax")  # Case-insensitive
    assert len(lax_candidates) == 1
    assert lax_candidates[0].city_code == "LAX"


def test_get_recommended_candidate() -> None:
    rec_country = VpnCountry(
        name="Recommended",
        code=RECOMMENDED_COUNTRY_CODE,
        cities=[
            VpnCity(
                name="Recommended City",
                code="REC_CITY",
                servers=[
                    VpnServerNode(
                        hostname="rec.vpn.mozilla.org",
                        port=443,
                        protocols=[VpnProtocol("connect", host="rec.proxy", port=443)],
                    )
                ],
            )
        ],
    )
    other_country = VpnCountry(
        name="Other",
        code="OT",
        cities=[
            VpnCity(
                name="Other City",
                code="OT_CITY",
                servers=[
                    VpnServerNode(
                        hostname="other.vpn.mozilla.org",
                        port=443,
                        protocols=[VpnProtocol("connect", host="other.proxy", port=443)],
                    )
                ],
            )
        ],
    )

    # With REC country present -> returns REC candidate
    rec = get_recommended_candidate([other_country, rec_country])
    assert rec is not None
    assert rec.country_code == RECOMMENDED_COUNTRY_CODE
    assert rec.host == "rec.proxy"

    # Without REC country present -> falls back to first available country
    rec_fallback = get_recommended_candidate([other_country])
    assert rec_fallback is not None
    assert rec_fallback.country_code == "OT"

    # Empty list -> returns None
    assert get_recommended_candidate([]) is None


def test_default_connect_target_rules() -> None:
    # 1. Connect protocol with host & port
    s1 = VpnServerNode("base.host", 443, protocols=[VpnProtocol("connect", "custom.host", 8080)])
    assert default_connect_target(s1) == ("custom.host", 8080)

    # 2. Connect protocol with blank host & 0 port -> fallback to base
    s2 = VpnServerNode("base.host", 443, protocols=[VpnProtocol("connect", "", 0)])
    assert default_connect_target(s2) == ("base.host", 443)

    # 3. Empty protocols -> fallback to base
    s3 = VpnServerNode("base.host", 443, protocols=[])
    assert default_connect_target(s3) == ("base.host", 443)

    # 4. Non-empty protocols without connect -> None
    s4 = VpnServerNode("base.host", 443, protocols=[VpnProtocol("wireguard", "wg.host", 51820)])
    assert default_connect_target(s4) is None


# ============================================================================
# 4. Latency Prober Tests
# ============================================================================


@pytest.mark.asyncio
async def test_ping_server_real_local_socket() -> None:
    server = await asyncio.start_server(lambda r, w: None, host="127.0.0.1", port=0)
    port = server.sockets[0].getsockname()[1]

    async with server:
        latency = await ping_server("127.0.0.1", port=port, timeout=2.0)
        assert latency is not None
        assert latency >= 0.0


@pytest.mark.asyncio
async def test_ping_server_unreachable_returns_none() -> None:
    # Closed port on localhost (guaranteed connection failure)
    latency = await ping_server("127.0.0.1", port=59999, timeout=0.5)
    assert latency is None


@pytest.mark.asyncio
async def test_ping_server_timeout_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    async def slow_connect(*args: Any, **kwargs: Any) -> Any:
        await asyncio.sleep(5.0)

    monkeypatch.setattr(asyncio, "open_connection", slow_connect)
    latency = await ping_server("10.255.255.1", port=443, timeout=0.05)
    assert latency is None


@pytest.mark.asyncio
async def test_ping_candidates_concurrent_and_sorted(monkeypatch: pytest.MonkeyPatch) -> None:
    candidates = [
        ProxyCandidate(host="slow.example.com", port=443, country_code="US", country_name="USA"),
        ProxyCandidate(host="fast.example.com", port=443, country_code="DE", country_name="Germany"),
        ProxyCandidate(host="unreachable.example.com", port=443, country_code="FR", country_name="France"),
        ProxyCandidate(host="medium.example.com", port=443, country_code="JP", country_name="Japan"),
    ]

    mock_latencies = {
        "slow.example.com": 120.5,
        "fast.example.com": 15.2,
        "unreachable.example.com": None,
        "medium.example.com": 45.0,
    }

    async def mock_ping(host: str, port: int = 443, timeout: float = 3.0) -> float | None:
        return mock_latencies.get(host)

    monkeypatch.setattr("foxyvpn.api.ping.ping_server", mock_ping)

    sorted_candidates = await ping_candidates(candidates, timeout=1.0)

    hosts_order = [c.host for c in sorted_candidates]
    assert hosts_order == [
        "fast.example.com",        # 15.2 ms
        "medium.example.com",      # 45.0 ms
        "slow.example.com",        # 120.5 ms
        "unreachable.example.com", # None ms (placed at end)
    ]
    assert sorted_candidates[0].ping_ms == 15.2
    assert sorted_candidates[-1].ping_ms is None


@pytest.mark.asyncio
async def test_ping_candidates_empty() -> None:
    assert await ping_candidates([]) == []


# ============================================================================
# 5. Fastly PoW Challenge Tests
# ============================================================================


def test_fastly_solve_pow() -> None:
    base = "challenge_base_string_123"
    # Choose suffix "K9" from POW_ALPHABET
    target_suffix = "K9"
    target_digest = hashlib.sha256((base + target_suffix).encode("utf-8")).digest()
    target_hex = target_digest.hex()

    found_suffix = solve_pow(base, target_hex)
    assert found_suffix == target_suffix


def test_fastly_solve_pow_invalid() -> None:
    assert solve_pow("base", "invalid_hex") is None
    assert solve_pow("base", "1234") is None  # length != 32 bytes


def test_fastly_client_metrics_answer() -> None:
    ans = client_metrics_answer()
    assert ans["ty"] == "clientmetrics"
    assert ans["webdriver"] is False
    assert ans["bot_detection_result"]["bot_detected"] is False
