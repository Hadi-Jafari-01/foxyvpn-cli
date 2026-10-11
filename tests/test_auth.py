"""Unit tests for Firefox Accounts (FxA) authentication, cryptography, Hawk, and Fastly challenge solver."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
import urllib.parse
from typing import Any

import httpx
import pytest

from foxyvpn.auth.challenge import (
    FastlyChallengeError,
    FastlyChallengeSolver,
    base_origin,
    client_metrics_answer,
    parse_challenge_init,
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
from foxyvpn.core.store import TokenStore


# ============================================================================
# 1. Cryptography Key Derivation Tests (crypto.py)
# ============================================================================


class TestCrypto:
    def test_protocol_version(self) -> None:
        assert PROTOCOL_VERSION == "identity.mozilla.com/picl/v1/"

    def test_derive_quick_stretch_length_and_type(self) -> None:
        res = derive_quick_stretch("user@example.com", "securepassword123")
        assert isinstance(res, bytes)
        assert len(res) == 32

    def test_derive_quick_stretch_deterministic(self) -> None:
        res1 = derive_quick_stretch("alice@example.com", "Password!1")
        res2 = derive_quick_stretch("alice@example.com", "Password!1")
        assert res1 == res2

        res3 = derive_quick_stretch("bob@example.com", "Password!1")
        assert res1 != res3

        res4 = derive_quick_stretch("alice@example.com", "DifferentPassword!1")
        assert res1 != res4

    def test_derive_auth_pw_format_and_properties(self) -> None:
        auth_pw = derive_auth_pw("user@example.com", "password123")
        assert isinstance(auth_pw, str)
        assert len(auth_pw) == 64
        # Must be valid hexadecimal
        assert re.fullmatch(r"[0-9a-f]{64}", auth_pw) is not None

        # Deterministic
        assert auth_pw == derive_auth_pw("user@example.com", "password123")
        assert auth_pw != derive_auth_pw("user@example.com", "otherpassword")

    def test_derive_hawk_credentials(self) -> None:
        # 32 bytes hex encoded = 64 hex characters
        dummy_session = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        token_id, hmac_key = derive_hawk_credentials(dummy_session)

        assert isinstance(token_id, str)
        assert len(token_id) == 64
        assert re.fullmatch(r"[0-9a-f]{64}", token_id) is not None

        assert isinstance(hmac_key, bytes)
        assert len(hmac_key) == 32

        # Deterministic
        tid2, hkey2 = derive_hawk_credentials(dummy_session)
        assert token_id == tid2
        assert hmac_key == hkey2


# ============================================================================
# 2. Hawk Header Tests (hawk.py)
# ============================================================================


class TestHawk:
    def test_generate_and_parse_hawk_header_no_body(self) -> None:
        token_id = "token_abc123"
        hmac_key = b"0" * 32
        url = "https://api.accounts.firefox.com/v1/session/verify_code"

        header = generate_hawk_header(
            method="POST",
            url=url,
            token_id=token_id,
            hmac_key=hmac_key,
            body=b"",
            ts="1600000000",
            nonce="nonce123",
        )

        assert header.startswith("Hawk ")
        parsed = parse_hawk_header(header)
        assert parsed["id"] == token_id
        assert parsed["ts"] == "1600000000"
        assert parsed["nonce"] == "nonce123"
        assert "mac" in parsed
        assert "hash" not in parsed

        # Verification passes
        assert verify_hawk_header(
            header=header,
            method="POST",
            url=url,
            hmac_key=hmac_key,
            body=b"",
        ) is True

        # Fails if method, URL, or key differs
        assert verify_hawk_header(header, "GET", url, hmac_key) is False
        assert verify_hawk_header(header, "POST", "https://api.accounts.firefox.com/v1/other", hmac_key) is False
        assert verify_hawk_header(header, "POST", url, b"1" * 32) is False

    def test_generate_and_verify_hawk_header_with_body(self) -> None:
        token_id = "token_xyz"
        hmac_key = b"k" * 32
        url = "https://api.accounts.firefox.com/v1/session/verify_code"
        body = b'{"code": "123456"}'

        header = generate_hawk_header(
            method="POST",
            url=url,
            token_id=token_id,
            hmac_key=hmac_key,
            body=body,
            ts="1600000000",
            nonce="nonce456",
        )

        parsed = parse_hawk_header(header)
        assert "hash" in parsed

        expected_hash = base64.b64encode(
            hashlib.sha256(b"hawk.1.payload\napplication/json\n" + body + b"\n").digest()
        ).decode("ascii")
        assert parsed["hash"] == expected_hash

        assert verify_hawk_header(header, "POST", url, hmac_key, body=body) is True
        # Tampered body fails verification
        assert verify_hawk_header(header, "POST", url, hmac_key, body=b'{"code": "999999"}') is False

    def test_hawk_header_with_query_and_custom_port(self) -> None:
        token_id = "token_custom"
        hmac_key = b"m" * 32
        url = "http://localhost:8080/v1/test?param=value"

        header = generate_hawk_header(
            method="GET",
            url=url,
            token_id=token_id,
            hmac_key=hmac_key,
            ts="1600000000",
            nonce="nonce789",
        )

        assert verify_hawk_header(header, "GET", url, hmac_key) is True
        # Different query fails
        assert verify_hawk_header(header, "GET", "http://localhost:8080/v1/test", hmac_key) is False


# ============================================================================
# 3. Fastly Challenge Solver Tests (challenge.py)
# ============================================================================


class TestChallenge:
    def test_solve_pow_known_vectors(self) -> None:
        base = "challenge_salt_987654"
        for expected_suffix in ["aa", "Z9", "M0", "7b"]:
            target_hash = hashlib.sha256((base + expected_suffix).encode("utf-8")).hexdigest()
            solved = solve_pow(base, target_hash)
            assert solved == expected_suffix

    def test_solve_pow_invalid_inputs(self) -> None:
        assert solve_pow("base", "invalid_hex") is None
        assert solve_pow("base", "1234") is None  # Not 32 bytes

        # SHA-256 hash of something outside 2-character space
        target_hash = hashlib.sha256(b"something_very_long_and_not_matching").hexdigest()
        assert solve_pow("base", target_hash) is None

    def test_client_metrics_answer(self) -> None:
        ans = client_metrics_answer()
        assert ans["ty"] == "clientmetrics"
        assert ans["webdriver"] is False
        assert ans["v"] == 2
        assert ans["bot_detection_result"]["bot_detected"] is False

    def test_base_origin(self) -> None:
        assert (
            base_origin("https://accounts.firefox.com/_fs-ch-abc123/pat")
            == "https://accounts.firefox.com"
        )
        assert (
            base_origin("https://api.accounts.firefox.com/_fs-ch-xyz")
            == "https://api.accounts.firefox.com"
        )
        assert base_origin("https://example.com/no_prefix") == "https://example.com/no_prefix"

    def test_parse_challenge_init(self) -> None:
        script = """
        function setup() {
            init([{"ty": "pow", "data": {"base": "b1", "hash": "h1"}}, {"ty": "clientmetrics"}], "token_sec_1", "extra");
        }
        """
        challenges, token = parse_challenge_init(script)
        assert token == "token_sec_1"
        assert len(challenges) == 2
        assert challenges[0]["ty"] == "pow"
        assert challenges[1]["ty"] == "clientmetrics"

    @pytest.mark.asyncio
    async def test_fastly_challenge_e2e_mock(self) -> None:
        base_url = "https://accounts.firefox.com"
        prefix = "/_fs-ch-test99"
        pow_base = "fastly_pow_base_123"
        pow_suffix = "K9"
        pow_target_hash = hashlib.sha256((pow_base + pow_suffix).encode("utf-8")).hexdigest()

        challenge_page_html = f"""
        <html>
        <head><title>Fastly Client Challenge</title></head>
        <body>
        <script src="{prefix}/script.js?reload=true"></script>
        </body>
        </html>
        """

        script_js = f"""
        init([
            {{"ty": "pow", "data": {{"base": "{pow_base}", "hash": "{pow_target_hash}"}}}},
            {{"ty": "clientmetrics"}}
        ], "token_initial_123", "param");
        """

        solved_state = {"solved": False}

        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/" or path == "":
                if not solved_state["solved"]:
                    return httpx.Response(200, text=challenge_page_html)
                else:
                    return httpx.Response(200, text="<html><body>Welcome, authenticated user</body></html>")
            elif path == f"{prefix}/script.js":
                return httpx.Response(200, text=script_js)
            elif path == f"{prefix}/fst-post-back":
                data = json.loads(request.content)
                assert data["token"] == "token_initial_123"
                answers = data["data"]
                assert len(answers) == 2
                assert answers[0]["ty"] == "pow"
                assert answers[0]["answer"] == pow_suffix
                assert answers[1]["ty"] == "clientmetrics"
                solved_state["solved"] = True
                return httpx.Response(
                    200,
                    headers={"Set-Cookie": "fs_challenge_cookie=passed_123; Domain=.firefox.com; Path=/"},
                    json={"status": "success"},
                )
            return httpx.Response(404, text="Not Found")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport, base_url=base_url) as client:
            solver = FastlyChallengeSolver(cookies=client.cookies)
            cookies = await solver.solve_and_install(client=client, bases=[base_url])
            assert "fs_challenge_cookie" in cookies
            assert cookies["fs_challenge_cookie"] == "passed_123"
            assert client.cookies.get("fs_challenge_cookie") == "passed_123"


# ============================================================================
# 4. FxA Auth Repository Tests (fxa.py)
# ============================================================================


class TestFxaAuthRepository:
    def test_constants(self) -> None:
        assert FXA_AUTH_SERVER == "https://api.accounts.firefox.com/v1"
        assert FIREFOX_CLIENT_ID == "5882386c6d801776"
        assert OAUTH_SCOPE == "profile https://identity.mozilla.com/apps/vpn"
        assert USER_AGENT == "MozillaVPN/2.35.0 (sys:linux; iap:true)"

    @pytest.mark.asyncio
    async def test_login_direct_success_no_2fa(self) -> None:
        session_token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/v1/account/login":
                body = json.loads(request.content)
                assert body["email"] == "test@example.com"
                assert "authPW" in body
                assert "verificationMethod" not in body
                assert request.headers.get("User-Agent") == USER_AGENT
                return httpx.Response(
                    200,
                    json={
                        "sessionToken": session_token,
                        "verified": True,
                    },
                )
            elif path == "/v1/oauth/token":
                body = json.loads(request.content)
                assert body["client_id"] == FIREFOX_CLIENT_ID
                assert body["grant_type"] == "fxa-credentials"
                assert "Authorization" in request.headers
                assert request.headers["Authorization"].startswith("Hawk ")
                return httpx.Response(
                    200,
                    json={
                        "access_token": "fxa_access_token_123",
                        "refresh_token": "fxa_refresh_token_456",
                        "expires_in": 3600,
                    },
                )
            return httpx.Response(404, text="Not Found")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            repo = FxaAuthRepository(client=client)
            needs_2fa, result = await repo.login("test@example.com", "mypassword")

            assert needs_2fa is False
            assert isinstance(result, RuntimeAuth)
            assert result.access_token == "fxa_access_token_123"
            assert result.refresh_token == "fxa_refresh_token_456"
            assert result.expires_at_epoch_seconds > 0
            assert result.email == "test@example.com"

    @pytest.mark.asyncio
    async def test_login_requires_2fa_and_submit_code(self) -> None:
        session_token = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/v1/account/login":
                return httpx.Response(
                    200,
                    json={
                        "sessionToken": session_token,
                        "verified": False,
                    },
                )
            elif path == "/v1/session/verify_code":
                assert request.headers["Authorization"].startswith("Hawk ")
                body = json.loads(request.content)
                assert body["code"] == "654321"
                return httpx.Response(200, json={"status": "verified"})
            elif path == "/v1/oauth/token":
                assert request.headers["Authorization"].startswith("Hawk ")
                return httpx.Response(
                    200,
                    json={
                        "access_token": "verified_access_token",
                        "refresh_token": "verified_refresh_token",
                        "expires_in": 1800,
                    },
                )
            return httpx.Response(404, text="Not Found")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            repo = FxaAuthRepository(client=client)
            needs_2fa, token_or_auth = await repo.login("user2fa@example.com", "pass2fa")

            assert needs_2fa is True
            assert token_or_auth == session_token
            assert repo.pending_session_token == session_token

            auth = await repo.submit_2fa(session_token=session_token, code="654321")
            assert isinstance(auth, RuntimeAuth)
            assert auth.access_token == "verified_access_token"
            assert auth.refresh_token == "verified_refresh_token"
            assert repo.pending_session_token is None

    @pytest.mark.asyncio
    async def test_login_errno_107_retry_without_verification_method(self) -> None:
        attempts = 0
        session_token = "1122334455667788990011223344556677889900112233445566778899001122"

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal attempts
            path = request.url.path
            if path == "/v1/account/login":
                attempts += 1
                body = json.loads(request.content)
                if attempts == 1:
                    assert "verificationMethod" in body
                    return httpx.Response(
                        400,
                        json={"errno": 107, "message": "invalid parameter"},
                    )
                else:
                    assert "verificationMethod" not in body
                    return httpx.Response(
                        200,
                        json={"sessionToken": session_token, "verified": True},
                    )
            elif path == "/v1/oauth/token":
                return httpx.Response(
                    200,
                    json={"access_token": "recovered_token", "expires_in": 3600},
                )
            return httpx.Response(404, text="Not Found")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            repo = FxaAuthRepository(client=client)
            needs_2fa, auth = await repo.login(
                "compat@example.com", "secret", force_verification_method=True
            )
            assert needs_2fa is False
            assert isinstance(auth, RuntimeAuth)
            assert auth.access_token == "recovered_token"
            assert attempts == 2

    @pytest.mark.asyncio
    async def test_refresh_access_token_success(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/v1/oauth/token":
                body = json.loads(request.content)
                assert body["grant_type"] == "refresh_token"
                assert body["refresh_token"] == "current_refresh_token"
                assert body["client_id"] == FIREFOX_CLIENT_ID
                assert body["scope"] == OAUTH_SCOPE
                return httpx.Response(
                    200,
                    json={
                        "access_token": "refreshed_access_token_999",
                        "refresh_token": "next_refresh_token_888",
                        "expires_in": 7200,
                    },
                )
            return httpx.Response(404, text="Not Found")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            repo = FxaAuthRepository(client=client)
            auth = await repo.refresh_access_token("current_refresh_token")

            assert auth.access_token == "refreshed_access_token_999"
            assert auth.refresh_token == "next_refresh_token_888"
            assert auth.expires_at_epoch_seconds > 0

    @pytest.mark.asyncio
    async def test_refresh_access_token_permanent_rejection(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                401,
                json={"message": "Invalid refresh token"},
            )

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            repo = FxaAuthRepository(client=client)
            with pytest.raises(FxaRefreshFailure) as exc_info:
                await repo.refresh_access_token("invalid_token")
            assert exc_info.value.permanent is True

    @pytest.mark.asyncio
    async def test_fxa_406_challenge_retry(self) -> None:
        session_token = "2233445566778899001122334455667788990011223344556677889900112233"
        attempts = 0
        challenge_solved = False

        class MockChallengeSolver(FastlyChallengeSolver):
            async def solve_and_install(
                self,
                client: httpx.AsyncClient | None = None,
                bases: list[str] | None = None,
            ) -> dict[str, str]:
                nonlocal challenge_solved
                challenge_solved = True
                return {"_fs_ch_pass": "1"}

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal attempts
            if request.url.path == "/v1/account/login":
                attempts += 1
                if attempts == 1:
                    return httpx.Response(406, text="Fastly Bot Challenge")
                else:
                    return httpx.Response(
                        200,
                        json={"sessionToken": session_token, "verified": True},
                    )
            elif request.url.path == "/v1/oauth/token":
                return httpx.Response(
                    200,
                    json={"access_token": "token_after_challenge", "expires_in": 3600},
                )
            return httpx.Response(404, text="Not Found")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            repo = FxaAuthRepository(client=client, challenge_solver=MockChallengeSolver())
            needs_2fa, auth = await repo.login("user@botcheck.com", "password")

            assert challenge_solved is True
            assert attempts == 2
            assert needs_2fa is False
            assert isinstance(auth, RuntimeAuth)
            assert auth.access_token == "token_after_challenge"

    @pytest.mark.asyncio
    async def test_token_store_integration(self, tmp_path: Any) -> None:
        tokens_file = tmp_path / "test_tokens.json"
        store = TokenStore(file_path=tokens_file)
        session_token = "3344556677889900112233445566778899001122334455667788990011223344"

        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/v1/account/login":
                return httpx.Response(
                    200,
                    json={"sessionToken": session_token, "verified": True},
                )
            elif path == "/v1/oauth/token":
                return httpx.Response(
                    200,
                    json={"access_token": "stored_token", "refresh_token": "stored_ref", "expires_in": 3600},
                )
            return httpx.Response(404, text="Not Found")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            repo = FxaAuthRepository(client=client, token_store=store)
            needs_2fa, auth = await repo.login("stored@example.com", "pass")
            assert needs_2fa is False

            # Verify saved into TokenStore
            loaded = store.load_auth()
            assert loaded is not None
            assert loaded.access_token == "stored_token"
            assert loaded.refresh_token == "stored_ref"
            assert loaded.email == "stored@example.com"
            assert store.has_valid_access_token() is True

            # Test ensure_fresh_access_token returns cached
            fresh = await repo.ensure_fresh_access_token(force=False)
            assert fresh.access_token == "stored_token"

    @pytest.mark.asyncio
    async def test_restore_session_scenarios(self, tmp_path: Any) -> None:
        tokens_file = tmp_path / "restore_tokens.json"
        store = TokenStore(file_path=tokens_file)

        # 1. No auth saved
        repo = FxaAuthRepository(token_store=store)
        assert await repo.restore_session() == "NEEDS_LOGIN"

        # 2. Valid unexpired access token
        valid_auth = RuntimeAuth(
            access_token="valid_acc",
            refresh_token="ref_tok",
            expires_at_epoch_seconds=int(time.time()) + 3600,
        )
        store.save_auth(valid_auth)
        assert await repo.restore_session() == "ACTIVE"

        # 3. Expired access token with refresh token -> successful refresh
        expired_auth = RuntimeAuth(
            access_token="expired_acc",
            refresh_token="good_refresh",
            expires_at_epoch_seconds=int(time.time()) - 100,
        )
        store.save_auth(expired_auth)

        def refresh_ok_handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/v1/oauth/token":
                return httpx.Response(
                    200,
                    json={"access_token": "newly_refreshed", "refresh_token": "next_refresh", "expires_in": 3600},
                )
            return httpx.Response(404)

        transport = httpx.MockTransport(refresh_ok_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            repo_refresh = FxaAuthRepository(client=client, token_store=store)
            status = await repo_refresh.restore_session()
            assert status == "ACTIVE"
            assert store.load_auth().access_token == "newly_refreshed"

        # 4. Expired access token with refresh token -> permanent rejection
        expired_bad = RuntimeAuth(
            access_token="expired_acc_2",
            refresh_token="bad_refresh",
            expires_at_epoch_seconds=int(time.time()) - 100,
        )
        store.save_auth(expired_bad)

        def refresh_fail_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(400, json={"message": "Invalid grant"})

        transport_fail = httpx.MockTransport(refresh_fail_handler)
        async with httpx.AsyncClient(transport=transport_fail) as client:
            repo_fail = FxaAuthRepository(client=client, token_store=store)
            status = await repo_fail.restore_session()
            assert status == "NEEDS_LOGIN"
            assert store.load_auth() is None

    @pytest.mark.asyncio
    async def test_submit_2fa_missing_session_raises(self) -> None:
        repo = FxaAuthRepository()
        with pytest.raises(ValueError, match="No session token provided or pending"):
            await repo.submit_2fa(code="123456")

    @pytest.mark.asyncio
    async def test_fxa_api_error_non_json_response(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(502, text="Bad Gateway (HTML error)")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            repo = FxaAuthRepository(client=client)
            with pytest.raises(FxaApiError) as exc_info:
                await repo.login("test@badgateway.com", "pass")
            assert exc_info.value.status_code == 502
            assert "Bad Gateway" in exc_info.value.message
