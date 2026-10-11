"""Unit tests for Web Browser Authentication and Token Export/Import."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from foxyvpn.auth.web_auth import WebAuthServer
from foxyvpn.core.models import RuntimeAuth
from foxyvpn.core.store import TokenStore


def test_token_export_and_import(tmp_path):
    store1 = TokenStore(tmp_path / "tokens1.json")
    store2 = TokenStore(tmp_path / "tokens2.json")

    auth = RuntimeAuth(
        access_token="test_access_jwt_123",
        refresh_token="test_refresh_token_456",
        expires_at_epoch_seconds=1800000000,
        email="browser_user@mozilla.com",
    )
    store1.save_auth(auth)

    exported = store1.export_token()
    assert isinstance(exported, str)
    assert len(exported) > 20

    # Import into store2
    imported = store2.import_token(exported)
    assert imported.access_token == "test_access_jwt_123"
    assert imported.refresh_token == "test_refresh_token_456"
    assert imported.email == "browser_user@mozilla.com"
    assert imported.expires_at_epoch_seconds == 1800000000

    loaded = store2.load_auth()
    assert loaded is not None
    assert loaded.email == "browser_user@mozilla.com"


@pytest.mark.asyncio
async def test_web_auth_server_html_page(tmp_path):
    store = TokenStore(tmp_path / "tokens.json")
    server = WebAuthServer(token_store=store, port=18765, host="127.0.0.1")

    url = await server.start()
    assert "http://127.0.0.1:18765" in url or f":{server.port}" in url

    try:
        async with httpx.AsyncClient(trust_env=False) as client:
            resp = await client.get(f"http://127.0.0.1:{server.port}/")
            assert resp.status_code == 200
            assert "FoxyVPN Sign In" in resp.text
            assert "Firefox Account Email" in resp.text
            assert "twofactor-step" in resp.text
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_web_auth_server_api_login_direct(tmp_path):
    store = TokenStore(tmp_path / "tokens.json")
    server = WebAuthServer(token_store=store, port=18766, host="127.0.0.1")

    mock_auth = RuntimeAuth(
        access_token="mock_access_token",
        refresh_token="mock_refresh_token",
        expires_at_epoch_seconds=1800000000,
        email="web_user@test.org",
    )

    with patch.object(server.fxa_repo, "login", new_callable=AsyncMock) as mock_login:
        mock_login.return_value = (False, mock_auth)

        await server.start()
        try:
            async with httpx.AsyncClient(trust_env=False) as client:
                resp = await client.post(
                    f"http://127.0.0.1:{server.port}/api/login",
                    json={"email": "web_user@test.org", "password": "supersecretpassword"},
                )
                assert resp.status_code == 200
                data = resp.json()
                assert data.get("success") is True
                assert data.get("email") == "web_user@test.org"

            # Check completion
            finished_auth = await server.wait_for_completion(timeout=2.0)
            assert finished_auth is not None
            assert finished_auth.email == "web_user@test.org"
            assert store.load_auth().email == "web_user@test.org"
        finally:
            await server.stop()


@pytest.mark.asyncio
async def test_web_auth_server_api_2fa_flow(tmp_path):
    store = TokenStore(tmp_path / "tokens.json")
    server = WebAuthServer(token_store=store, port=18767, host="127.0.0.1")

    mock_auth = RuntimeAuth(
        access_token="final_2fa_token",
        refresh_token="final_refresh",
        expires_at_epoch_seconds=1800000000,
        email="twofa_user@test.org",
    )

    with patch.object(server.fxa_repo, "login", new_callable=AsyncMock) as mock_login, \
         patch.object(server.fxa_repo, "submit_2fa", new_callable=AsyncMock) as mock_submit_2fa:

        # Step 1: Login triggers 2FA
        mock_login.return_value = (True, "pending_session_abc123")
        mock_submit_2fa.return_value = mock_auth

        await server.start()
        try:
            async with httpx.AsyncClient(trust_env=False) as client:
                # 1. First step returns needs_2fa
                resp1 = await client.post(
                    f"http://127.0.0.1:{server.port}/api/login",
                    json={"email": "twofa_user@test.org", "password": "pw"},
                )
                assert resp1.status_code == 200
                d1 = resp1.json()
                assert d1.get("needs_2fa") is True
                assert d1.get("session_token") == "pending_session_abc123"

                # 2. Second step submits 2FA code
                resp2 = await client.post(
                    f"http://127.0.0.1:{server.port}/api/2fa",
                    json={"session_token": "pending_session_abc123", "code": "654321"},
                )
                assert resp2.status_code == 200
                d2 = resp2.json()
                assert d2.get("success") is True

            finished_auth = await server.wait_for_completion(timeout=2.0)
            assert finished_auth is not None
            assert finished_auth.email == "twofa_user@test.org"
            assert store.load_auth().access_token == "final_2fa_token"
        finally:
            await server.stop()
