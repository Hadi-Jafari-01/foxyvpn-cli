"""Unit tests for FoxyVPN Click Command-Line Interface."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner

from foxyvpn.cli import cli
from foxyvpn.core.models import (
    ConnectionState,
    Entitlement,
    ProxyCandidate,
    ProxyPass,
    RuntimeAuth,
    VpnCity,
    VpnCountry,
    VpnServerNode,
)
from foxyvpn.core.store import SettingsStore, TokenStore


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


# ===========================================================================
# 1. Root Group & Help Tests
# ===========================================================================


class TestCliBasics:
    def test_version_flag(self, runner: CliRunner):
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "v1.0.0" in result.output

    def test_help_command(self, runner: CliRunner):
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "FoxyVPN" in result.output
        assert "login" in result.output
        assert "connect" in result.output
        assert "disconnect" in result.output
        assert "locations" in result.output

    def test_invoked_without_command_shows_help(self, runner: CliRunner):
        result = runner.invoke(cli, [])
        assert result.exit_code == 0
        assert "Usage:" in result.output or "Options:" in result.output


# ===========================================================================
# 2. Login & Logout Tests
# ===========================================================================


class TestCliAuth:
    def test_login_success_no_2fa(self, runner: CliRunner, tmp_path: Path):
        mock_auth = RuntimeAuth(
            access_token="test_token",
            refresh_token="test_refresh",
            expires_at_epoch_seconds=1800000000,
            email="user@mozilla.com",
        )

        with patch("foxyvpn.cli.TokenStore") as mock_ts_cls, \
             patch("foxyvpn.cli.FxaAuthRepository") as mock_fxa_cls:
            mock_ts = MagicMock()
            mock_ts_cls.return_value = mock_ts

            mock_fxa = MagicMock()
            mock_fxa.__aenter__.return_value = mock_fxa
            mock_fxa.login = AsyncMock(return_value=(False, mock_auth))
            mock_fxa_cls.return_value = mock_fxa

            result = runner.invoke(
                cli,
                ["login", "--email", "user@mozilla.com", "--password", "SecretPass123"],
            )
            assert result.exit_code == 0
            assert "Successfully logged in as user@mozilla.com" in result.output
            mock_ts.save_auth.assert_called_once()

    def test_login_success_with_2fa(self, runner: CliRunner, tmp_path: Path):
        mock_auth = RuntimeAuth(
            access_token="test_token_2fa",
            refresh_token="test_refresh",
            expires_at_epoch_seconds=1800000000,
            email="2fa_user@mozilla.com",
        )

        with patch("foxyvpn.cli.TokenStore") as mock_ts_cls, \
             patch("foxyvpn.cli.FxaAuthRepository") as mock_fxa_cls:
            mock_ts = MagicMock()
            mock_ts_cls.return_value = mock_ts

            mock_fxa = MagicMock()
            mock_fxa.__aenter__.return_value = mock_fxa
            # Step 1 returns needs_2fa=True with session token
            mock_fxa.login = AsyncMock(return_value=(True, "session_token_xyz"))
            mock_fxa.submit_2fa = AsyncMock(return_value=mock_auth)
            mock_fxa_cls.return_value = mock_fxa

            result = runner.invoke(
                cli,
                [
                    "login",
                    "--email",
                    "2fa_user@mozilla.com",
                    "--password",
                    "SecretPass123",
                    "--code",
                    "123456",
                ],
            )
            assert result.exit_code == 0
            assert "Successfully logged in as 2fa_user@mozilla.com" in result.output
            mock_fxa.submit_2fa.assert_called_once_with(
                session_token="session_token_xyz", code="123456"
            )

    def test_login_failure(self, runner: CliRunner):
        with patch("foxyvpn.cli.FxaAuthRepository") as mock_fxa_cls:
            mock_fxa = MagicMock()
            mock_fxa.__aenter__.return_value = mock_fxa
            mock_fxa.login = AsyncMock(side_effect=RuntimeError("Invalid credentials"))
            mock_fxa_cls.return_value = mock_fxa

            result = runner.invoke(
                cli,
                ["login", "--email", "fail@mozilla.com", "--password", "WrongPass"],
            )
            assert result.exit_code != 0
            assert "Login failed" in result.output

    def test_logout(self, runner: CliRunner):
        with patch("foxyvpn.cli.TokenStore") as mock_ts_cls, \
             patch("foxyvpn.cli.DaemonManager") as mock_dm_cls, \
             patch("foxyvpn.cli.SystemProxyManager") as mock_sp_cls:
            mock_ts = MagicMock()
            mock_ts_cls.return_value = mock_ts

            mock_dm = MagicMock()
            mock_dm.is_daemon_running.return_value = True
            mock_dm_cls.return_value = mock_dm

            mock_sp = MagicMock()
            mock_sp.is_system_proxy_enabled.return_value = True
            mock_sp_cls.return_value = mock_sp

            result = runner.invoke(cli, ["logout"])
            assert result.exit_code == 0
            assert "Logged out successfully" in result.output
            mock_ts.clear.assert_called_once()
            mock_dm.stop_daemon.assert_called_once()
            mock_sp.disable_system_proxy.assert_called_once()


# ===========================================================================
# 3. Status & Quota Tests
# ===========================================================================


class TestCliStatusAndQuota:
    def test_status_logged_out(self, runner: CliRunner):
        with patch("foxyvpn.cli.TokenStore") as mock_ts_cls, \
             patch("foxyvpn.cli.DaemonManager") as mock_dm_cls:
            mock_ts = MagicMock()
            mock_ts.load_auth.return_value = None
            mock_ts_cls.return_value = mock_ts

            mock_dm = MagicMock()
            mock_dm.load_state.return_value = None
            mock_dm.is_daemon_running.return_value = False
            mock_dm_cls.return_value = mock_dm

            result = runner.invoke(cli, ["status"])
            assert result.exit_code == 0
            assert "Not logged in" in result.output
            assert "DISCONNECTED" in result.output

    def test_status_connected(self, runner: CliRunner):
        auth = RuntimeAuth(
            access_token="acc",
            refresh_token="ref",
            expires_at_epoch_seconds=1900000000,
            email="connected_user@mozilla.com",
        )
        state_dict = {
            "status": "CONNECTED",
            "location": "Berlin (DE)",
            "edge_ip": "1.2.3.4",
            "server_hostname": "de-ber-01.vpn.mozilla.org",
            "socks_port": 10808,
            "bytes_sent": 5000,
            "bytes_received": 15000,
            "start_time": 1700000000.0,
        }
        entitlement = Entitlement(
            subscribed=True,
            uid="uid",
            max_bytes=None,
            limited_bandwidth=False,
        )

        with patch("foxyvpn.cli.TokenStore") as mock_ts_cls, \
             patch("foxyvpn.cli.DaemonManager") as mock_dm_cls, \
             patch("foxyvpn.cli.GuardianClient") as mock_gc_cls:
            mock_ts = MagicMock()
            mock_ts.load_auth.return_value = auth
            mock_ts_cls.return_value = mock_ts

            mock_dm = MagicMock()
            mock_dm.load_state.return_value = state_dict
            mock_dm.is_daemon_running.return_value = True
            mock_dm_cls.return_value = mock_dm

            mock_gc = MagicMock()
            mock_gc.__aenter__.return_value = mock_gc
            mock_gc.fetch_user_info = AsyncMock(return_value=entitlement)
            mock_gc_cls.return_value = mock_gc

            result = runner.invoke(cli, ["status"])
            assert result.exit_code == 0
            assert "connected_user@mozilla.com" in result.output
            assert "Berlin (DE)" in result.output
            assert "CONNECTED" in result.output

    def test_quota_not_logged_in(self, runner: CliRunner):
        with patch("foxyvpn.cli.TokenStore") as mock_ts_cls:
            mock_ts = MagicMock()
            mock_ts.load_auth.return_value = None
            mock_ts_cls.return_value = mock_ts

            result = runner.invoke(cli, ["quota"])
            assert result.exit_code != 0
            assert "Not logged in" in result.output

    def test_quota_success(self, runner: CliRunner):
        auth = RuntimeAuth(
            access_token="acc",
            refresh_token="ref",
            expires_at_epoch_seconds=1900000000,
            email="user@mozilla.com",
        )
        ent = Entitlement(
            subscribed=False,
            uid="uid",
            max_bytes=10 * 1024 * 1024 * 1024,
            limited_bandwidth=True,
            quota_remaining=5 * 1024 * 1024 * 1024,
        )
        pass_data = ProxyPass(
            token="tok",
            quota_max=10 * 1024 * 1024 * 1024,
            quota_remaining=5 * 1024 * 1024 * 1024,
            quota_reset=1800000000,
        )

        with patch("foxyvpn.cli.TokenStore") as mock_ts_cls, \
             patch("foxyvpn.cli.GuardianClient") as mock_gc_cls:
            mock_ts = MagicMock()
            mock_ts.load_auth.return_value = auth
            mock_ts_cls.return_value = mock_ts

            mock_gc = MagicMock()
            mock_gc.__aenter__.return_value = mock_gc
            mock_gc.fetch_user_info = AsyncMock(return_value=ent)
            mock_gc.fetch_proxy_pass = AsyncMock(return_value=pass_data)
            mock_gc_cls.return_value = mock_gc

            result = runner.invoke(cli, ["quota"])
            assert result.exit_code == 0
            assert "Bandwidth Quota" in result.output
            assert "5.00 GB" in result.output


# ===========================================================================
# 4. Locations & Servers Tests
# ===========================================================================


class TestCliLocations:
    def test_locations_without_ping(self, runner: CliRunner):
        countries = [
            VpnCountry(
                name="Switzerland",
                code="CH",
                cities=[
                    VpnCity(
                        name="Zurich",
                        code="zrh",
                        servers=[VpnServerNode(hostname="ch-zrh-01.vpn.mozilla.org", port=443)],
                    )
                ],
            )
        ]

        with patch("foxyvpn.cli.ServerListClient") as mock_sl_cls:
            mock_sl = MagicMock()
            mock_sl.__aenter__.return_value = mock_sl
            mock_sl.fetch_countries = AsyncMock(return_value=countries)
            mock_sl_cls.return_value = mock_sl

            result = runner.invoke(cli, ["locations"])
            assert result.exit_code == 0
            assert "Switzerland" in result.output
            assert "CH" in result.output

    def test_servers_alias_with_ping(self, runner: CliRunner):
        countries = [
            VpnCountry(
                name="Japan",
                code="JP",
                cities=[
                    VpnCity(
                        name="Tokyo",
                        code="tyo",
                        servers=[VpnServerNode(hostname="jp-tyo-01.vpn.mozilla.org", port=443)],
                    )
                ],
            )
        ]

        with patch("foxyvpn.cli.ServerListClient") as mock_sl_cls, \
             patch("foxyvpn.cli.ping_server", new_callable=AsyncMock) as mock_ping:
            mock_sl = MagicMock()
            mock_sl.__aenter__.return_value = mock_sl
            mock_sl.fetch_countries = AsyncMock(return_value=countries)
            mock_sl_cls.return_value = mock_sl
            mock_ping.return_value = 85.5

            result = runner.invoke(cli, ["servers", "--ping"])
            assert result.exit_code == 0
            assert "Japan" in result.output
            assert "85.5" in result.output


# ===========================================================================
# 5. Connect & Disconnect Tests
# ===========================================================================


class TestCliConnectDisconnect:
    def test_connect_not_logged_in(self, runner: CliRunner):
        with patch("foxyvpn.cli.TokenStore") as mock_ts_cls:
            mock_ts = MagicMock()
            mock_ts.has_stored_session.return_value = False
            mock_ts_cls.return_value = mock_ts

            result = runner.invoke(cli, ["connect"])
            assert result.exit_code != 0
            assert "Not logged in" in result.output

    def test_connect_daemon_spawn(self, runner: CliRunner):
        with patch("foxyvpn.cli.DaemonManager") as mock_dm_cls:
            mock_dm = MagicMock()
            mock_dm.is_daemon_running.return_value = False
            mock_dm.spawn_daemon.return_value = 9999
            mock_dm_cls.return_value = mock_dm

            result = runner.invoke(cli, ["connect", "--daemon", "--country", "US"])
            assert result.exit_code == 0
            assert "Started FoxyVPN background daemon with PID 9999" in result.output
            mock_dm.spawn_daemon.assert_called_once()

    def test_connect_daemon_already_running(self, runner: CliRunner):
        with patch("foxyvpn.cli.DaemonManager") as mock_dm_cls:
            mock_dm = MagicMock()
            mock_dm.is_daemon_running.return_value = True
            mock_dm_cls.return_value = mock_dm

            result = runner.invoke(cli, ["connect", "--daemon"])
            assert result.exit_code == 0
            assert "already running" in result.output

    def test_disconnect_active_session(self, runner: CliRunner):
        with patch("foxyvpn.cli.DaemonManager") as mock_dm_cls, \
             patch("foxyvpn.cli.SystemProxyManager") as mock_sp_cls:
            mock_dm = MagicMock()
            mock_dm.is_daemon_running.return_value = True
            mock_dm_cls.return_value = mock_dm

            mock_sp = MagicMock()
            mock_sp.is_system_proxy_enabled.return_value = True
            mock_sp_cls.return_value = mock_sp

            result = runner.invoke(cli, ["disconnect"])
            assert result.exit_code == 0
            assert "Successfully disconnected" in result.output
            mock_dm.stop_daemon.assert_called_once()
            mock_sp.disable_system_proxy.assert_called_once()

    def test_disconnect_inactive(self, runner: CliRunner):
        with patch("foxyvpn.cli.DaemonManager") as mock_dm_cls, \
             patch("foxyvpn.cli.SystemProxyManager") as mock_sp_cls:
            mock_dm = MagicMock()
            mock_dm.is_daemon_running.return_value = False
            mock_dm_cls.return_value = mock_dm

            mock_sp = MagicMock()
            mock_sp.is_system_proxy_enabled.return_value = False
            mock_sp_cls.return_value = mock_sp

            result = runner.invoke(cli, ["disconnect"])
            assert result.exit_code == 0
            assert "not actively connected" in result.output


# ===========================================================================
# 6. Verify & Test Command Tests
# ===========================================================================


class TestCliVerify:
    def test_verify_success(self, runner: CliRunner):
        trace_data = {
            "ip": "195.181.160.10",
            "country": "DE",
            "verified": True,
            "details": {"fl": "123f", "colo": "FRA"},
        }
        with patch("foxyvpn.cli.ExitChecker") as mock_ec_cls:
            mock_ec = MagicMock()
            mock_ec.check_exit = AsyncMock(return_value=trace_data)
            mock_ec_cls.return_value = mock_ec

            result = runner.invoke(cli, ["verify", "--port", "10808"])
            assert result.exit_code == 0
            assert "195.181.160.10" in result.output
            assert "Exit node verified successfully" in result.output

    def test_test_alias_failure(self, runner: CliRunner):
        with patch("foxyvpn.cli.ExitChecker") as mock_ec_cls:
            mock_ec = MagicMock()
            mock_ec.check_exit = AsyncMock(side_effect=RuntimeError("SOCKS proxy connection refused"))
            mock_ec_cls.return_value = mock_ec

            result = runner.invoke(cli, ["test", "--port", "10808"])
            assert result.exit_code != 0
            assert "Verification failed" in result.output


# ===========================================================================
# 7. Config Subcommands Tests
# ===========================================================================


class TestCliConfig:
    def test_config_show(self, runner: CliRunner):
        result = runner.invoke(cli, ["config", "show"])
        assert result.exit_code == 0
        assert "FoxyVPN Settings" in result.output
        assert "socks_port" in result.output

    def test_config_get_and_set(self, runner: CliRunner, tmp_path: Path):
        with patch("foxyvpn.cli.SettingsStore") as mock_store_cls:
            mock_store = MagicMock()
            mock_store.get.return_value = 10808
            mock_store_cls.return_value = mock_store

            # Test get
            res_get = runner.invoke(cli, ["config", "get", "socks_port"])
            assert res_get.exit_code == 0
            assert "10808" in res_get.output

            # Test set
            res_set = runner.invoke(cli, ["config", "set", "socks_port", "10999"])
            assert res_set.exit_code == 0
            assert "Updated socks_port = 10999" in res_set.output
            mock_store.set.assert_called_with("socks_port", 10999)
