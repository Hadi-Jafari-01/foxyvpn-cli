"""Unit tests for FoxyVPN Interactive Menu."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from foxyvpn.core.models import ConnectionState, RuntimeAuth
from foxyvpn.ui.menu import _get_status_summary, run_interactive_menu


def test_get_status_summary_logged_out():
    with patch("foxyvpn.ui.menu.TokenStore") as mock_ts_cls, \
         patch("foxyvpn.ui.menu.DaemonManager") as mock_dm_cls, \
         patch("foxyvpn.ui.menu.SystemProxyManager") as mock_pm_cls:

        mock_ts = MagicMock()
        mock_ts.load_auth.return_value = None
        mock_ts_cls.return_value = mock_ts

        mock_dm = MagicMock()
        mock_dm.is_daemon_running.return_value = False
        mock_dm_cls.return_value = mock_dm

        mock_pm = MagicMock()
        mock_pm.is_system_proxy_enabled.return_value = False
        mock_pm_cls.return_value = mock_pm

        acc, vpn, sys_p = _get_status_summary()
        assert "Not logged in" in acc
        assert "DISCONNECTED" in vpn
        assert "OFF" in sys_p


def test_get_status_summary_logged_in_and_connected():
    with patch("foxyvpn.ui.menu.TokenStore") as mock_ts_cls, \
         patch("foxyvpn.ui.menu.DaemonManager") as mock_dm_cls, \
         patch("foxyvpn.ui.menu.SystemProxyManager") as mock_pm_cls:

        mock_ts = MagicMock()
        mock_ts.load_auth.return_value = RuntimeAuth(
            access_token="tok",
            refresh_token="ref",
            expires_at_epoch_seconds=1800000000,
            email="user@test.org",
        )
        mock_ts_cls.return_value = mock_ts

        mock_dm = MagicMock()
        mock_dm.is_daemon_running.return_value = True
        mock_dm.load_state.return_value = ConnectionState(
            status="CONNECTED",
            location="United States (US)",
            socks_port=10808,
        )
        mock_dm_cls.return_value = mock_dm

        mock_pm = MagicMock()
        mock_pm.is_system_proxy_enabled.return_value = True
        mock_pm_cls.return_value = mock_pm

        acc, vpn, sys_p = _get_status_summary()
        assert "user@test.org" in acc
        assert "CONNECTED" in vpn
        assert "10808" in vpn
        assert "ON" in sys_p


def test_menu_exit_immediately():
    with patch("foxyvpn.ui.menu.Prompt.ask", return_value="0"), \
         patch("foxyvpn.ui.menu.print_banner"):
        # Should cleanly exit without throwing
        run_interactive_menu()


def test_menu_dispatch_status_then_exit():
    with patch("foxyvpn.ui.menu.Prompt.ask", side_effect=["4", "0"]), \
         patch("foxyvpn.ui.menu.handle_status") as mock_handle_status, \
         patch("foxyvpn.ui.menu.print_banner"):
        run_interactive_menu()
        assert mock_handle_status.call_count == 1


def test_menu_dispatch_disconnect_then_exit():
    with patch("foxyvpn.ui.menu.Prompt.ask", side_effect=["3", "Enter", "0"]), \
         patch("foxyvpn.ui.menu.handle_disconnect") as mock_handle_disconnect, \
         patch("foxyvpn.ui.menu.print_banner"):
        run_interactive_menu()
        assert mock_handle_disconnect.call_count == 1
