"""Unit tests for SystemProxyManager, DaemonManager, and UI Formatters."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest
from rich.console import Console

from foxyvpn.core.models import (
    ConnectionState,
    Entitlement,
    ProxyCandidate,
    RuntimeAuth,
    VpnCity,
    VpnCountry,
    VpnServerNode,
)
from foxyvpn.system.daemon import (
    DaemonManager,
    is_daemon_running,
    stop_daemon,
)
from foxyvpn.system.proxy import (
    INTERNET_OPTION_REFRESH,
    INTERNET_OPTION_SETTINGS_CHANGED,
    SystemProxyManager,
    disable_system_proxy,
    enable_system_proxy,
    get_env_proxy_commands,
    is_system_proxy_enabled,
)
from foxyvpn.ui.formatters import (
    format_bytes,
    format_quota_bar,
    format_servers_table,
    format_speed,
    format_status_table,
    print_banner,
    render_dashboard,
)


# ===========================================================================
# 1. SystemProxyManager Tests
# ===========================================================================


class TestSystemProxyManager:
    def test_init_and_platform_detection(self):
        mgr = SystemProxyManager()
        assert mgr.platform == sys.platform.lower()

        custom_mgr = SystemProxyManager(platform="Darwin")
        assert custom_mgr.platform == "darwin"

    def test_get_env_proxy_commands(self):
        commands = SystemProxyManager.get_env_proxy_commands("127.0.0.1", 10808)
        assert "bash" in commands
        assert "sh" in commands
        assert "zsh" in commands
        assert "fish" in commands
        assert "powershell" in commands
        assert "cmd" in commands

        assert 'export all_proxy="socks5h://127.0.0.1:10808"' in commands["bash"]
        assert '$env:all_proxy="socks5h://127.0.0.1:10808"' in commands["powershell"]
        assert "set all_proxy=socks5h://127.0.0.1:10808" in commands["cmd"]
        assert 'set -gx all_proxy "socks5h://127.0.0.1:10808"' in commands["fish"]

        # Module-level shortcut
        shortcut_cmds = get_env_proxy_commands("10.0.0.1", 9050)
        assert "socks5h://10.0.0.1:9050" in shortcut_cmds["bash"]

    # --- Windows Proxy Tests ---

    def test_windows_enable_success(self):
        mgr = SystemProxyManager(platform="win32")
        mock_winreg = MagicMock()
        mock_key = MagicMock()
        mock_winreg.CreateKeyEx.return_value = mock_key
        mock_winreg.HKEY_CURRENT_USER = 1
        mock_winreg.KEY_SET_VALUE = 2
        mock_winreg.KEY_QUERY_VALUE = 4
        mock_winreg.REG_DWORD = "DWORD"
        mock_winreg.REG_SZ = "SZ"

        with patch("foxyvpn.system.proxy.winreg", mock_winreg), \
             patch.object(mgr, "_refresh_windows_wininet") as mock_refresh:
            res = mgr._enable_windows("127.0.0.1", 10808)
            assert res is True
            mock_winreg.SetValueEx.assert_any_call(mock_key, "ProxyEnable", 0, "DWORD", 1)
            mock_winreg.SetValueEx.assert_any_call(mock_key, "ProxyServer", 0, "SZ", "socks=127.0.0.1:10808")
            mock_winreg.CloseKey.assert_called_once_with(mock_key)
            mock_refresh.assert_called_once()

    def test_windows_disable_success(self):
        mgr = SystemProxyManager(platform="win32")
        mock_winreg = MagicMock()
        mock_key = MagicMock()
        mock_winreg.CreateKeyEx.return_value = mock_key
        mock_winreg.HKEY_CURRENT_USER = 1
        mock_winreg.REG_DWORD = "DWORD"

        with patch("foxyvpn.system.proxy.winreg", mock_winreg), \
             patch.object(mgr, "_refresh_windows_wininet") as mock_refresh:
            res = mgr._disable_windows()
            assert res is True
            mock_winreg.SetValueEx.assert_called_with(mock_key, "ProxyEnable", 0, "DWORD", 0)
            mock_winreg.CloseKey.assert_called_once_with(mock_key)
            mock_refresh.assert_called_once()

    def test_windows_is_enabled(self):
        mgr = SystemProxyManager(platform="win32")
        mock_winreg = MagicMock()
        mock_key = MagicMock()
        mock_winreg.OpenKey.return_value = mock_key

        with patch("foxyvpn.system.proxy.winreg", mock_winreg):
            # When ProxyEnable == 1
            mock_winreg.QueryValueEx.return_value = (1, 4)
            assert mgr._is_enabled_windows() is True

            # When ProxyEnable == 0
            mock_winreg.QueryValueEx.return_value = (0, 4)
            assert mgr._is_enabled_windows() is False

            # On registry error
            mock_winreg.QueryValueEx.side_effect = OSError("Key not found")
            assert mgr._is_enabled_windows() is False

    def test_windows_missing_winreg(self):
        mgr = SystemProxyManager(platform="win32")
        with patch("foxyvpn.system.proxy.winreg", None):
            assert mgr._enable_windows("127.0.0.1", 10808) is False
            assert mgr._disable_windows() is False
            assert mgr._is_enabled_windows() is False

    def test_windows_wininet_refresh(self):
        mgr = SystemProxyManager(platform="win32")
        mock_ctypes = MagicMock()
        mock_wininet = MagicMock()
        mock_ctypes.windll.wininet = mock_wininet

        with patch("foxyvpn.system.proxy.ctypes", mock_ctypes):
            mgr._refresh_windows_wininet()
            assert mock_wininet.InternetSetOptionW.call_count == 2
            mock_wininet.InternetSetOptionW.assert_any_call(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
            mock_wininet.InternetSetOptionW.assert_any_call(0, INTERNET_OPTION_REFRESH, 0, 0)

    # --- macOS Proxy Tests ---

    def test_macos_get_interfaces(self):
        mgr = SystemProxyManager(platform="darwin")
        sample_output = (
            "An asterisk (*) denotes that a network service is disabled.\n"
            "(1) Wi-Fi\n"
            "(Hardware Port: Wi-Fi, Device: en0)\n\n"
            "(2) Thunderbolt Ethernet\n"
            "(Hardware Port: Thunderbolt Ethernet, Device: en5)\n"
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=sample_output)
            ifaces = mgr._get_macos_interfaces()
            assert ifaces == ["Wi-Fi", "Thunderbolt Ethernet"]

    def test_macos_get_interfaces_fallback(self):
        mgr = SystemProxyManager(platform="darwin")
        with patch("subprocess.run", side_effect=OSError("Command not found")):
            ifaces = mgr._get_macos_interfaces()
            assert ifaces == ["Wi-Fi", "Ethernet"]

    def test_macos_enable_and_disable(self):
        mgr = SystemProxyManager(platform="darwin")
        with patch.object(mgr, "_get_macos_interfaces", return_value=["Wi-Fi"]), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="")
            assert mgr._enable_macos("127.0.0.1", 10808) is True
            assert mock_run.call_count == 2

            mock_run.reset_mock()
            assert mgr._disable_macos() is True
            assert mock_run.call_count == 1

    def test_macos_is_enabled(self):
        mgr = SystemProxyManager(platform="darwin")
        with patch.object(mgr, "_get_macos_interfaces", return_value=["Wi-Fi"]), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="Enabled: Yes\nServer: 127.0.0.1\nPort: 10808")
            assert mgr._is_enabled_macos() is True

            mock_run.return_value = MagicMock(returncode=0, stdout="Enabled: No\n")
            assert mgr._is_enabled_macos() is False

    # --- Linux Proxy Tests ---

    def test_linux_enable_and_disable(self):
        mgr = SystemProxyManager(platform="linux")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="")
            assert mgr._enable_linux("127.0.0.1", 10808) is True
            assert mock_run.call_count == 3

            mock_run.reset_mock()
            assert mgr._disable_linux() is True
            assert mock_run.call_count == 1

    def test_linux_is_enabled(self):
        mgr = SystemProxyManager(platform="linux")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="'manual'\n")
            assert mgr._is_enabled_linux() is True

            mock_run.return_value = MagicMock(returncode=0, stdout="'none'\n")
            assert mgr._is_enabled_linux() is False

    # --- Dispatcher Tests ---

    def test_dispatcher_routes(self):
        mgr_win = SystemProxyManager(platform="win32")
        with patch.object(mgr_win, "_enable_windows", return_value=True) as m1, \
             patch.object(mgr_win, "_disable_windows", return_value=True) as m2, \
             patch.object(mgr_win, "_is_enabled_windows", return_value=True) as m3:
            assert mgr_win.enable_system_proxy("1.2.3.4", 8080) is True
            m1.assert_called_with("1.2.3.4", 8080)
            assert mgr_win.disable_system_proxy() is True
            m2.assert_called_once()
            assert mgr_win.is_system_proxy_enabled() is True
            m3.assert_called_once()

        mgr_mac = SystemProxyManager(platform="darwin")
        with patch.object(mgr_mac, "_enable_macos", return_value=True) as m1:
            assert mgr_mac.enable_system_proxy() is True
            m1.assert_called_once()

        mgr_linux = SystemProxyManager(platform="linux")
        with patch.object(mgr_linux, "_enable_linux", return_value=True) as m1:
            assert mgr_linux.enable_system_proxy() is True
            m1.assert_called_once()

        mgr_unknown = SystemProxyManager(platform="freebsd")
        assert mgr_unknown.enable_system_proxy() is False
        assert mgr_unknown.disable_system_proxy() is False
        assert mgr_unknown.is_system_proxy_enabled() is False

    def test_module_level_helpers(self):
        with patch("foxyvpn.system.proxy._default_manager") as mock_mgr:
            mock_mgr.enable_system_proxy.return_value = True
            mock_mgr.disable_system_proxy.return_value = True
            mock_mgr.is_system_proxy_enabled.return_value = False

            assert enable_system_proxy("127.0.0.1", 10808) is True
            assert disable_system_proxy() is True
            assert is_system_proxy_enabled() is False


# ===========================================================================
# 2. DaemonManager Tests
# ===========================================================================


class TestDaemonManager:
    def test_pid_lifecycle(self, tmp_path: Path):
        dm = DaemonManager(config_dir=tmp_path)
        assert dm.get_pid() is None

        # Write current PID
        dm.write_pid(12345)
        assert dm.get_pid() == 12345

        # Check PID file content
        assert (tmp_path / "daemon.pid").read_text().strip() == "12345"

        # Remove PID
        dm.remove_pid()
        assert dm.get_pid() is None
        assert not (tmp_path / "daemon.pid").exists()

    def test_is_pid_running_current_process(self, tmp_path: Path):
        dm = DaemonManager(config_dir=tmp_path)
        assert dm.is_pid_running(os.getpid()) is True
        assert dm.is_pid_running(0) is False
        assert dm.is_pid_running(-100) is False

    def test_is_pid_running_permission_error(self, tmp_path: Path):
        dm = DaemonManager(config_dir=tmp_path)
        with patch("os.kill", side_effect=PermissionError("Access denied")):
            assert dm.is_pid_running(9999) is True

    def test_is_pid_running_dead_process(self, tmp_path: Path):
        dm = DaemonManager(config_dir=tmp_path)
        with patch("os.kill", side_effect=ProcessLookupError()):
            assert dm.is_pid_running(999999) is False

    def test_is_daemon_running_clean_up_stale(self, tmp_path: Path):
        dm = DaemonManager(config_dir=tmp_path)
        dm.write_pid(888888)

        with patch.object(dm, "is_pid_running", return_value=False):
            assert dm.is_daemon_running() is False
            # PID file should have been cleaned up automatically
            assert dm.get_pid() is None

    def test_is_daemon_running_active(self, tmp_path: Path):
        dm = DaemonManager(config_dir=tmp_path)
        dm.write_pid(os.getpid())
        assert dm.is_daemon_running() is True

    def test_save_and_load_state(self, tmp_path: Path):
        dm = DaemonManager(config_dir=tmp_path)
        assert dm.load_state() is None

        state = ConnectionState(
            status="CONNECTED",
            location="Frankfurt (DE)",
            edge_ip="195.181.160.10",
            server_hostname="de-fra-wg-001.vpn.mozilla.org",
            socks_port=10808,
            bytes_sent=1024,
            bytes_received=2048,
            start_time=1700000000.0,
        )
        dm.save_state(state)

        loaded = dm.load_state()
        assert loaded is not None
        assert loaded["status"] == "CONNECTED"
        assert loaded["location"] == "Frankfurt (DE)"
        assert loaded["edge_ip"] == "195.181.160.10"
        assert loaded["bytes_sent"] == 1024
        assert loaded["bytes_received"] == 2048

        dm.remove_state()
        assert dm.load_state() is None

    def test_stop_daemon_not_running(self, tmp_path: Path):
        dm = DaemonManager(config_dir=tmp_path)
        assert dm.stop_daemon() is False

    def test_stop_daemon_successful(self, tmp_path: Path):
        dm = DaemonManager(config_dir=tmp_path)
        dm.write_pid(12345)
        dm.save_state({"status": "CONNECTED"})

        # Process alive on first check, dead on second check
        running_checks = [True, False]

        def mock_is_running(pid: int) -> bool:
            if running_checks:
                return running_checks.pop(0)
            return False

        with patch.object(dm, "is_pid_running", side_effect=mock_is_running), \
             patch("os.kill") as mock_kill, \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            res = dm.stop_daemon(timeout_seconds=1.0)
            assert res is True
            assert dm.get_pid() is None
            assert dm.load_state() is None

    def test_spawn_daemon(self, tmp_path: Path):
        dm = DaemonManager(config_dir=tmp_path)
        mock_proc = MagicMock(pid=54321)

        with patch("subprocess.Popen", return_value=mock_proc) as mock_popen:
            pid = dm.spawn_daemon(["python", "-m", "foxyvpn.cli"])
            assert pid == 54321
            mock_popen.assert_called_once()
            assert dm.get_pid() == 54321


# ===========================================================================
# 3. UI Formatters Tests
# ===========================================================================


class TestUIFormatters:
    def test_format_bytes(self):
        assert format_bytes(None) == "N/A"
        assert format_bytes("invalid") == "N/A"
        assert format_bytes(0) == "0 B"
        assert format_bytes(500) == "500 B"
        assert format_bytes(1024) == "1.00 KB"
        assert format_bytes(1048576) == "1.00 MB"
        assert format_bytes(1073741824) == "1.00 GB"

    def test_format_speed(self):
        assert format_speed(None) == "0 B/s"
        assert format_speed(-10) == "0 B/s"
        assert format_speed(1048576) == "1.00 MB/s"

    def test_print_banner(self):
        console = Console(record=True)
        print_banner(console)
        output = console.export_text()
        assert "Firefox" in output or "VPN" in output

    def test_format_quota_bar_unlimited(self):
        panel = format_quota_bar(remaining_bytes=None, max_bytes=None)
        console = Console(record=True)
        console.print(panel)
        out = console.export_text()
        assert "UNLIMITED" in out

    def test_format_quota_bar_limited(self):
        # 25 GB remaining out of 50 GB
        panel = format_quota_bar(
            remaining_bytes=25 * 1024 * 1024 * 1024,
            max_bytes=50 * 1024 * 1024 * 1024,
            reset_epoch=int(time.time() + 86400 * 3),
        )
        console = Console(record=True)
        console.print(panel)
        out = console.export_text()
        assert "50.0% used" in out
        assert "25.00 GB" in out
        assert "50.00 GB" in out
        assert "Resets In" in out

    def test_format_servers_table(self):
        country1 = VpnCountry(
            name="Germany",
            code="DE",
            cities=[
                VpnCity(name="Frankfurt", code="fra", servers=[
                    VpnServerNode(hostname="de-fra-01.vpn.mozilla.org", port=443)
                ])
            ],
        )
        country2 = VpnCountry(
            name="United States",
            code="US",
            cities=[
                VpnCity(name="New York", code="nyc", servers=[
                    VpnServerNode(hostname="us-nyc-01.vpn.mozilla.org", port=443)
                ])
            ],
        )

        pings = {"DE": 45.2, "US": 120.5}
        table = format_servers_table([country1, country2], pings=pings)

        console = Console(record=True)
        console.print(table)
        out = console.export_text()
        assert "Germany" in out
        assert "DE" in out
        assert "45.2" in out
        assert "United States" in out
        assert "120.5" in out

    def test_format_status_table(self):
        auth = RuntimeAuth(
            access_token="tok_test",
            refresh_token="ref_test",
            expires_at_epoch_seconds=int(time.time() + 3600),
            email="testuser@mozilla.com",
        )
        entitlement = Entitlement(
            subscribed=True,
            uid="uid_123",
            max_bytes=None,
            limited_bandwidth=False,
        )
        state = ConnectionState(
            status="CONNECTED",
            location="London (GB)",
            edge_ip="194.150.1.1",
            server_hostname="gb-lon-01.vpn.mozilla.org",
            socks_port=10808,
            bytes_sent=500000,
            bytes_received=1500000,
            start_time=time.time() - 120,
        )

        table = format_status_table(auth=auth, entitlement=entitlement, state=state)
        console = Console(record=True)
        console.print(table)
        out = console.export_text()
        assert "testuser@mozilla.com" in out
        assert "Subscribed" in out
        assert "Unlimited" in out
        assert "CONNECTED" in out
        assert "London (GB)" in out
        assert "194.150.1.1" in out

    def test_render_dashboard(self):
        candidate = ProxyCandidate(
            host="se-sto-01.vpn.mozilla.org",
            port=443,
            country_code="SE",
            country_name="Sweden",
            city_code="sto",
        )
        state = ConnectionState(
            status="CONNECTED",
            location="Stockholm (SE)",
            edge_ip="185.20.1.1",
            server_hostname="se-sto-01.vpn.mozilla.org",
            socks_port=10808,
            bytes_sent=1048576,
            bytes_received=5242880,
            start_time=time.time() - 300,
        )
        panel = render_dashboard(
            candidate=candidate,
            state=state,
            speed_down=250000.0,
            speed_up=50000.0,
            system_proxy_active=True,
        )
        console = Console(record=True)
        console.print(panel)
        out = console.export_text()
        assert "Sweden (SE)" in out
        assert "se-sto-01.vpn.mozilla.org" in out
        assert "185.20.1.1" in out
        assert "ENABLED" in out
        assert "127.0.0.1:10808" in out
