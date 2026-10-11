"""Cross-platform system proxy configuration manager.

Supports Windows (Registry + WinINet refresh), macOS (networksetup),
and Linux (GNOME gsettings), as well as environment variable proxy exports.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import sys
from typing import Any

try:
    import winreg
except ImportError:
    winreg = None  # type: ignore[assignment]

try:
    import ctypes
except ImportError:
    ctypes = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

# Windows WinINet InternetSetOption constants
INTERNET_OPTION_REFRESH = 37
INTERNET_OPTION_SETTINGS_CHANGED = 39
WINDOWS_INTERNET_SETTINGS_REG_KEY = (
    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
)


class SystemProxyManager:
    """Manages OS-level network proxy configuration cross-platform."""

    def __init__(self, platform: str | None = None) -> None:
        self.platform = (platform or sys.platform).lower()

    # --- Windows Implementation ---

    def _enable_windows(self, host: str, port: int) -> bool:
        if winreg is None:
            logger.warning("winreg module is unavailable; cannot configure Windows proxy")
            return False
        try:
            key = winreg.CreateKeyEx(
                winreg.HKEY_CURRENT_USER,
                WINDOWS_INTERNET_SETTINGS_REG_KEY,
                0,
                winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE,
            )
            proxy_server = f"socks={host}:{port}"
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy_server)
            winreg.CloseKey(key)

            # Refresh Windows system proxy cache
            self._refresh_windows_wininet()
            logger.info("Enabled Windows system proxy: %s", proxy_server)
            return True
        except Exception as exc:
            logger.error("Failed to enable Windows system proxy: %s", exc)
            return False

    def _disable_windows(self) -> bool:
        if winreg is None:
            logger.warning("winreg module is unavailable; cannot disable Windows proxy")
            return False
        try:
            key = winreg.CreateKeyEx(
                winreg.HKEY_CURRENT_USER,
                WINDOWS_INTERNET_SETTINGS_REG_KEY,
                0,
                winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE,
            )
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)

            # Refresh Windows system proxy cache
            self._refresh_windows_wininet()
            logger.info("Disabled Windows system proxy")
            return True
        except Exception as exc:
            logger.error("Failed to disable Windows system proxy: %s", exc)
            return False

    def _is_enabled_windows(self) -> bool:
        if winreg is None:
            return False
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                WINDOWS_INTERNET_SETTINGS_REG_KEY,
                0,
                winreg.KEY_QUERY_VALUE,
            )
            value, _ = winreg.QueryValueEx(key, "ProxyEnable")
            winreg.CloseKey(key)
            return bool(value == 1)
        except Exception:
            return False

    def _refresh_windows_wininet(self) -> None:
        if ctypes is not None and hasattr(ctypes, "windll") and hasattr(ctypes.windll, "wininet"):
            try:
                ctypes.windll.wininet.InternetSetOptionW(
                    0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0
                )
                ctypes.windll.wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)
            except Exception as exc:
                logger.debug("WinINet refresh call failed: %s", exc)

    # --- macOS Implementation ---

    def _get_macos_interfaces(self) -> list[str]:
        interfaces: list[str] = []
        try:
            res = subprocess.run(
                ["networksetup", "-listnetworkserviceorder"],
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    match = re.search(r"\(\d+\)\s+(.+)$", line)
                    if match:
                        iface = match.group(1).strip()
                        if iface and iface not in interfaces:
                            interfaces.append(iface)
        except Exception as exc:
            logger.debug("Error listing macOS network services: %s", exc)

        if not interfaces:
            interfaces = ["Wi-Fi", "Ethernet"]
        return interfaces

    def _enable_macos(self, host: str, port: int) -> bool:
        interfaces = self._get_macos_interfaces()
        success = False
        for iface in interfaces:
            try:
                res1 = subprocess.run(
                    ["networksetup", "-setsocksfirewallproxy", iface, host, str(port)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                res2 = subprocess.run(
                    ["networksetup", "-setsocksfirewallproxystate", iface, "on"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if res1.returncode == 0 and res2.returncode == 0:
                    success = True
                    logger.info("Enabled macOS SOCKS proxy on interface '%s'", iface)
            except Exception as exc:
                logger.error("Failed to enable proxy on macOS interface '%s': %s", iface, exc)
        return success

    def _disable_macos(self) -> bool:
        interfaces = self._get_macos_interfaces()
        success = False
        for iface in interfaces:
            try:
                res = subprocess.run(
                    ["networksetup", "-setsocksfirewallproxystate", iface, "off"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if res.returncode == 0:
                    success = True
                    logger.info("Disabled macOS SOCKS proxy on interface '%s'", iface)
            except Exception as exc:
                logger.error("Failed to disable proxy on macOS interface '%s': %s", iface, exc)
        return success

    def _is_enabled_macos(self) -> bool:
        interfaces = self._get_macos_interfaces()
        for iface in interfaces:
            try:
                res = subprocess.run(
                    ["networksetup", "-getsocksfirewallproxy", iface],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if res.returncode == 0 and "Enabled: Yes" in res.stdout:
                    return True
            except Exception:
                pass
        return False

    # --- Linux Implementation ---

    @staticmethod
    def _has_gnome_desktop() -> bool:
        """Check if Linux system has an active GNOME / graphical session for gsettings."""
        if sys.platform == "linux":
            if not shutil.which("gsettings"):
                return False
            # If running headless without display or dbus session, gsettings cannot configure system proxy
            if not (os.environ.get("DBUS_SESSION_BUS_ADDRESS") or os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
                return False
        return True

    def _enable_linux(self, host: str, port: int) -> bool:
        if not self._has_gnome_desktop():
            logger.debug("Headless Linux detected (no graphical session). Skipping GNOME system proxy.")
            return False
        try:
            r1 = subprocess.run(
                ["gsettings", "set", "org.gnome.system.proxy.socks", "host", host],
                capture_output=True,
                check=False,
            )
            r2 = subprocess.run(
                ["gsettings", "set", "org.gnome.system.proxy.socks", "port", str(port)],
                capture_output=True,
                check=False,
            )
            r3 = subprocess.run(
                ["gsettings", "set", "org.gnome.system.proxy", "mode", "manual"],
                capture_output=True,
                check=False,
            )
            if r1.returncode == 0 and r2.returncode == 0 and r3.returncode == 0:
                logger.info("Enabled Linux GNOME system proxy: %s:%s", host, port)
                return True
            logger.debug("gsettings returned non-zero when enabling Linux proxy")
            return False
        except Exception as exc:
            logger.error("Failed to enable Linux system proxy: %s", exc)
            return False

    def _disable_linux(self) -> bool:
        if not self._has_gnome_desktop():
            return True
        try:
            res = subprocess.run(
                ["gsettings", "set", "org.gnome.system.proxy", "mode", "none"],
                capture_output=True,
                check=False,
            )
            if res.returncode == 0:
                logger.info("Disabled Linux GNOME system proxy")
                return True
            logger.debug("gsettings returned non-zero when disabling Linux proxy")
            return False
        except Exception as exc:
            logger.error("Failed to disable Linux system proxy: %s", exc)
            return False

    def _is_enabled_linux(self) -> bool:
        try:
            res = subprocess.run(
                ["gsettings", "get", "org.gnome.system.proxy", "mode"],
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode == 0 and "manual" in res.stdout:
                return True
            return False
        except Exception:
            return False

    # --- Public API ---

    def enable_system_proxy(self, host: str = "127.0.0.1", port: int = 10808) -> bool:
        """Enable system-wide SOCKS5 proxy on current OS."""
        if self.platform.startswith("win"):
            return self._enable_windows(host, port)
        elif self.platform.startswith("darwin") or self.platform.startswith("mac"):
            return self._enable_macos(host, port)
        elif self.platform.startswith("linux"):
            return self._enable_linux(host, port)
        else:
            logger.warning("Unsupported platform for system proxy: %s", self.platform)
            return False

    def disable_system_proxy(self) -> bool:
        """Disable system-wide SOCKS5 proxy on current OS."""
        if self.platform.startswith("win"):
            return self._disable_windows()
        elif self.platform.startswith("darwin") or self.platform.startswith("mac"):
            return self._disable_macos()
        elif self.platform.startswith("linux"):
            return self._disable_linux()
        else:
            logger.warning("Unsupported platform for system proxy: %s", self.platform)
            return False

    def is_system_proxy_enabled(self) -> bool:
        """Check if system-wide proxy is currently enabled on this OS."""
        if self.platform.startswith("win"):
            return self._is_enabled_windows()
        elif self.platform.startswith("darwin") or self.platform.startswith("mac"):
            return self._is_enabled_macos()
        elif self.platform.startswith("linux"):
            return self._is_enabled_linux()
        else:
            return False

    @staticmethod
    def get_env_proxy_commands(
        host: str = "127.0.0.1", port: int = 10808
    ) -> dict[str, str]:
        """Return environment variable export strings for various shells."""
        proxy_url = f"socks5h://{host}:{port}"
        return {
            "bash": (
                f'export all_proxy="{proxy_url}"\n'
                f'export ALL_PROXY="{proxy_url}"\n'
                f'export http_proxy="{proxy_url}"\n'
                f'export https_proxy="{proxy_url}"'
            ),
            "sh": (
                f'export all_proxy="{proxy_url}"\n'
                f'export ALL_PROXY="{proxy_url}"\n'
                f'export http_proxy="{proxy_url}"\n'
                f'export https_proxy="{proxy_url}"'
            ),
            "zsh": (
                f'export all_proxy="{proxy_url}"\n'
                f'export ALL_PROXY="{proxy_url}"\n'
                f'export http_proxy="{proxy_url}"\n'
                f'export https_proxy="{proxy_url}"'
            ),
            "fish": (
                f'set -gx all_proxy "{proxy_url}"\n'
                f'set -gx ALL_PROXY "{proxy_url}"\n'
                f'set -gx http_proxy "{proxy_url}"\n'
                f'set -gx https_proxy "{proxy_url}"'
            ),
            "powershell": (
                f'$env:all_proxy="{proxy_url}"; '
                f'$env:ALL_PROXY="{proxy_url}"; '
                f'$env:http_proxy="{proxy_url}"; '
                f'$env:https_proxy="{proxy_url}"'
            ),
            "cmd": (
                f"set all_proxy={proxy_url} && "
                f"set ALL_PROXY={proxy_url} && "
                f"set http_proxy={proxy_url} && "
                f"set https_proxy={proxy_url}"
            ),
        }


# Module-level convenience functions
_default_manager = SystemProxyManager()


def enable_system_proxy(host: str = "127.0.0.1", port: int = 10808) -> bool:
    return _default_manager.enable_system_proxy(host, port)


def disable_system_proxy() -> bool:
    return _default_manager.disable_system_proxy()


def is_system_proxy_enabled() -> bool:
    return _default_manager.is_system_proxy_enabled()


def get_env_proxy_commands(
    host: str = "127.0.0.1", port: int = 10808
) -> dict[str, str]:
    return SystemProxyManager.get_env_proxy_commands(host, port)
