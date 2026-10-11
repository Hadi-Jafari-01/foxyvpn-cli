"""TUN (Virtual Network Adapter) Interface and Route Management for FoxyVPN.

Provides full-system VPN coverage (routing all TCP/UDP/ICMP traffic, games, DNS)
by managing a virtual TUN interface (Wintun on Windows, /dev/net/tun on Linux, utun on macOS)
and running the native tun2socks engine paired with local SOCKS5 proxy (127.0.0.1:10808).
"""

from __future__ import annotations

import ctypes
import io
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from typing import Any

import httpx

from foxyvpn.core.config import get_config_dir

logger = logging.getLogger(__name__)

TUN2SOCKS_VERSION = "v2.7.0"
TUN2SOCKS_DOWNLOAD_BASE = f"https://github.com/xjasonlyu/tun2socks/releases/download/{TUN2SOCKS_VERSION}"


class TunManager:
    """Manages TUN interface lifecycle, tun2socks daemon, and system IP routing."""

    def __init__(
        self,
        tun_name: str = "foxyvpn0",
        tun_ip: str = "10.8.0.2",
        tun_gateway: str = "10.8.0.1",
        tun_mask: str = "255.255.255.0",
        tun_mtu: int = 1500,
    ) -> None:
        self.tun_name = tun_name
        self.tun_ip = tun_ip
        self.tun_gateway = tun_gateway
        self.tun_mask = tun_mask
        self.tun_mtu = tun_mtu
        self.platform = sys.platform
        self._process: subprocess.Popen[Any] | None = None
        self._physical_gateway: str | None = None
        self._physical_interface_ip: str | None = None
        self._vpn_server_ip: str | None = None

    @staticmethod
    def is_admin() -> bool:
        """Check if current process has root or Administrator privileges."""
        if sys.platform == "win32":
            try:
                return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore[attr-defined]
            except Exception:
                return False
        else:
            return os.geteuid() == 0

    def get_bin_dir(self) -> Path:
        """Get directory containing tun2socks binary and drivers."""
        # 1. Check local foxyvpn/bin package directory
        local_bin = Path(__file__).parent.parent / "bin"
        if local_bin.exists():
            return local_bin

        # 2. Check user config bin dir
        cfg_bin = get_config_dir() / "bin"
        cfg_bin.mkdir(parents=True, exist_ok=True)
        return cfg_bin

    def get_binary_path(self) -> Path | None:
        """Find executable tun2socks on the system or in foxyvpn bin."""
        exe_name = "tun2socks.exe" if sys.platform == "win32" else "tun2socks"
        
        # 1. Package directory
        bin_dir = self.get_bin_dir()
        candidate = bin_dir / exe_name
        if candidate.exists():
            return candidate

        # 2. Config directory
        cfg_candidate = get_config_dir() / "bin" / exe_name
        if cfg_candidate.exists():
            return cfg_candidate

        # 3. System PATH
        which_path = shutil.which("tun2socks")
        if which_path:
            return Path(which_path)

        return None

    def ensure_binary(self) -> Path:
        """Ensure tun2socks is available, downloading if needed."""
        existing = self.get_binary_path()
        if existing and existing.exists():
            return existing

        target_dir = get_config_dir() / "bin"
        target_dir.mkdir(parents=True, exist_ok=True)
        exe_name = "tun2socks.exe" if sys.platform == "win32" else "tun2socks"
        target_exe = target_dir / exe_name

        # Detect OS & Arch
        arch = platform.machine().lower()
        if arch in ("amd64", "x86_64"):
            arch_str = "amd64"
        elif "arm" in arch or "aarch64" in arch:
            arch_str = "arm64"
        else:
            arch_str = "386"

        if sys.platform == "win32":
            asset_name = f"tun2socks-windows-{arch_str}.zip"
        elif sys.platform == "darwin":
            asset_name = f"tun2socks-darwin-{arch_str}.zip"
        else:
            asset_name = f"tun2socks-linux-{arch_str}.zip"

        url = f"{TUN2SOCKS_DOWNLOAD_BASE}/{asset_name}"
        logger.info("Downloading tun2socks from %s...", url)

        with httpx.Client(follow_redirects=True, timeout=30.0, trust_env=False) as client:
            resp = client.get(url)
            resp.raise_for_status()

            with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
                for member in z.namelist():
                    if member.endswith(".exe") or member == "tun2socks":
                        data = z.read(member)
                        target_exe.write_bytes(data)
                        if sys.platform != "win32":
                            target_exe.chmod(0o755)
                        logger.info("Extracted tun2socks to %s", target_exe)
                        return target_exe

        raise RuntimeError(f"Failed to find executable in downloaded archive: {asset_name}")

    def get_default_gateway(self) -> tuple[str | None, str | None]:
        """Detect the OS physical default gateway IP and interface IP."""
        if sys.platform == "win32":
            try:
                output = subprocess.check_output(["route", "print", "0.0.0.0"], text=True, stderr=subprocess.DEVNULL)
                for line in output.splitlines():
                    line = line.strip()
                    if line.startswith("0.0.0.0"):
                        parts = re.split(r"\s+", line)
                        if len(parts) >= 5:
                            return parts[2], parts[3]
            except Exception as e:
                logger.debug("Failed route print: %s", e)
        elif sys.platform == "darwin":
            try:
                output = subprocess.check_output(["route", "-n", "get", "default"], text=True, stderr=subprocess.DEVNULL)
                gw = None
                iface = None
                for line in output.splitlines():
                    if "gateway:" in line:
                        gw = line.split("gateway:")[1].strip()
                    if "interface:" in line:
                        iface = line.split("interface:")[1].strip()
                return gw, iface
            except Exception as e:
                logger.debug("Failed darwin route get: %s", e)
        else:
            # Linux
            try:
                output = subprocess.check_output(["ip", "route", "show", "default"], text=True, stderr=subprocess.DEVNULL)
                for line in output.splitlines():
                    parts = line.split()
                    if "via" in parts:
                        idx = parts.index("via")
                        return parts[idx + 1], parts[idx + 3] if idx + 3 < len(parts) else None
            except Exception as e:
                logger.debug("Failed ip route show: %s", e)

        return None, None

    def start_tun(
        self,
        socks_host: str = "127.0.0.1",
        socks_port: int = 10808,
        vpn_server_ip: str = "",
        log_file: Path | str | None = None,
    ) -> bool:
        """Start TUN adapter, tun2socks daemon, and configure routing tables."""
        if not self.is_admin():
            logger.warning("Administrator / root privileges required for TUN mode.")
            return False

        binary_path = self.ensure_binary()
        bin_dir = binary_path.parent

        # 1. Detect physical gateway
        gw, iface_ip = self.get_default_gateway()
        self._physical_gateway = gw
        self._physical_interface_ip = iface_ip
        self._vpn_server_ip = vpn_server_ip or None

        logger.info("Detected physical default gateway: %s (interface %s)", gw, iface_ip)

        # 2. Build device argument
        if sys.platform == "win32":
            device_arg = f"wintun://{self.tun_name}"
        elif sys.platform == "darwin":
            device_arg = f"utun://{self.tun_name}"
        else:
            device_arg = f"tun://{self.tun_name}"

        proxy_arg = f"socks5://{socks_host}:{socks_port}"

        cmd = [
            str(binary_path),
            "-device",
            device_arg,
            "-proxy",
            proxy_arg,
            "-loglevel",
            "info",
        ]

        # On Windows, wintun.dll must be in the working directory or PATH
        wintun_dll = bin_dir / "wintun.dll"
        env = dict(os.environ)
        if wintun_dll.exists():
            env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"

        # 3. Spawn tun2socks
        stdout_dest = subprocess.DEVNULL
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            stdout_dest = open(log_path, "a", encoding="utf-8")

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=stdout_dest,
                stderr=subprocess.STDOUT,
                cwd=str(bin_dir),
                env=env,
            )
            logger.info("Spawned tun2socks process PID %d", self._process.pid)
        except Exception as exc:
            logger.error("Failed to spawn tun2socks: %s", exc)
            return False

        # Allow adapter to initialize
        time.sleep(1.2)

        # 4. Configure IP address & routes
        self._configure_network()
        return True

    def _configure_network(self) -> None:
        """Configure IP address, MTU, and system routing table."""
        if sys.platform == "win32":
            self._configure_network_windows()
        elif sys.platform == "darwin":
            self._configure_network_macos()
        else:
            self._configure_network_linux()

    def _configure_network_windows(self) -> None:
        """Configure Windows adapter IP and 0/1 & 128/1 routes."""
        try:
            # Set adapter IP
            subprocess.run(
                [
                    "netsh",
                    "interface",
                    "ip",
                    "set",
                    "address",
                    f"name={self.tun_name}",
                    "static",
                    self.tun_ip,
                    self.tun_mask,
                    self.tun_gateway,
                ],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            # Set DNS on TUN interface
            subprocess.run(
                ["netsh", "interface", "ip", "set", "dns", f"name={self.tun_name}", "static", "1.1.1.1"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                ["netsh", "interface", "ip", "add", "dns", f"name={self.tun_name}", "8.8.8.8", "index=2"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            # Route to VPN Server via physical gateway (prevent routing loops)
            if self._vpn_server_ip and self._physical_gateway:
                subprocess.run(
                    ["route", "add", self._vpn_server_ip, "mask", "255.255.255.255", self._physical_gateway, "metric", "1"],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )

            # Add two half-routes 0.0.0.0/1 and 128.0.0.0/1 via TUN gateway
            subprocess.run(
                ["route", "add", "0.0.0.0", "mask", "128.0.0.0", self.tun_gateway, "metric", "1"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                ["route", "add", "128.0.0.0", "mask", "128.0.0.0", self.tun_gateway, "metric", "1"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            logger.info("Configured Windows TUN routes via %s", self.tun_gateway)
        except Exception as e:
            logger.error("Error setting up Windows TUN routes: %s", e)

    def _configure_network_linux(self) -> None:
        """Configure Linux TUN IP and ip route table."""
        try:
            subprocess.run(["ip", "link", "set", "dev", self.tun_name, "up"], check=False)
            subprocess.run(["ip", "addr", "add", f"{self.tun_ip}/24", "dev", self.tun_name], check=False)

            if self._vpn_server_ip and self._physical_gateway:
                subprocess.run(["ip", "route", "add", self._vpn_server_ip, "via", self._physical_gateway], check=False)

            subprocess.run(["ip", "route", "add", "0.0.0.0/1", "dev", self.tun_name], check=False)
            subprocess.run(["ip", "route", "add", "128.0.0.0/1", "dev", self.tun_name], check=False)
            logger.info("Configured Linux TUN routes")
        except Exception as e:
            logger.error("Error setting up Linux TUN routes: %s", e)

    def _configure_network_macos(self) -> None:
        """Configure macOS utun routing."""
        try:
            subprocess.run(["ifconfig", self.tun_name, self.tun_ip, self.tun_gateway, "up"], check=False)

            if self._vpn_server_ip and self._physical_gateway:
                subprocess.run(["route", "add", "-host", self._vpn_server_ip, self._physical_gateway], check=False)

            subprocess.run(["route", "add", "-net", "0.0.0.0/1", self.tun_gateway], check=False)
            subprocess.run(["route", "add", "-net", "128.0.0.0/1", self.tun_gateway], check=False)
            logger.info("Configured macOS TUN routes")
        except Exception as e:
            logger.error("Error setting up macOS TUN routes: %s", e)

    def stop_tun(self) -> bool:
        """Teardown routes, kill tun2socks, and destroy TUN adapter."""
        # 1. Clean routes
        self._restore_network()

        # 2. Terminate tun2socks process
        if self._process is not None:
            try:
                self._process.terminate()
                self._process.wait(timeout=2.0)
            except Exception:
                try:
                    self._process.kill()
                except Exception:
                    pass
            self._process = None

        logger.info("TUN interface %s stopped and routes restored.", self.tun_name)
        return True

    def _restore_network(self) -> None:
        """Remove added routes and restore physical routing."""
        if sys.platform == "win32":
            subprocess.run(["route", "delete", "0.0.0.0", "mask", "128.0.0.0", self.tun_gateway], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["route", "delete", "128.0.0.0", "mask", "128.0.0.0", self.tun_gateway], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if self._vpn_server_ip:
                subprocess.run(["route", "delete", self._vpn_server_ip], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif sys.platform == "darwin":
            subprocess.run(["route", "delete", "-net", "0.0.0.0/1"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["route", "delete", "-net", "128.0.0.0/1"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if self._vpn_server_ip:
                subprocess.run(["route", "delete", "-host", self._vpn_server_ip], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            # Linux
            subprocess.run(["ip", "route", "del", "0.0.0.0/1", "dev", self.tun_name], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["ip", "route", "del", "128.0.0.0/1", "dev", self.tun_name], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if self._vpn_server_ip:
                subprocess.run(["ip", "route", "del", self._vpn_server_ip], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["ip", "link", "set", "dev", self.tun_name, "down"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def is_tun_active(self) -> bool:
        """Check if tun2socks process is still running."""
        return self._process is not None and self._process.poll() is None
