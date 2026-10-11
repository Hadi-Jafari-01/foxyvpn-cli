"""Daemon manager for FoxyVPN background process lifecycle and state tracking.

Manages PID files, process health checks, graceful and forced process termination,
and runtime connection state persistence.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import subprocess
import sys
import time
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from foxyvpn.core.config import get_config_dir

logger = logging.getLogger(__name__)

DEFAULT_PID_FILENAME = "daemon.pid"
DEFAULT_STATE_FILENAME = "daemon.json"
DEFAULT_STOP_TIMEOUT = 5.0


class DaemonManager:
    """Controls the lifecycle and state persistence of the background FoxyVPN daemon."""

    def __init__(self, config_dir: Path | str | None = None) -> None:
        if config_dir is not None:
            self.config_dir = Path(config_dir)
        else:
            self.config_dir = get_config_dir()

        self.pid_file = self.config_dir / DEFAULT_PID_FILENAME
        self.state_file = self.config_dir / DEFAULT_STATE_FILENAME

    # --- PID Management ---

    def get_pid(self) -> int | None:
        """Read and parse PID from the daemon PID file. Returns None if absent or invalid."""
        if not self.pid_file.exists():
            return None
        try:
            content = self.pid_file.read_text(encoding="utf-8").strip()
            if not content:
                return None
            pid = int(content)
            return pid if pid > 0 else None
        except Exception as exc:
            logger.debug("Failed to read daemon PID file: %s", exc)
            return None

    def write_pid(self, pid: int | None = None) -> None:
        """Write PID (defaults to current process PID) to the daemon PID file."""
        target_pid = pid if pid is not None else os.getpid()
        self.config_dir.mkdir(parents=True, exist_ok=True)
        temp_file = self.pid_file.with_suffix(f".tmp.{os.getpid()}")
        try:
            temp_file.write_text(str(target_pid), encoding="utf-8")
            temp_file.replace(self.pid_file)
        except Exception:
            self.pid_file.write_text(str(target_pid), encoding="utf-8")
            if temp_file.exists():
                try:
                    temp_file.unlink()
                except OSError:
                    pass
        logger.debug("Wrote daemon PID %d to %s", target_pid, self.pid_file)

    def remove_pid(self) -> None:
        """Remove the daemon PID file if it exists."""
        try:
            if self.pid_file.exists():
                self.pid_file.unlink()
                logger.debug("Removed daemon PID file: %s", self.pid_file)
        except OSError as exc:
            logger.debug("Error removing PID file %s: %s", self.pid_file, exc)

    # --- Process Liveness ---

    @staticmethod
    def is_pid_running(pid: int) -> bool:
        """Check if a process with given PID is currently active."""
        if pid <= 0:
            return False
        try:
            os.kill(pid, 0)
            return True
        except PermissionError:
            # Process exists, but we lack permissions to signal it -> definitely running
            return True
        except (ProcessLookupError, OSError):
            return False

    def is_daemon_running(self) -> bool:
        """Check if the daemon is running. Automatically cleans up stale PID file."""
        pid = self.get_pid()
        if pid is None:
            return False

        if self.is_pid_running(pid):
            return True

        # Process is dead but PID file remains: clean up stale state
        logger.info("Found stale daemon PID %d; cleaning up", pid)
        self.remove_pid()
        return False

    # --- State Management ---

    def save_state(self, state: dict[str, Any] | Any) -> None:
        """Persist daemon connection state to daemon.json atomically."""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        if hasattr(state, "to_dict") and callable(state.to_dict):
            data = state.to_dict()
        elif is_dataclass(state) and not isinstance(state, type):
            data = asdict(state)
        elif isinstance(state, dict):
            data = state
        else:
            data = {"data": str(state)}

        temp_file = self.state_file.with_suffix(f".tmp.{os.getpid()}")
        try:
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            temp_file.replace(self.state_file)
        except Exception:
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            if temp_file.exists():
                try:
                    temp_file.unlink()
                except OSError:
                    pass

    def load_state(self) -> dict[str, Any] | None:
        """Load persisted daemon state from daemon.json. Returns None if absent or invalid."""
        if not self.state_file.exists():
            return None
        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else None
        except Exception as exc:
            logger.debug("Failed to load daemon state from %s: %s", self.state_file, exc)
            return None

    def remove_state(self) -> None:
        """Remove daemon state file if it exists."""
        try:
            if self.state_file.exists():
                self.state_file.unlink()
                logger.debug("Removed daemon state file: %s", self.state_file)
        except OSError as exc:
            logger.debug("Error removing state file %s: %s", self.state_file, exc)

    # --- Process Termination ---

    def stop_daemon(self, timeout_seconds: float = DEFAULT_STOP_TIMEOUT) -> bool:
        """Terminate the running daemon cleanly with SIGTERM or fallback force kill.

        Returns True if the daemon was found and terminated (or already stopped),
        False if no running daemon was detected.
        """
        pid = self.get_pid()
        if pid is None or not self.is_pid_running(pid):
            self.remove_pid()
            self.remove_state()
            return False

        logger.info("Stopping daemon process with PID %d...", pid)

        # 1. Attempt graceful termination
        try:
            if sys.platform == "win32":
                # On Windows, try taskkill first for clean shutdown
                res = subprocess.run(
                    ["taskkill", "/PID", str(pid)],
                    capture_output=True,
                    check=False,
                )
                if res.returncode != 0:
                    # Fallback to os.kill
                    try:
                        os.kill(pid, signal.SIGTERM)
                    except OSError:
                        pass
            else:
                os.kill(pid, signal.SIGTERM)
        except Exception as exc:
            logger.warning("Error sending termination signal to PID %d: %s", pid, exc)

        # 2. Wait for process exit
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            if not self.is_pid_running(pid):
                logger.info("Daemon process %d exited cleanly", pid)
                self.remove_pid()
                self.remove_state()
                return True
            time.sleep(0.15)

        # 3. Force kill if still running after timeout
        logger.warning("Daemon PID %d did not exit in %s seconds; force killing...", pid, timeout_seconds)
        try:
            if sys.platform == "win32":
                subprocess.run(
                    ["taskkill", "/F", "/PID", str(pid)],
                    capture_output=True,
                    check=False,
                )
            else:
                os.kill(pid, signal.SIGKILL)
        except Exception as exc:
            logger.error("Failed to force kill PID %d: %s", pid, exc)

        # Give OS a moment to reap process
        time.sleep(0.2)
        self.remove_pid()
        self.remove_state()
        return True

    # --- Spawning Background Daemon ---

    def spawn_daemon(
        self,
        command: list[str] | None = None,
        log_file: Path | str | None = None,
        country: str = "REC",
        city: str = "",
        port: int = 10808,
        bind: str = "127.0.0.1",
        system_proxy: bool = False,
        tun: bool = False,
        custom_edge: str = "",
    ) -> int:
        """Spawn a detached background process and record its PID.

        Returns the PID of the spawned process.
        """
        self.config_dir.mkdir(parents=True, exist_ok=True)

        if command is None:
            command = [
                sys.executable,
                "-m",
                "foxyvpn.cli",
                "connect",
                "--worker",
                "--country",
                country,
                "--port",
                str(port),
                "--bind",
                bind,
            ]
            if city:
                command.extend(["--city", city])
            if system_proxy:
                command.append("--system-proxy")
            if tun:
                command.append("--tun")
            if custom_edge:
                command.extend(["--edge", custom_edge])

        stdout_file: Any
        stderr_file: Any
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_fd = open(log_path, "a", encoding="utf-8")
            stdout_file = log_fd
            stderr_file = subprocess.STDOUT
        else:
            stdout_file = subprocess.DEVNULL
            stderr_file = subprocess.DEVNULL

        child_env = dict(os.environ)
        child_env["PYTHONIOENCODING"] = "utf-8"
        child_env["PYTHONUTF8"] = "1"

        try:
            if sys.platform == "win32":
                creation_flags = (
                    subprocess.CREATE_NEW_PROCESS_GROUP
                    | getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
                )
                proc = subprocess.Popen(
                    command,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    creationflags=creation_flags,
                    env=child_env,
                )
            else:
                proc = subprocess.Popen(
                    command,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    start_new_session=True,
                    env=child_env,
                )

            self.write_pid(proc.pid)
            logger.info("Spawned daemon process with PID %d", proc.pid)
            return proc.pid
        finally:
            if log_file and "log_fd" in locals():
                log_fd.close()


# Module-level convenience functions
_default_daemon = DaemonManager()


def is_daemon_running() -> bool:
    return _default_daemon.is_daemon_running()


def stop_daemon(timeout_seconds: float = DEFAULT_STOP_TIMEOUT) -> bool:
    return _default_daemon.stop_daemon(timeout_seconds)
