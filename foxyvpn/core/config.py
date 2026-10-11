"""Cross-platform configuration management for FoxyVPN CLI.

Handles path resolution across Linux, macOS, and Windows, defaults,
Settings dataclass, and JSON persistence.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

DEFAULT_CONFIG_FILENAME = "settings.json"

DOH_PROVIDERS: tuple[str, ...] = ("automatic", "cloudflare", "google", "quad9", "off")
UPSTREAM_PROXY_TYPES: tuple[str, ...] = ("socks5", "http")

DOH_SERVERS: dict[str, list[str]] = {
    "automatic": ["1.1.1.1", "8.8.8.8", "9.9.9.9"],
    "cloudflare": ["1.1.1.1", "1.0.0.1"],
    "google": ["8.8.8.8", "8.8.4.4"],
    "quad9": ["9.9.9.9", "149.112.112.112"],
    "off": [],
}


@dataclass
class Settings:
    """User and proxy runtime configuration settings."""

    socks_host: str = "127.0.0.1"
    socks_port: int = 10808
    doh_provider: str = "automatic"
    custom_dns: str = ""
    exit_check: bool = True
    system_proxy: bool = False
    custom_edge: str = ""
    upstream_proxy_enabled: bool = False
    upstream_proxy_type: str = "socks5"
    upstream_proxy_host: str = ""
    upstream_proxy_port: int = 1080
    upstream_proxy_user: str = ""
    upstream_proxy_pass: str = ""
    default_country: str = "REC"
    default_city: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert settings to dictionary format."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Settings:
        """Create Settings instance from dictionary, supporting both snake_case and camelCase."""
        key_mapping: dict[str, str] = {
            "socksHost": "socks_host",
            "socksPort": "socks_port",
            "dohProvider": "doh_provider",
            "customDns": "custom_dns",
            "exitCheck": "exit_check",
            "systemProxy": "system_proxy",
            "customEdge": "custom_edge",
            "upstreamProxyEnabled": "upstream_proxy_enabled",
            "upstreamProxyType": "upstream_proxy_type",
            "upstreamProxyHost": "upstream_proxy_host",
            "upstreamProxyPort": "upstream_proxy_port",
            "upstreamProxyUser": "upstream_proxy_user",
            "upstreamProxyPass": "upstream_proxy_pass",
            "defaultCountry": "default_country",
            "defaultCity": "default_city",
        }

        normalized: dict[str, Any] = {}
        for k, v in data.items():
            norm_k = key_mapping.get(k, k)
            normalized[norm_k] = v

        defaults = cls()
        kwargs: dict[str, Any] = {}
        for field_name, field_def in cls.__dataclass_fields__.items():
            if field_name in normalized:
                val = normalized[field_name]
                if field_def.type is int:
                    val = int(val)
                elif field_def.type is bool:
                    val = bool(val)
                elif field_def.type is str:
                    val = str(val) if val is not None else ""
                kwargs[field_name] = val
            else:
                kwargs[field_name] = getattr(defaults, field_name)
        return cls(**kwargs)

    @property
    def effective_doh_servers(self) -> list[str]:
        """Return upstream DoH server IP addresses based on provider setting."""
        return DOH_SERVERS.get(self.doh_provider, DOH_SERVERS["automatic"])


def get_config_dir() -> Path:
    """Return the cross-platform configuration directory.

    Platform resolution:
    - Environment override: $FOXYVPN_CONFIG_DIR
    - Windows: %APPDATA%/foxyvpn (fallback: ~/AppData/Roaming/foxyvpn)
    - Linux / macOS: $XDG_CONFIG_HOME/foxyvpn or ~/.config/foxyvpn
    """
    override = os.environ.get("FOXYVPN_CONFIG_DIR")
    if override:
        return Path(override)

    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            base_dir = Path(appdata)
        else:
            base_dir = Path.home() / "AppData" / "Roaming"
        return base_dir / "foxyvpn"
    else:
        xdg = os.environ.get("XDG_CONFIG_HOME")
        if xdg:
            base_dir = Path(xdg)
        else:
            base_dir = Path.home() / ".config"
        return base_dir / "foxyvpn"


def get_default_config_path() -> Path:
    """Return default configuration file path."""
    return get_config_dir() / DEFAULT_CONFIG_FILENAME


def load_settings(path: Path | str | None = None) -> Settings:
    """Load settings from JSON file or return defaults if absent/corrupted."""
    if path is None:
        target_path = get_default_config_path()
        if not target_path.exists():
            alt_path = get_config_dir() / "config.json"
            if alt_path.exists():
                target_path = alt_path
    else:
        target_path = Path(path)

    if not target_path.exists():
        return Settings()

    try:
        with open(target_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return Settings.from_dict(data)
    except Exception:
        pass
    return Settings()


def save_settings(settings: Settings | dict[str, Any], path: Path | str | None = None) -> None:
    """Save settings to JSON file with atomic write semantics."""
    target_path = Path(path) if path is not None else get_default_config_path()
    target_path.parent.mkdir(parents=True, exist_ok=True)

    if isinstance(settings, Settings):
        data = settings.to_dict()
    elif isinstance(settings, dict):
        data = settings
    else:
        raise TypeError("settings must be a Settings instance or dict")

    temp_path = target_path.with_suffix(f".tmp.{os.getpid()}")
    try:
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        temp_path.replace(target_path)
    except Exception:
        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass
