"""Persistent storage managers for authentication tokens and settings.

Provides TokenStore for token lifecycle and session validation,
and SettingsStore for configuration persistence and manipulation.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any

from foxyvpn.core.config import Settings, get_config_dir, get_default_config_path, load_settings, save_settings
from foxyvpn.core.models import ProxyPass, RuntimeAuth

DEFAULT_TOKENS_FILENAME = "tokens.json"


def _set_private_file_permissions(path: Path) -> None:
    """Set restrictive read/write permissions on non-Windows platforms."""
    if sys.platform != "win32":
        try:
            path.chmod(0o600)
        except OSError:
            pass


class TokenStore:
    """Persistent storage for authentication and proxy tokens."""

    def __init__(self, file_path: Path | str | None = None) -> None:
        if file_path is not None:
            self.file_path = Path(file_path)
        else:
            self.file_path = get_config_dir() / DEFAULT_TOKENS_FILENAME

    def _read_data(self) -> dict[str, Any]:
        if not self.file_path.exists():
            return {}
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _write_data(self, data: dict[str, Any]) -> None:
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = self.file_path.with_suffix(f".tmp.{os.getpid()}")
        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            _set_private_file_permissions(temp_path)
            temp_path.replace(self.file_path)
            _set_private_file_permissions(self.file_path)
        except Exception:
            with open(self.file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            _set_private_file_permissions(self.file_path)
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    pass

    def save_auth(self, auth: RuntimeAuth, make_active: bool = True) -> None:
        """Persist authentication session to disk, tracking multiple accounts."""
        data = self._read_data()
        auth_dict = auth.to_dict()

        # Multi-account registry
        accounts = data.get("accounts", {})
        if not isinstance(accounts, dict):
            accounts = {}

        account_key = auth.email.strip().lower() if auth.email and auth.email.strip() else "default"
        accounts[account_key] = auth_dict
        data["accounts"] = accounts

        if make_active:
            data["auth"] = auth_dict
            data["active_email"] = account_key
            # Mirror top-level keys for backward compatibility
            data["access_token"] = auth.access_token
            data["refresh_token"] = auth.refresh_token
            data["expires_at_epoch_seconds"] = auth.expires_at_epoch_seconds
            data["email"] = auth.email

        self._write_data(data)

    def list_accounts(self) -> list[dict[str, Any]]:
        """Return list of all saved user accounts."""
        data = self._read_data()
        accounts = data.get("accounts", {})
        if not isinstance(accounts, dict):
            accounts = {}

        active_email = data.get("active_email", "")
        current_auth = self.load_auth()
        if current_auth and current_auth.email:
            active_email = current_auth.email.strip().lower()

        result = []
        for key, acc_data in accounts.items():
            if isinstance(acc_data, dict):
                email = acc_data.get("email") or key
                is_active = (key == active_email) or (email.strip().lower() == active_email)
                result.append({
                    "email": email,
                    "key": key,
                    "is_active": is_active,
                    "expires_at": acc_data.get("expires_at_epoch_seconds", 0),
                })
        return result

    def switch_account(self, email: str) -> bool:
        """Switch the active session to a previously saved account."""
        data = self._read_data()
        accounts = data.get("accounts", {})
        if not isinstance(accounts, dict):
            return False

        target_key = email.strip().lower()
        target_data = None
        for key, acc_data in accounts.items():
            if key == target_key or (isinstance(acc_data, dict) and acc_data.get("email", "").strip().lower() == target_key):
                target_data = acc_data
                target_key = key
                break

        if not target_data or not isinstance(target_data, dict):
            return False

        data["auth"] = target_data
        data["active_email"] = target_key
        data["access_token"] = target_data.get("access_token")
        data["refresh_token"] = target_data.get("refresh_token")
        data["expires_at_epoch_seconds"] = target_data.get("expires_at_epoch_seconds", 0)
        data["email"] = target_data.get("email")

        # Invalidate current proxy pass so new account's Guardian token is fetched fresh
        if "proxy_pass" in data:
            del data["proxy_pass"]

        self._write_data(data)
        return True

    def remove_account(self, email: str) -> bool:
        """Remove a saved account from the multi-account registry."""
        data = self._read_data()
        accounts = data.get("accounts", {})
        if not isinstance(accounts, dict):
            return False

        target_key = email.strip().lower()
        matched_key = None
        for key, acc_data in accounts.items():
            if key == target_key or (isinstance(acc_data, dict) and acc_data.get("email", "").strip().lower() == target_key):
                matched_key = key
                break

        if not matched_key or matched_key not in accounts:
            return False

        del accounts[matched_key]
        data["accounts"] = accounts

        # If we removed the active account, clear active session
        current_auth = self.load_auth()
        if current_auth and current_auth.email and current_auth.email.strip().lower() == target_key:
            data.pop("auth", None)
            data.pop("active_email", None)
            data.pop("access_token", None)
            data.pop("refresh_token", None)
            data.pop("expires_at_epoch_seconds", None)
            data.pop("email", None)
            data.pop("proxy_pass", None)

            # Auto-switch to another account if one exists
            if accounts:
                first_key = next(iter(accounts))
                data["auth"] = accounts[first_key]
                data["active_email"] = first_key

        self._write_data(data)
        return True

    def load_auth(self) -> RuntimeAuth | None:
        """Load stored authentication session if present and valid."""
        data = self._read_data()
        if not data:
            return None

        auth_data = data.get("auth") if ("auth" in data and isinstance(data["auth"], dict)) else data
        if not isinstance(auth_data, dict):
            return None

        access_token = auth_data.get("access_token") or auth_data.get("accessToken")
        if not access_token or not str(access_token).strip():
            return None

        try:
            return RuntimeAuth.from_dict(auth_data)
        except Exception:
            return None

    def clear(self) -> None:
        """Remove stored authentication tokens."""
        if self.file_path.exists():
            try:
                self.file_path.unlink()
            except OSError:
                self._write_data({})
        else:
            self._write_data({})

    def has_valid_access_token(self) -> bool:
        """Check if an access token is stored and unexpired with 30s safety margin."""
        auth = self.load_auth()
        if auth is None or not auth.access_token or not auth.access_token.strip():
            return False
        if auth.expires_at_epoch_seconds <= 0:
            return False
        now = time.time()
        # 30-second safety margin to prevent mid-flight token expiration
        return (auth.expires_at_epoch_seconds - now) > 30

    def has_stored_session(self) -> bool:
        """Return True if any valid auth session exists."""
        return self.load_auth() is not None

    def has_refresh_token(self) -> bool:
        """Return True if stored auth includes a non-empty refresh token."""
        auth = self.load_auth()
        return bool(auth and auth.refresh_token and auth.refresh_token.strip())

    def save_proxy_pass(self, proxy_pass: ProxyPass) -> None:
        """Save Guardian proxy credentials."""
        data = self._read_data()
        data["proxy_pass"] = proxy_pass.to_dict()
        self._write_data(data)

    def load_proxy_pass(self) -> ProxyPass | None:
        """Load Guardian proxy credentials if stored."""
        data = self._read_data()
        pass_data = data.get("proxy_pass")
        if not isinstance(pass_data, dict) or not pass_data.get("token"):
            return None
        try:
            return ProxyPass.from_dict(pass_data)
        except Exception:
            return None

    def clear_proxy_pass(self) -> None:
        """Remove stored proxy credentials while keeping auth."""
        data = self._read_data()
        if "proxy_pass" in data:
            del data["proxy_pass"]
            self._write_data(data)

    def export_token(self) -> str:
        """Export current authentication session as a portable base64 string."""
        import base64
        auth = self.load_auth()
        if not auth:
            raise ValueError("No active authentication session to export.")
        raw_json = json.dumps(auth.to_dict()).encode("utf-8")
        return base64.urlsafe_b64encode(raw_json).decode("ascii")

    def import_token(self, token_str: str) -> RuntimeAuth:
        """Import a portable base64 token string and activate it."""
        import base64
        clean = token_str.strip()
        padding = 4 - (len(clean) % 4)
        if padding != 4:
            clean += "=" * padding
        raw_json = base64.urlsafe_b64decode(clean.encode("ascii")).decode("utf-8")
        data = json.loads(raw_json)
        auth = RuntimeAuth.from_dict(data)
        self.save_auth(auth)
        return auth


class SettingsStore:
    """Persistent storage and manipulator for application settings."""

    def __init__(self, file_path: Path | str | None = None) -> None:
        if file_path is not None:
            self.file_path = Path(file_path)
        else:
            self.file_path = get_default_config_path()

    def _read_dict(self) -> dict[str, Any]:
        if not self.file_path.exists():
            return {}
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def load(self) -> Settings:
        """Load settings from disk or return defaults."""
        return load_settings(self.file_path)

    def save(self, settings: dict[str, Any] | Settings) -> None:
        """Save settings instance or dictionary to disk."""
        save_settings(settings, self.file_path)

    def get(self, key: str, default: Any = None) -> Any:
        """Retrieve a specific setting value with fallback to default."""
        data = self._read_dict()
        if key in data:
            return data[key]
        current_settings = self.load()
        if hasattr(current_settings, key):
            val = getattr(current_settings, key)
            return val if val is not None else default
        return default

    def set(self, key: str, value: Any) -> None:
        """Update a specific setting and persist it immediately."""
        data = self._read_dict()
        if not data:
            # Seed with current default settings dict
            data = self.load().to_dict()
        data[key] = value
        self.save(data)
