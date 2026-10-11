"""Core module for FoxyVPN CLI.

Exports models, configuration, and persistent stores.
"""

from foxyvpn.core.config import (
    DEFAULT_CONFIG_FILENAME,
    DOH_PROVIDERS,
    DOH_SERVERS,
    UPSTREAM_PROXY_TYPES,
    Settings,
    get_config_dir,
    get_default_config_path,
    load_settings,
    save_settings,
)
from foxyvpn.core.models import (
    ConnectionState,
    Entitlement,
    ProxyCandidate,
    ProxyPass,
    RuntimeAuth,
    UpstreamProxyConfig,
    VpnCity,
    VpnCountry,
    VpnProtocol,
    VpnServerNode,
    from_dict,
    to_dict,
)
from foxyvpn.core.store import (
    DEFAULT_TOKENS_FILENAME,
    SettingsStore,
    TokenStore,
)

__all__ = [
    # Models
    "RuntimeAuth",
    "ProxyPass",
    "Entitlement",
    "VpnProtocol",
    "VpnServerNode",
    "VpnCity",
    "VpnCountry",
    "ProxyCandidate",
    "UpstreamProxyConfig",
    "ConnectionState",
    "to_dict",
    "from_dict",
    # Config
    "Settings",
    "DOH_PROVIDERS",
    "DOH_SERVERS",
    "UPSTREAM_PROXY_TYPES",
    "DEFAULT_CONFIG_FILENAME",
    "get_config_dir",
    "get_default_config_path",
    "load_settings",
    "save_settings",
    # Store
    "DEFAULT_TOKENS_FILENAME",
    "TokenStore",
    "SettingsStore",
]
