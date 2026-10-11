"""Cross-platform system proxy and daemon management."""

from foxyvpn.system.daemon import (
    DaemonManager,
    is_daemon_running,
    stop_daemon,
)
from foxyvpn.system.proxy import (
    SystemProxyManager,
    disable_system_proxy,
    enable_system_proxy,
    get_env_proxy_commands,
    is_system_proxy_enabled,
)

__all__ = [
    "DaemonManager",
    "SystemProxyManager",
    "disable_system_proxy",
    "enable_system_proxy",
    "get_env_proxy_commands",
    "is_daemon_running",
    "is_system_proxy_enabled",
    "stop_daemon",
]
