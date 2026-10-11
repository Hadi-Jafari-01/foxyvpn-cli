"""FoxyVPN: High-performance cross-platform CLI client for Firefox VPN."""

__version__ = "1.0.0"

from foxyvpn.proxy.resolver import enable_secure_dns

enable_secure_dns()
