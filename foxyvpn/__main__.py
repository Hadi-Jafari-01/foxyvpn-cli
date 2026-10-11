"""Entry point for python -m foxyvpn execution."""

import sys
from pathlib import Path

# Ensure package root is in sys.path
_pkg_root = str(Path(__file__).resolve().parent.parent)
if _pkg_root not in sys.path:
    sys.path.insert(0, _pkg_root)

from foxyvpn.proxy.resolver import enable_secure_dns

enable_secure_dns()

from foxyvpn.cli import cli

if __name__ == "__main__":
    cli()
