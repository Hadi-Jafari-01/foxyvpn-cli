"""Entry point for python -m foxyvpn execution."""

from foxyvpn.proxy.resolver import enable_secure_dns

enable_secure_dns()

from foxyvpn.cli import cli

if __name__ == "__main__":
    cli()
