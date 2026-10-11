"""FoxyVPN Command-Line Interface.

High-performance cross-platform CLI client for Firefox VPN.
Supports login, locations, connect, status, quota, verify, disconnect, and configuration.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any

# Ensure safe UTF-8 output on all platforms, including Windows consoles and log redirects
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import click
from rich import box
from rich.console import Console
from rich.live import Live
from rich.table import Table

from foxyvpn.proxy.resolver import enable_secure_dns

# Activate secure DoH DNS interception to neutralize censorship and DNS poisoning
enable_secure_dns()

from foxyvpn.api.guardian import GuardianClient
from foxyvpn.api.ping import ping_server
from foxyvpn.api.server_list import (
    ServerListClient,
    candidates_for_city,
    candidates_for_country,
    get_recommended_candidate,
)
from foxyvpn.auth.fxa import FxaAuthRepository
from foxyvpn.auth.web_auth import run_browser_login
from foxyvpn.core.config import Settings, get_config_dir
from foxyvpn.core.models import ConnectionState, Entitlement, ProxyCandidate, RuntimeAuth
from foxyvpn.core.store import SettingsStore, TokenStore
from foxyvpn.proxy.exit_check import ExitChecker
from foxyvpn.proxy.socks5 import LocalSocks5Server
from foxyvpn.system.daemon import DaemonManager
from foxyvpn.system.proxy import SystemProxyManager
from foxyvpn.system.tun import TunManager
from foxyvpn.tunnel.h2_session import H2UpstreamSession
from foxyvpn.ui.formatters import (
    format_quota_bar,
    format_servers_table,
    format_status_table,
    print_banner,
    render_dashboard,
)
from foxyvpn.ui.menu import run_interactive_menu

logger = logging.getLogger("foxyvpn.cli")
console = Console()


def _get_active_auth(token_store: TokenStore) -> RuntimeAuth | None:
    """Load stored authentication session if present."""
    return token_store.load_auth()


@click.group(invoke_without_command=True)
@click.option("--version", "-v", is_flag=True, help="Show FoxyVPN version.")
@click.option("--interactive", "-i", is_flag=True, help="Launch interactive menu mode.")
@click.pass_context
def cli(ctx: click.Context, version: bool, interactive: bool = False) -> None:
    """FoxyVPN: High-performance CLI for Mozilla Firefox VPN."""
    if version:
        console.print("[bold yellow]FoxyVPN CLI[/bold yellow] v1.0.0")
        ctx.exit(0)
    if ctx.invoked_subcommand is None:
        if interactive or (hasattr(sys.stdin, "isatty") and sys.stdin.isatty()):
            run_interactive_menu()
        else:
            print_banner(console)
            console.print(ctx.get_help())


@cli.command("menu")
def menu_command() -> None:
    """Launch interactive menu dashboard (no need to memorize commands)."""
    run_interactive_menu()


@cli.command("interactive", hidden=True)
def interactive_command() -> None:
    """Alias for 'menu'."""
    run_interactive_menu()


# ---------------------------------------------------------------------------
# LOGIN & LOGOUT
# ---------------------------------------------------------------------------


@cli.command("login")
@click.option("--browser", "-b", is_flag=True, help="Open browser-based login portal.")
@click.option("--port", default=8765, help="Port for browser login portal (default: 8765).")
@click.option("--token", "-t", default=None, help="Import exported token string directly.")
@click.option("--email", "-e", default=None, help="Firefox Accounts email address.")
@click.option("--password", "-p", default=None, help="Firefox Accounts password.")
@click.option("--code", default=None, help="Two-factor verification code (if 2FA enabled).")
def login(
    browser: bool,
    port: int,
    token: str | None,
    email: str | None,
    password: str | None,
    code: str | None,
) -> None:
    """Log in to Firefox Accounts and obtain session credentials."""
    print_banner(console)
    token_store = TokenStore()

    if token:
        try:
            auth = token_store.import_token(token)
            console.print(f"[bold green]✔ Successfully imported session for {auth.email or 'Active User'}![/bold green]")
            return
        except Exception as exc:
            console.print(f"[bold red]✘ Failed to import token:[/bold red] {exc}")
            sys.exit(1)

    if browser:
        auth = run_browser_login(port=port, token_store=token_store)
        if not auth:
            sys.exit(1)
        return

    # If non-flag execution in an interactive TTY, let user pick their preferred method
    if email is None and password is None and hasattr(sys.stdin, "isatty") and sys.stdin.isatty():
        console.print("[bold]Choose Login Method:[/bold]")
        console.print("  [bold cyan][1][/bold cyan] 🌐 [bold]Web Browser Login[/bold] (Recommended - Local or Remote Server)")
        console.print("  [bold cyan][2][/bold cyan] 💻 [bold]Terminal Direct Login[/bold] (Type email & password)")
        console.print("  [bold cyan][3][/bold cyan] 📋 [bold]Import Session Token[/bold]")
        method = click.prompt("Select method", default="1", type=str)
        if method == "1":
            auth = run_browser_login(port=port, token_store=token_store)
            if not auth:
                sys.exit(1)
            return
        elif method == "3":
            t_str = click.prompt("Paste token string", type=str)
            try:
                auth = token_store.import_token(t_str)
                console.print(f"[bold green]✔ Successfully imported session for {auth.email or 'Active User'}![/bold green]")
                return
            except Exception as exc:
                console.print(f"[bold red]✘ Failed to import token:[/bold red] {exc}")
                sys.exit(1)

    user_email = email or click.prompt("Firefox Accounts Email")
    user_password = password or click.prompt("Firefox Accounts Password", hide_input=True)

    fxa_repo = FxaAuthRepository(token_store=token_store)

    async def _do_login() -> RuntimeAuth:
        async with fxa_repo:
            needs_2fa, result = await fxa_repo.login(user_email, user_password)
            if needs_2fa:
                session_token = str(result)
                v_method = getattr(fxa_repo, "verification_method", "email-2fa")
                if v_method == "totp-2fa":
                    console.print("\n[yellow]🔑 Mozilla requires two-factor authentication from your Authenticator app.[/yellow]")
                else:
                    console.print(f"\n[yellow]📩 Mozilla has sent a 6-digit confirmation code to your email inbox: [bold cyan]{user_email}[/bold cyan][/yellow]")
                    console.print("[dim](Please check your Inbox as well as your Spam/Junk folder)[/dim]\n")
                user_code = code or click.prompt("Enter 6-digit confirmation code")
                auth = await fxa_repo.submit_2fa(session_token=session_token, code=user_code)
            else:
                if isinstance(result, RuntimeAuth):
                    auth = result
                else:
                    raise RuntimeError("Unexpected login result from FxA")

            # Persist authenticated email
            auth.email = user_email
            token_store.save_auth(auth)
            return auth

    with console.status("[bold cyan]Authenticating with Firefox Accounts...[/bold cyan]"):
        try:
            auth = asyncio.run(_do_login())
            console.print(f"[bold green]✔ Successfully logged in as {auth.email or user_email}![/bold green]")
            try:
                guardian = GuardianClient()
                asyncio.run(guardian.activate_guardian(auth.access_token))
            except Exception:
                pass
        except Exception as exc:
            console.print(f"[bold red]✘ Login failed:[/bold red] {exc}")
            sys.exit(1)


@cli.command("logout")
def logout() -> None:
    """Log out and remove stored authentication credentials."""
    # Stop background daemon if running
    daemon_mgr = DaemonManager()
    if daemon_mgr.is_daemon_running():
        console.print("[yellow]Stopping active VPN daemon...[/yellow]")
        daemon_mgr.stop_daemon()

    # Disable system proxy
    sys_proxy_mgr = SystemProxyManager()
    if sys_proxy_mgr.is_system_proxy_enabled():
        sys_proxy_mgr.disable_system_proxy()

    token_store = TokenStore()
    token_store.clear()
    console.print("[bold green]✔ Logged out successfully. Credentials cleared.[/bold green]")


@cli.command("accounts")
def accounts_command() -> None:
    """List all saved Firefox accounts."""
    token_store = TokenStore()
    accounts = token_store.list_accounts()
    if not accounts:
        console.print("[yellow]No saved accounts found. Use 'foxyvpn login' to add one.[/yellow]")
        return

    table = Table(box=box.ROUNDED, title="[bold yellow]Saved Firefox Accounts[/bold yellow]")
    table.add_column("#", style="bold yellow", width=4, justify="center")
    table.add_column("Status", width=10, justify="center")
    table.add_column("Email", style="bold white")

    for idx, acc in enumerate(accounts, 1):
        status_str = "[bold green]ACTIVE[/bold green]" if acc["is_active"] else "[dim]Saved[/dim]"
        table.add_row(str(idx), status_str, acc["email"])

    console.print(table)


@cli.command("switch")
@click.argument("email", required=False)
def switch_command(email: str | None = None) -> None:
    """Switch active session to a saved Firefox account."""
    token_store = TokenStore()
    accounts = token_store.list_accounts()
    if not accounts:
        console.print("[yellow]No saved accounts found. Use 'foxyvpn login' to add one.[/yellow]")
        return

    target_email = email
    if not target_email:
        table = Table(box=box.ROUNDED, title="[bold cyan]Select Account to Activate[/bold cyan]")
        table.add_column("#", style="bold yellow", width=4, justify="center")
        table.add_column("Status", width=10, justify="center")
        table.add_column("Email", style="bold white")
        for idx, acc in enumerate(accounts, 1):
            st = "[bold green]ACTIVE[/bold green]" if acc["is_active"] else "[dim]Saved[/dim]"
            table.add_row(str(idx), st, acc["email"])
        console.print(table)
        sel = click.prompt("Enter account # or email")
        if sel.isdigit() and 1 <= int(sel) <= len(accounts):
            target_email = accounts[int(sel) - 1]["email"]
        else:
            target_email = sel.strip()

    if token_store.switch_account(target_email):
        console.print(f"[bold green]✔ Active account switched to: {target_email}[/bold green]")
    else:
        console.print(f"[bold red]✘ Account '{target_email}' not found in saved accounts.[/bold red]")


@cli.group("token")
def token_group() -> None:
    """Export or import session tokens for headless servers."""
    pass


@token_group.command("export")
def token_export() -> None:
    """Export current session token as a portable string."""
    token_store = TokenStore()
    try:
        exported = token_store.export_token()
        console.print("\n[bold cyan]Session Token String (Copy & save securely):[/bold cyan]\n")
        console.print(f"[bold green]{exported}[/bold green]\n")
        console.print("[dim]You can import this token on another server using:[/dim]")
        console.print(f"[dim]foxyvpn token import {exported[:16]}...[/dim]\n")
    except Exception as exc:
        console.print(f"[bold red]✘ Export failed:[/bold red] {exc}")


@token_group.command("import")
@click.argument("token_string")
def token_import(token_string: str) -> None:
    """Import an exported session token string."""
    token_store = TokenStore()
    try:
        auth = token_store.import_token(token_string)
        console.print(f"[bold green]✔ Successfully imported session for {auth.email or 'Active User'}![/bold green]")
    except Exception as exc:
        console.print(f"[bold red]✘ Import failed:[/bold red] {exc}")


# ---------------------------------------------------------------------------
# STATUS & QUOTA
# ---------------------------------------------------------------------------


@cli.command("status")
def status() -> None:
    """Display authentication, subscription, and active VPN connection status."""
    token_store = TokenStore()
    auth = token_store.load_auth()
    daemon_mgr = DaemonManager()
    state_dict = daemon_mgr.load_state()

    conn_state: ConnectionState | None = None
    if state_dict:
        try:
            conn_state = ConnectionState.from_dict(state_dict)
            if not daemon_mgr.is_daemon_running():
                conn_state.status = "DISCONNECTED"
        except Exception:
            pass
    elif daemon_mgr.is_daemon_running():
        conn_state = ConnectionState(status="CONNECTED", socks_port=10808)

    entitlement: Entitlement | None = None
    if auth and auth.access_token:
        async def _fetch_entitlement() -> Entitlement | None:
            try:
                guardian = GuardianClient()
                async with guardian:
                    return await guardian.fetch_user_info(auth.access_token)
            except Exception:
                return None

        entitlement = asyncio.run(_fetch_entitlement())

    table = format_status_table(auth=auth, entitlement=entitlement, state=conn_state)
    console.print(table)


@cli.command("quota")
def quota() -> None:
    """Display current bandwidth quota and monthly usage limit."""
    token_store = TokenStore()
    auth = token_store.load_auth()
    if not auth or not auth.access_token:
        console.print("[bold red]Not logged in.[/bold red] Please run 'foxyvpn login'.")
        sys.exit(1)

    async def _fetch_quota() -> tuple[Entitlement | None, int | None]:
        guardian = GuardianClient()
        async with guardian:
            ent = await guardian.fetch_user_info(auth.access_token)
            pass_data = await guardian.fetch_proxy_pass(auth.access_token)
            return ent, (pass_data.quota_reset if pass_data else None)

    with console.status("[bold cyan]Fetching bandwidth quota from Guardian...[/bold cyan]"):
        try:
            entitlement, reset_epoch = asyncio.run(_fetch_quota())
            if entitlement:
                panel = format_quota_bar(
                    remaining_bytes=entitlement.quota_remaining,
                    max_bytes=entitlement.max_bytes,
                    reset_epoch=reset_epoch,
                )
                console.print(panel)
            else:
                console.print("[bold yellow]Unable to retrieve quota information.[/bold yellow]")
        except Exception as exc:
            console.print(f"[bold red]Error fetching quota:[/bold red] {exc}")
            sys.exit(1)


# ---------------------------------------------------------------------------
# LOCATIONS / SERVERS
# ---------------------------------------------------------------------------


async def _probe_country_pings(
    countries: list[Any],
) -> dict[str, float]:
    """Probe latency to candidate servers across countries concurrently."""
    pings: dict[str, float] = {}

    async def _ping_country(country: Any) -> None:
        for city in country.cities:
            for srv in city.servers:
                if not srv.quarantined:
                    target_port = srv.port if srv.port != 0 else 443
                    val = await ping_server(srv.hostname, target_port, timeout=2.0)
                    if val is not None:
                        pings[country.code] = val
                        pings[srv.hostname] = val
                        return

    tasks = [_ping_country(c) for c in countries]
    await asyncio.gather(*tasks, return_exceptions=True)
    return pings


@cli.command("locations")
@click.option("--ping", is_flag=True, help="Probe latency for server candidates.")
def locations(ping: bool) -> None:
    """List available VPN server countries and probe latencies."""
    async def _run() -> None:
        client = ServerListClient()
        async with client:
            countries = await client.fetch_countries()

        pings: dict[str, float] = {}
        if ping:
            with console.status("[bold cyan]Pinging VPN server locations...[/bold cyan]"):
                pings = await _probe_country_pings(countries)

        table = format_servers_table(countries=countries, pings=pings)
        console.print(table)

    try:
        asyncio.run(_run())
    except Exception as exc:
        console.print(f"[bold red]Failed to fetch server locations:[/bold red] {exc}")
        sys.exit(1)


@cli.command("servers")
@click.option("--ping", is_flag=True, help="Probe latency for server candidates.")
def servers(ping: bool) -> None:
    """Alias for 'locations'."""
    ctx = click.get_current_context()
    ctx.invoke(locations, ping=ping)


# ---------------------------------------------------------------------------
# CONNECT & DISCONNECT
# ---------------------------------------------------------------------------


async def _run_tunnel_service(
    candidate: ProxyCandidate,
    proxy_token: str,
    bind_host: str,
    bind_port: int,
    custom_edge: str | None,
    system_proxy: bool,
    daemon_mode: bool,
    expected_country: str | None = None,
    tun: bool = False,
) -> None:
    """Establish HTTP/2 upstream session and run local SOCKS5 server."""
    sys_proxy_mgr = SystemProxyManager()
    daemon_mgr = DaemonManager()
    tun_mgr = TunManager() if tun else None

    # 1. Establish HTTP/2 upstream connection
    console.print(f"[cyan]Connecting to upstream VPN node:[/cyan] {candidate.host}:{candidate.port}...")
    upstream_session = H2UpstreamSession(
        upstream_host=candidate.host,
        upstream_port=candidate.port or 443,
        bearer_token=proxy_token,
        edge_address=custom_edge or None,
    )
    await upstream_session.connect()

    # 2. Start local SOCKS5 proxy server
    socks_server = LocalSocks5Server(
        bind_address=bind_host,
        port=bind_port,
        session_provider=lambda: upstream_session,
    )
    await socks_server.start()
    console.print(f"[green]✔ Local SOCKS5 proxy listening on[/green] {bind_host}:{bind_port}")

    # 3. Configure OS system proxy or TUN mode
    if tun and tun_mgr:
        if not tun_mgr.is_admin():
            console.print("[yellow]⚠ TUN mode requires Administrator/root privileges. Run with elevated privileges.[/yellow]")
            console.print("[cyan]Falling back to system proxy mode...[/cyan]")
            system_proxy = True
            tun_mgr = None
        else:
            console.print("[cyan]Configuring virtual TUN interface and system routes...[/cyan]")
            vpn_node_ip = upstream_session.remote_ip or getattr(candidate, "edge_ip", None) or ""
            if tun_mgr.start_tun(socks_host=bind_host, socks_port=bind_port, vpn_server_ip=vpn_node_ip):
                console.print("[green]✔ Virtual TUN adapter active (Full-System VPN: TCP/UDP/ICMP/DNS).[/green]")
            else:
                console.print("[yellow]⚠ Failed to start TUN adapter. Falling back to system proxy.[/yellow]")
                system_proxy = True
                tun_mgr = None

    if system_proxy:
        console.print("[cyan]Configuring operating system proxy settings...[/cyan]")
        if sys_proxy_mgr.enable_system_proxy(bind_host, bind_port):
            console.print("[green]✔ System-wide proxy enabled.[/green]")
        else:
            console.print("[yellow]⚠ Failed to automatically set OS system proxy.[/yellow]")

    # 4. Verify egress exit IP through Cloudflare trace
    egress_ip = "Active"
    console.print("[cyan]Verifying egress node via Cloudflare trace...[/cyan]")
    exit_checker = ExitChecker(timeout=8.0)
    try:
        trace_result = await exit_checker.check_exit(
            socks_host=bind_host,
            socks_port=bind_port,
            expected_country=expected_country if expected_country != "REC" else None,
        )
        egress_ip = trace_result.get("ip") or "Active"
        loc = trace_result.get("country") or candidate.country_code
        console.print(f"[bold green]✔ Exit verification successful![/bold green] IP: {egress_ip} ({loc})")
    except Exception as exc:
        logger.debug("Exit check notice: %s", exc)
        console.print(f"[yellow]⚠ Exit check skipped or slow:[/yellow] {exc}")

    # 5. Persist connection state
    start_time = time.time()
    conn_state = ConnectionState(
        status="CONNECTED",
        location=f"{candidate.country_name} ({candidate.country_code})",
        edge_ip=egress_ip,
        server_hostname=candidate.host,
        socks_port=bind_port,
        start_time=start_time,
        tun_mode=bool(tun_mgr and tun_mgr.is_tun_active()),
    )
    daemon_mgr.write_pid(os.getpid())
    daemon_mgr.save_state(conn_state)

    # 6. Event loop / Live dashboard
    stop_event = asyncio.Event()

    def _signal_handler() -> None:
        stop_event.set()

    # Register graceful signal handlers on non-Windows or where supported
    loop = asyncio.get_running_loop()
    if sys.platform != "win32":
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, _signal_handler)
            except (NotImplementedError, RuntimeError):
                pass

    last_bytes_down = 0
    last_bytes_up = 0
    last_tick = time.time()

    try:
        if daemon_mode:
            # Worker daemon loop (no interactive UI)
            while not stop_event.is_set():
                await asyncio.sleep(2.0)
                conn_state.bytes_sent = socks_server.total_bytes_sent()
                conn_state.bytes_received = socks_server.total_bytes_received()
                daemon_mgr.save_state(conn_state)
        else:
            # Foreground interactive Live dashboard
            with Live(
                render_dashboard(
                    candidate=candidate,
                    state=conn_state,
                    system_proxy_active=system_proxy,
                ),
                console=console,
                refresh_per_second=2,
            ) as live:
                while not stop_event.is_set():
                    await asyncio.sleep(0.5)
                    now = time.time()
                    dt = max(0.001, now - last_tick)

                    total_sent = socks_server.total_bytes_sent()
                    total_recv = socks_server.total_bytes_received()

                    speed_up = max(0.0, (total_sent - last_bytes_up) / dt)
                    speed_down = max(0.0, (total_recv - last_bytes_down) / dt)

                    last_bytes_up = total_sent
                    last_bytes_down = total_recv
                    last_tick = now

                    conn_state.bytes_sent = total_sent
                    conn_state.bytes_received = total_recv
                    daemon_mgr.save_state(conn_state)

                    live.update(
                        render_dashboard(
                            candidate=candidate,
                            state=conn_state,
                            speed_down=speed_down,
                            speed_up=speed_up,
                            system_proxy_active=system_proxy,
                        )
                    )
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        console.print("\n[yellow]Shutting down VPN proxy and restoring settings...[/yellow]")
        if tun_mgr:
            tun_mgr.stop_tun()
        if system_proxy:
            sys_proxy_mgr.disable_system_proxy()
        try:
            await socks_server.stop()
        except Exception:
            pass
        try:
            upstream_session.close()
        except Exception:
            pass
        daemon_mgr.remove_pid()
        daemon_mgr.remove_state()
        console.print("[bold green]✔ Disconnected gracefully.[/bold green]")


@cli.command("connect")
@click.option("--country", "-c", default=None, help="Target country code (e.g. US, DE) or 'REC'.")
@click.option("--city", default=None, help="Target city code (optional).")
@click.option("--port", "-p", default=None, type=int, help="Local SOCKS5 port (default: 10808).")
@click.option("--bind", "-b", default=None, help="Local SOCKS5 bind IP (default: 127.0.0.1).")
@click.option("--system-proxy/--no-system-proxy", default=None, help="Set system OS proxy.")
@click.option("--tun", "-t", is_flag=True, help="Enable full-system TUN mode (Virtual Network Adapter).")
@click.option("--daemon", "-d", is_flag=True, help="Run VPN connection in background.")
@click.option("--edge", default=None, help="Override Fastly upstream edge IP.")
@click.option("--worker", is_flag=True, hidden=True, help="Internal background worker flag.")
def connect(
    country: str | None,
    city: str | None,
    port: int | None,
    bind: str | None,
    system_proxy: bool | None,
    tun: bool,
    daemon: bool,
    edge: str | None,
    worker: bool,
) -> None:
    """Connect to Firefox VPN and start local SOCKS5 proxy."""
    settings_store = SettingsStore()
    settings = settings_store.load()

    target_port = port if port is not None else settings.socks_port
    target_bind = bind if bind is not None else settings.socks_host
    use_system_proxy = system_proxy if system_proxy is not None else settings.system_proxy
    custom_edge = edge or (settings.custom_edge if settings.custom_edge else None)

    daemon_mgr = DaemonManager()

    # If running in daemon mode and not yet the spawned worker, spawn worker process
    if daemon and not worker:
        if daemon_mgr.is_daemon_running():
            console.print("[yellow]FoxyVPN daemon is already running.[/yellow]")
            return

        cmd = [
            sys.executable,
            "-m",
            "foxyvpn.cli",
            "connect",
            "--worker",
            "--port",
            str(target_port),
            "--bind",
            target_bind,
        ]
        if country:
            cmd.extend(["--country", country])
        if city:
            cmd.extend(["--city", city])
        if use_system_proxy:
            cmd.append("--system-proxy")
        if tun:
            cmd.append("--tun")
        if custom_edge:
            cmd.extend(["--edge", custom_edge])

        log_path = get_config_dir() / "daemon.log"
        pid = daemon_mgr.spawn_daemon(cmd, log_file=log_path)
        console.print(f"[bold green]✔ Started FoxyVPN background daemon with PID {pid}[/bold green]")
        console.print("  • SOCKS5 proxy: 127.0.0.1:" + str(target_port))
        console.print("  • To check status: [cyan]foxyvpn status[/cyan]")
        console.print("  • To disconnect:   [cyan]foxyvpn disconnect[/cyan]")
        return

    # Check authentication
    token_store = TokenStore()
    if not token_store.has_stored_session():
        console.print("[bold red]Not logged in.[/bold red] Please run 'foxyvpn login' first.")
        sys.exit(1)

    async def _setup_and_run() -> None:
        # Step 1: Ensure fresh FxA access token
        fxa_repo = FxaAuthRepository(token_store=token_store)
        async with fxa_repo:
            try:
                auth = await fxa_repo.ensure_fresh_access_token()
            except Exception as exc:
                console.print(f"[bold red]Authentication refresh failed:[/bold red] {exc}")
                sys.exit(1)

        # Step 2: Fetch Guardian ProxyPass
        guardian = GuardianClient()
        async with guardian:
            try:
                proxy_pass = await guardian.fetch_proxy_pass(access_token=auth.access_token)
            except Exception as exc:
                console.print(f"[bold red]Failed to fetch proxy token from Guardian:[/bold red] {exc}")
                sys.exit(1)

        # Step 3: Fetch server list and select candidate
        server_client = ServerListClient()
        async with server_client:
            countries = await server_client.fetch_countries()

        req_country = (country or settings.default_country or "REC").strip().upper()
        req_city = (city or settings.default_city or "").strip().lower()

        candidate: ProxyCandidate | None = None
        if req_country == "REC":
            candidate = get_recommended_candidate(countries)
            if not candidate and countries:
                first_cands = candidates_for_country(countries, countries[0].code)
                candidate = first_cands[0] if first_cands else None
        else:
            if req_city:
                candidates = candidates_for_city(countries, req_country, req_city)
            else:
                candidates = candidates_for_country(countries, req_country)
            if not candidates:
                console.print(f"[bold red]No servers available for country '{req_country}'.[/bold red]")
                sys.exit(1)
            candidate = candidates[0]

        if not candidate:
            console.print("[bold red]No VPN servers found.[/bold red]")
            sys.exit(1)

        # Step 4-9: Establish tunnel and run proxy
        await _run_tunnel_service(
            candidate=candidate,
            proxy_token=proxy_pass.token,
            bind_host=target_bind,
            bind_port=target_port,
            custom_edge=custom_edge,
            system_proxy=use_system_proxy,
            daemon_mode=worker,
            expected_country=req_country,
            tun=tun,
        )

    try:
        asyncio.run(_setup_and_run())
    except Exception as exc:
        console.print(f"[bold red]Connection error:[/bold red] {exc}")
        sys.exit(1)


@cli.command("disconnect")
def disconnect() -> None:
    """Disconnect active VPN connection and restore proxy settings."""
    stopped_anything = False
    daemon_mgr = DaemonManager()
    if daemon_mgr.is_daemon_running():
        console.print("[cyan]Stopping FoxyVPN background daemon...[/cyan]")
        daemon_mgr.stop_daemon()
        stopped_anything = True

    tun_mgr = TunManager()
    tun_mgr.stop_tun()

    sys_proxy_mgr = SystemProxyManager()
    if sys_proxy_mgr.is_system_proxy_enabled():
        console.print("[cyan]Disabling system OS proxy...[/cyan]")
        sys_proxy_mgr.disable_system_proxy()
        stopped_anything = True

    daemon_mgr.remove_pid()
    daemon_mgr.remove_state()

    if stopped_anything:
        console.print("[bold green]✔ Successfully disconnected from FoxyVPN.[/bold green]")
    else:
        console.print("[yellow]FoxyVPN was not actively connected.[/yellow]")


# ---------------------------------------------------------------------------
# VERIFY / TEST
# ---------------------------------------------------------------------------


@cli.command("verify")
@click.option("--port", "-p", default=None, type=int, help="Local SOCKS5 port (default: 10808).")
@click.option("--host", "-h", default="127.0.0.1", help="Local SOCKS5 host.")
def verify(port: int | None, host: str) -> None:
    """Verify tunnel egress IP and geolocation using Cloudflare trace."""
    settings = SettingsStore().load()
    socks_port = port if port is not None else settings.socks_port

    async def _do_verify() -> None:
        checker = ExitChecker()
        with console.status(f"[bold cyan]Querying Cloudflare trace via {host}:{socks_port}...[/bold cyan]"):
            try:
                res = await checker.check_exit(socks_host=host, socks_port=socks_port)
                table = Table(title="Exit Node Verification", box=box.ROUNDED)
                table.add_column("Property", style="bold")
                table.add_column("Value", style="cyan")

                table.add_row("Exit IP", res.get("ip", "N/A"))
                table.add_row("Location Code", res.get("country", "N/A"))
                for k, v in res.get("details", {}).items():
                    if k not in ("ip", "loc"):
                        table.add_row(k, v)

                console.print(table)
                console.print("[bold green]✔ Exit node verified successfully.[/bold green]")
            except Exception as exc:
                console.print(f"[bold red]✘ Verification failed:[/bold red] {exc}")
                sys.exit(1)

    asyncio.run(_do_verify())


@cli.command("test")
@click.option("--port", "-p", default=None, type=int, help="Local SOCKS5 port.")
@click.option("--host", "-h", default="127.0.0.1", help="Local SOCKS5 host.")
def test(port: int | None, host: str) -> None:
    """Alias for 'verify'."""
    ctx = click.get_current_context()
    ctx.invoke(verify, port=port, host=host)


# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------


@cli.group("config", invoke_without_command=True)
@click.pass_context
def config(ctx: click.Context) -> None:
    """View and modify FoxyVPN local configuration."""
    if ctx.invoked_subcommand is None:
        store = SettingsStore()
        settings = store.load()
        table = Table(title="FoxyVPN Settings", box=box.ROUNDED)
        table.add_column("Setting", style="bold magenta")
        table.add_column("Value", style="cyan")

        for k, v in sorted(settings.to_dict().items()):
            table.add_row(k, str(v))
        console.print(table)


@config.command("show")
def config_show() -> None:
    """Display all current configuration settings."""
    store = SettingsStore()
    settings = store.load()
    table = Table(title="FoxyVPN Settings", box=box.ROUNDED)
    table.add_column("Setting", style="bold magenta")
    table.add_column("Value", style="cyan")
    for k, v in sorted(settings.to_dict().items()):
        table.add_row(k, str(v))
    console.print(table)


@config.command("get")
@click.argument("key")
def config_get(key: str) -> None:
    """Get the value of a specific setting."""
    store = SettingsStore()
    val = store.get(key)
    if val is not None:
        console.print(f"[bold]{key}:[/bold] [cyan]{val}[/cyan]")
    else:
        console.print(f"[yellow]Setting '{key}' not found.[/yellow]")


@config.command("set")
@click.argument("key")
@click.argument("value")
def config_set(key: str, value: str) -> None:
    """Update a specific configuration setting."""
    store = SettingsStore()
    # Convert types automatically if matches boolean or integer
    val: Any = value
    if value.lower() in ("true", "yes", "1"):
        val = True
    elif value.lower() in ("false", "no", "0"):
        val = False
    elif value.isdigit():
        val = int(value)

    store.set(key, val)
    console.print(f"[bold green]✔ Updated {key} = {val}[/bold green]")


if __name__ == "__main__":
    cli()
