"""Interactive Menu Interface for FoxyVPN.

Provides a user-friendly, menu-driven terminal interface so users do not
need to remember command-line arguments or flags.
"""

from __future__ import annotations

import asyncio
import getpass
import os
import sys
import time
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

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table
from rich.text import Text

from foxyvpn.proxy.resolver import enable_secure_dns

enable_secure_dns()

from foxyvpn.api.guardian import GuardianClient, GuardianHttpError, QuotaExceededError, TokenInvalidError
from foxyvpn.api.ping import ping_candidates, ping_server
from foxyvpn.api.server_list import (
    ServerListClient,
    candidates_for_country,
    get_recommended_candidate,
)
from foxyvpn.auth.fxa import FxaApiError, FxaAuthRepository
from foxyvpn.auth.web_auth import run_browser_login
from foxyvpn.core.config import Settings, get_config_dir, load_settings, save_settings
from foxyvpn.core.models import ConnectionState, Entitlement, ProxyCandidate, RuntimeAuth, VpnCountry
from foxyvpn.core.store import SettingsStore, TokenStore
from foxyvpn.proxy.exit_check import ExitChecker
from foxyvpn.proxy.socks5 import LocalSocks5Server
from foxyvpn.system.daemon import DaemonManager
from foxyvpn.system.proxy import SystemProxyManager
from foxyvpn.system.tun import TunManager
from foxyvpn.tunnel.h2_session import H2UpstreamSession
from foxyvpn.tunnel.upstream import UpstreamConnectRejectedException, UpstreamProxyConfig
from foxyvpn.ui.formatters import (
    format_quota_bar,
    format_servers_table,
    format_status_table,
    print_banner,
    render_dashboard,
)

console = Console()


def _get_status_summary() -> tuple[str, str, str]:
    """Get brief summary strings for Account, Daemon, and Proxy."""
    token_store = TokenStore()
    daemon_mgr = DaemonManager()
    proxy_mgr = SystemProxyManager()

    # 1. Auth status
    auth = token_store.load_auth()
    if auth and auth.email:
        acc_text = f"[green]● {auth.email}[/green]"
    elif auth:
        acc_text = "[green]● Logged in (active session)[/green]"
    else:
        acc_text = "[yellow]○ Not logged in (Guest)[/yellow]"

    # 2. VPN Tunnel status
    if daemon_mgr.is_daemon_running():
        state = daemon_mgr.load_state()
        loc = state.location or "Unknown" if state else "Unknown"
        port = state.socks_port if state else 10808
        vpn_text = f"[bold green]● CONNECTED[/bold green] ([cyan]{loc}[/cyan] | SOCKS: [cyan]127.0.0.1:{port}[/cyan])"
    else:
        vpn_text = "[bold red]○ DISCONNECTED[/bold red]"

    # 3. System Proxy status
    if proxy_mgr.is_system_proxy_enabled():
        sys_text = "[bold green]ON[/bold green]"
    else:
        sys_text = "[dim]OFF[/dim]"

    return acc_text, vpn_text, sys_text


def _render_menu_panel() -> None:
    """Render top summary and main menu options."""
    acc_text, vpn_text, sys_text = _get_status_summary()

    # Summary table
    summary_table = Table.grid(padding=(0, 2))
    summary_table.add_column(style="bold")
    summary_table.add_column()
    summary_table.add_row("Account:", acc_text)
    summary_table.add_row("VPN Tunnel:", vpn_text)
    summary_table.add_row("System Proxy:", sys_text)

    console.print(Panel(summary_table, title="[bold cyan]Current Status[/bold cyan]", border_style="cyan"))

    # Menu items table
    menu_table = Table(box=box.ROUNDED, show_header=False, expand=True, border_style="blue")
    menu_table.add_column("Key", style="bold yellow", width=6, justify="center")
    menu_table.add_column("Icon", width=4, justify="center")
    menu_table.add_column("Action", style="bold white")
    menu_table.add_column("Description", style="dim")

    menu_table.add_row("[1]", "⚡", "Quick Connect", "Auto-connect to lowest latency location")
    menu_table.add_row("[2]", "🌍", "Choose Location & Connect", "Select from 30+ countries and cities")
    menu_table.add_row("[3]", "🛑", "Disconnect VPN", "Stop tunnel and restore OS proxy settings")
    menu_table.add_row("[4]", "📊", "Connection Status", "View full account, entitlement, and tunnel info")
    menu_table.add_row("[5]", "📦", "Bandwidth Quota", "Check your monthly 50 GB traffic allowance")
    menu_table.add_row("[6]", "🏓", "Server Locations & Pings", "List available countries with live latency test")
    menu_table.add_row("[7]", "🔍", "Verify Exit IP & Location", "Check exit IP and country via Cloudflare trace")
    menu_table.add_row("[8]", "🔑", "Account & Login", "Sign in, sign out, or switch Firefox account")
    menu_table.add_row("[9]", "⚙️", "Settings & Configuration", "Configure SOCKS port, DoH DNS, System Proxy")
    menu_table.add_row("[0]", "🚪", "Exit", "Close FoxyVPN menu")

    console.print(Panel(menu_table, title="[bold yellow]FoxyVPN Main Menu[/bold yellow]", border_style="blue"))


# ---------------------------------------------------------------------------
# SUBMENU HANDLERS
# ---------------------------------------------------------------------------


def handle_accounts_management() -> None:
    """Multi-account management: switch, add, or remove accounts."""
    token_store = TokenStore()
    daemon_mgr = DaemonManager()
    proxy_mgr = SystemProxyManager()

    while True:
        console.print("\n[bold cyan]─── Firefox Accounts Management ───[/bold cyan]")
        accounts = token_store.list_accounts()
        current = token_store.load_auth()

        table = Table(box=box.ROUNDED, show_header=True, title="[bold yellow]Saved Firefox Accounts[/bold yellow]")
        table.add_column("#", style="bold yellow", width=4, justify="center")
        table.add_column("Status", width=10, justify="center")
        table.add_column("Account Email", style="bold white")
        table.add_column("Session State", style="cyan")

        if not accounts:
            table.add_row("-", "[dim]None[/dim]", "[dim]No saved accounts found[/dim]", "[dim]-[/dim]")
        else:
            for idx, acc in enumerate(accounts, 1):
                email = acc["email"]
                is_active = acc["is_active"]
                status_str = "[bold green]ACTIVE[/bold green]" if is_active else "[dim]Saved[/dim]"
                exp_ts = acc.get("expires_at", 0)
                if exp_ts > time.time():
                    days_left = max(1, int((exp_ts - time.time()) / 86400))
                    state_str = f"[green]Valid (renews via token, ~{days_left}d)[/green]"
                else:
                    state_str = "[yellow]Auto-renew ready[/yellow]"

                table.add_row(str(idx), status_str, email, state_str)

        console.print(table)

        console.print("\n[bold]Options:[/bold]")
        if len(accounts) > 1:
            console.print("  [bold cyan][#][/bold cyan] Enter account number (e.g. 1, 2) to [bold green]switch immediately[/bold green]")
        console.print("  [bold cyan][A][/bold cyan] Add / Log in with a new Firefox account")
        if accounts:
            console.print("  [bold cyan][S][/bold cyan] Switch active account")
            console.print("  [bold cyan][R][/bold cyan] Remove a saved account")
            console.print("  [bold cyan][L][/bold cyan] Log out current active account")
        console.print("  [bold cyan][0][/bold cyan] Back to Main Menu")

        choice = Prompt.ask("\nChoose an action", default="0").strip()

        if choice in ("0", "b", "back", "q"):
            break
        elif choice.isdigit() and 1 <= int(choice) <= len(accounts):
            target_acc = accounts[int(choice) - 1]
            target_email = target_acc["email"]
            if target_acc["is_active"]:
                console.print(f"[yellow]Account '{target_email}' is already the active account.[/yellow]")
            else:
                if daemon_mgr.is_daemon_running():
                    console.print("[yellow]Notice: An active VPN connection is currently running.[/yellow]")
                    if Confirm.ask("Would you like to restart the VPN with this new account?", default=True):
                        daemon_mgr.stop_daemon()
                        proxy_mgr.disable_system_proxy()
                token_store.switch_account(target_email)
                console.print(f"[bold green]✔ Successfully switched active account to: {target_email}[/bold green]")
            time.sleep(1)
        elif choice.upper() == "A":
            handle_login()
        elif choice.upper() == "S":
            if not accounts:
                console.print("[yellow]No saved accounts available. Use [A] to add an account first.[/yellow]")
                continue
            acc_num = IntPrompt.ask(f"Enter account number to activate (1-{len(accounts)})")
            if 1 <= acc_num <= len(accounts):
                target_email = accounts[acc_num - 1]["email"]
                token_store.switch_account(target_email)
                console.print(f"[bold green]✔ Switched active account to: {target_email}[/bold green]")
                time.sleep(1)
            else:
                console.print("[red]Invalid account number.[/red]")
        elif choice.upper() == "R":
            if not accounts:
                console.print("[yellow]No saved accounts to remove.[/yellow]")
                continue
            acc_num = IntPrompt.ask(f"Enter account number to remove (1-{len(accounts)})")
            if 1 <= acc_num <= len(accounts):
                rem_email = accounts[acc_num - 1]["email"]
                if Confirm.ask(f"Are you sure you want to remove '{rem_email}'?", default=True):
                    token_store.remove_account(rem_email)
                    console.print(f"[green]✔ Removed account '{rem_email}'.[/green]")
                    time.sleep(1)
            else:
                console.print("[red]Invalid account number.[/red]")
        elif choice.upper() == "L":
            handle_logout()
        else:
            console.print("[red]Invalid option. Please try again.[/red]")


def handle_login() -> None:
    """Interactive login flow with browser, terminal, and token import options."""
    console.print("\n[bold cyan]─── Firefox Accounts Login ───[/bold cyan]")
    token_store = TokenStore()

    console.print("[bold]Choose Login Method:[/bold]")
    console.print("  [bold cyan][1][/bold cyan] 🌐 [bold]Web Browser Login[/bold] (Recommended - works on local PC, Mac, or Remote Server)")
    console.print("  [bold cyan][2][/bold cyan] 💻 [bold]Terminal Direct Login[/bold] (Type email & password in CLI)")
    console.print("  [bold cyan][3][/bold cyan] 📋 [bold]Import Session Token[/bold] (Paste token string exported from another machine)")
    console.print("  [bold cyan][0][/bold cyan] Back")

    method = Prompt.ask("\nSelect method", default="1").strip()
    if method in ("0", "b", "back", "q"):
        return
    elif method == "1":
        # Browser Login
        auth = run_browser_login(token_store=token_store)
        if auth:
            return
        # If timed out or failed, offer terminal fallback
        if not Confirm.ask("Would you like to try terminal direct login instead?", default=False):
            return
    elif method == "3":
        # Token Import
        token_str = Prompt.ask("Paste exported session token string").strip()
        try:
            auth = token_store.import_token(token_str)
            console.print(f"[bold green]✔ Successfully imported session for {auth.email or 'Active User'}![/bold green]")
            return
        except Exception as err:
            console.print(f"[bold red]✘ Failed to import token:[/bold red] {err}")
            return

    # Terminal direct credentials login
    email = Prompt.ask("[bold]Firefox Accounts Email[/bold]")
    password = Prompt.ask("[bold]Password[/bold]", password=True)

    fxa_repo = FxaAuthRepository(token_store=token_store)

    async def _do_login():
        async with fxa_repo:
            needs_2fa, result = await fxa_repo.login(email, password)
            if needs_2fa:
                session_token = str(result)
                v_method = getattr(fxa_repo, "verification_method", "email-2fa")
                if v_method == "totp-2fa":
                    console.print("\n[yellow]🔑 Mozilla requires two-factor authentication from your Authenticator app.[/yellow]")
                else:
                    console.print(f"\n[yellow]📩 Mozilla has sent a 6-digit confirmation code to your email inbox: [bold cyan]{email}[/bold cyan][/yellow]")
                    console.print("[dim](Please check your Inbox as well as your Spam/Junk folder)[/dim]\n")
                code = Prompt.ask("[bold]Enter 6-digit code[/bold]")
                return await fxa_repo.submit_2fa(session_token=session_token, code=code)
            elif isinstance(result, RuntimeAuth):
                return result
            else:
                session_token = str(result)
                return await fxa_repo.fxa_credentials_oauth(session_token)

    with console.status("[cyan]Authenticating with Firefox Accounts...[/cyan]"):
        try:
            auth = asyncio.run(_do_login())
            console.print(f"[bold green]✔ Successfully logged in as {auth.email or email}![/bold green]")
            # Ensure Guardian free entitlement is activated immediately
            try:
                guardian = GuardianClient()
                asyncio.run(guardian.activate_guardian(auth.access_token))
            except Exception:
                pass
        except FxaApiError as err:
            console.print(f"[bold red]✘ Login failed:[/bold red] {err.message} (errno={err.errno})")
        except Exception as err:
            console.print(f"[bold red]✘ Login error:[/bold red] {err}")


def handle_logout() -> None:
    """Interactive logout flow."""
    token_store = TokenStore()
    daemon_mgr = DaemonManager()
    proxy_mgr = SystemProxyManager()

    if not token_store.load_auth():
        console.print("[yellow]You are not currently logged in.[/yellow]")
        return

    if Confirm.ask("Are you sure you want to log out and clear saved credentials?", default=True):
        if daemon_mgr.is_daemon_running():
            console.print("[yellow]Stopping active VPN session...[/yellow]")
            daemon_mgr.stop_daemon()
            proxy_mgr.disable_system_proxy()
        token_store.clear()
        console.print("[bold green]✔ Logged out successfully.[/bold green]")


def handle_quota() -> None:
    """View quota allowance."""
    token_store = TokenStore()
    auth = token_store.load_auth()
    if not auth or not auth.access_token:
        console.print("[bold red]Not logged in.[/bold red] Please select option [8] to log in first.")
        Prompt.ask("\nPress Enter to return to menu...")
        return

    guardian = GuardianClient()

    async def _fetch():
        async with guardian:
            proxy_pass = await guardian.fetch_proxy_pass(auth.access_token)
            entitlement = await guardian.fetch_user_info(auth.access_token)
            return proxy_pass, entitlement

    with console.status("[cyan]Fetching quota details from Mozilla Guardian...[/cyan]"):
        try:
            proxy_pass, entitlement = asyncio.run(_fetch())
            console.print("\n[bold cyan]─── Monthly Bandwidth Quota ───[/bold cyan]")
            panel = format_quota_bar(
                remaining_bytes=proxy_pass.quota_remaining,
                max_bytes=proxy_pass.quota_max or entitlement.max_bytes,
                reset_epoch=proxy_pass.quota_reset,
            )
            console.print(panel)
        except Exception as err:
            console.print(f"[bold red]Failed to fetch quota:[/bold red] {err}")

    Prompt.ask("\nPress Enter to return to menu...")


def handle_status() -> None:
    """View detailed status table."""
    token_store = TokenStore()
    daemon_mgr = DaemonManager()
    auth = token_store.load_auth()
    state = daemon_mgr.load_state() if daemon_mgr.is_daemon_running() else None

    entitlement: Entitlement | None = None
    if auth and auth.access_token:
        guardian = GuardianClient()

        async def _fetch():
            async with guardian:
                return await guardian.fetch_user_info(auth.access_token)

        try:
            entitlement = asyncio.run(_fetch())
        except Exception:
            pass

    console.print("\n[bold cyan]─── Detailed Connection & Account Status ───[/bold cyan]")
    table = format_status_table(auth=auth, entitlement=entitlement, state=state)
    console.print(table)
    Prompt.ask("\nPress Enter to return to menu...")


def handle_locations() -> None:
    """List locations with optional ping probe."""
    server_client = ServerListClient()

    with console.status("[cyan]Fetching server list from Mozilla Remote Settings...[/cyan]"):
        try:
            countries = asyncio.run(server_client.fetch_countries())
        except Exception as err:
            console.print(f"[bold red]Failed to fetch servers:[/bold red] {err}")
            Prompt.ask("\nPress Enter to return to menu...")
            return

    run_ping = Confirm.ask("Do you want to test live ping latencies to all locations?", default=True)
    ping_results: dict[str, float] = {}

    if run_ping:
        candidates: list[ProxyCandidate] = []
        for c in countries:
            cands = candidates_for_country(countries, c.code)
            if cands:
                candidates.append(cands[0])

        with console.status("[cyan]Probing latency to Fastly edge servers...[/cyan]"):
            try:
                probed = asyncio.run(ping_candidates(candidates, timeout=3.0))
                for cand in probed:
                    if cand.ping_ms is not None:
                        ping_results[cand.country_code.upper()] = cand.ping_ms
            except Exception as err:
                console.print(f"[yellow]Ping probe warning:[/yellow] {err}")

    console.print("\n")
    table = format_servers_table(countries=countries, pings=ping_results if ping_results else None)
    console.print(table)
    Prompt.ask("\nPress Enter to return to menu...")


def handle_verify() -> None:
    """Verify exit IP and country."""
    daemon_mgr = DaemonManager()
    settings_store = SettingsStore()
    settings = settings_store.load()

    port = settings.socks_port
    if daemon_mgr.is_daemon_running():
        st = daemon_mgr.load_state()
        if st and st.socks_port:
            port = st.socks_port

    checker = ExitChecker()

    console.print(f"\n[cyan]Testing egress traffic through SOCKS5 proxy (127.0.0.1:{port})...[/cyan]")
    with console.status("[cyan]Querying Cloudflare trace endpoint...[/cyan]"):
        try:
            res = asyncio.run(checker.check_exit(socks_host="127.0.0.1", socks_port=port))
            table = Table(box=box.ROUNDED, title="[bold green]Egress Verification[/bold green]")
            table.add_column("Property", style="bold cyan")
            table.add_column("Value", style="bold white")

            table.add_row("Exit IP Address", res.get("ip", "Unknown"))
            table.add_row("Country (ISO)", res.get("country", "Unknown"))
            table.add_row("Warp Status", res.get("details", {}).get("warp", "off"))
            table.add_row("Data Center", res.get("details", {}).get("colo", "Unknown"))
            console.print(table)
            console.print("[bold green]✔ Traffic is actively routing through the VPN tunnel![/bold green]")
        except Exception as err:
            console.print(f"[bold red]✘ Verification failed:[/bold red] {err}")
            console.print("[dim](Ensure VPN connection is running or start one with option [1] or [2])[/dim]")

    Prompt.ask("\nPress Enter to return to menu...")


def handle_disconnect() -> None:
    """Disconnect active VPN."""
    daemon_mgr = DaemonManager()
    proxy_mgr = SystemProxyManager()

    if not daemon_mgr.is_daemon_running():
        console.print("[yellow]No active background VPN daemon detected.[/yellow]")
        # Still make sure proxy is clean if requested
        if proxy_mgr.is_system_proxy_enabled():
            if Confirm.ask("System proxy is currently ON. Would you like to turn it OFF?", default=True):
                proxy_mgr.disable_system_proxy()
                console.print("[green]✔ System proxy disabled.[/green]")
        return

    console.print("[yellow]Stopping VPN connection and restoring system proxy...[/yellow]")
    stopped = daemon_mgr.stop_daemon()
    proxy_mgr.disable_system_proxy()
    tun_mgr = TunManager()
    tun_mgr.stop_tun()
    if stopped:
        console.print("[bold green]✔ VPN disconnected and system settings restored successfully.[/bold green]")
    else:
        console.print("[yellow]VPN process was stopped and proxy settings restored.[/yellow]")


def handle_connect(country_code: str | None = None) -> None:
    """Orchestrate VPN connection."""
    token_store = TokenStore()
    settings_store = SettingsStore()
    settings = settings_store.load()
    daemon_mgr = DaemonManager()
    proxy_mgr = SystemProxyManager()

    # 1. Check Auth
    auth = token_store.load_auth()
    if not auth or not auth.access_token:
        console.print("[yellow]You must be logged into a Firefox Account before connecting.[/yellow]")
        if Confirm.ask("Would you like to log in now?", default=True):
            handle_login()
            auth = token_store.load_auth()
            if not auth or not auth.access_token:
                return
        else:
            return

    if auth.is_expired() and auth.refresh_token:
        with console.status("[cyan]Access token expired. Renewing with refresh token...[/cyan]"):
            try:
                fxa_repo = FxaAuthRepository(token_store=token_store)
                async def _refresh():
                    async with fxa_repo:
                        return await fxa_repo.refresh_access_token(auth.refresh_token)
                auth = asyncio.run(_refresh())
                console.print("[green]✔ Authentication token refreshed successfully.[/green]")
            except Exception as exc:
                console.print(f"[yellow]⚠ Token renewal failed: {exc}. Attempting connection with current token...[/yellow]")

    # 2. Check if already running
    if daemon_mgr.is_daemon_running():
        st = daemon_mgr.load_state()
        loc = st.location if st else "active server"
        console.print(f"[yellow]A VPN session is already running connected to {loc}.[/yellow]")
        if Confirm.ask("Do you want to disconnect the existing session first?", default=True):
            daemon_mgr.stop_daemon()
            proxy_mgr.disable_system_proxy()
            time.sleep(0.5)
        else:
            return

    # 3. Connection Options
    tun_mgr = TunManager()
    is_admin = tun_mgr.is_admin()

    console.print("\n[bold cyan]Select Network Routing Mode:[/bold cyan]")
    console.print("  [1] System Proxy Mode (Browsers & Desktop Apps - Standard user) [bold green](Default)[/bold green]")
    console.print("  [2] Full-System TUN Mode (Virtual Network Adapter - Games, ICMP, DNS, 100% traffic)")
    console.print("  [3] Proxy-Only Mode (SOCKS5 on 127.0.0.1:10808 without changing OS settings)")
    mode_choice = Prompt.ask("Choose mode [1-3]", choices=["1", "2", "3"], default="1")

    enable_tun = False
    enable_sys_proxy = False

    if mode_choice == "2":
        if not is_admin:
            console.print("[yellow]⚠ TUN mode requires Administrator/root privileges.[/yellow]")
            if Confirm.ask("Would you like to fall back to System Proxy Mode?", default=True):
                enable_sys_proxy = True
            else:
                return
        else:
            enable_tun = True
    elif mode_choice == "1":
        enable_sys_proxy = True

    run_daemon = Confirm.ask("Run VPN in background (Daemon mode)?", default=False)

    target_country = (country_code or settings.default_country or "REC").upper()
    socks_port = settings.socks_port or 10808
    socks_bind = settings.socks_host or "127.0.0.1"

    if run_daemon:
        console.print(f"[cyan]Launching background daemon for location '{target_country}'...[/cyan]")
        log_path = get_config_dir() / "daemon.log"
        pid = daemon_mgr.spawn_daemon(
            log_file=log_path,
            country=target_country,
            city="",
            port=socks_port,
            bind=socks_bind,
            system_proxy=enable_sys_proxy,
            tun=enable_tun,
        )
        if pid:
            console.print(f"[bold green]✔ VPN daemon started successfully (PID: {pid})![/bold green]")
            console.print(f"SOCKS5 Proxy is listening on: [bold cyan]{socks_bind}:{socks_port}[/bold cyan]")
            if enable_sys_proxy:
                console.print("[green]System proxy has been configured.[/green]")
        else:
            console.print("[bold red]Failed to spawn background daemon.[/bold red]")
        Prompt.ask("\nPress Enter to return to menu...")
        return

    # Foreground Mode
    console.print(f"\n[cyan]Connecting to Firefox VPN ({target_country})...[/cyan]")

    server_client = ServerListClient()
    guardian_client = GuardianClient()
    exit_checker = ExitChecker()

    async def _run_foreground():
        nonlocal enable_sys_proxy, enable_tun
        # A. Fetch servers
        with console.status("[cyan]Fetching server topology...[/cyan]"):
            countries = await server_client.fetch_countries()
            candidate: ProxyCandidate | None = None
            if target_country == "REC":
                candidate = get_recommended_candidate(countries)
            else:
                cands = candidates_for_country(countries, target_country)
                candidate = cands[0] if cands else None

            if not candidate:
                candidate = get_recommended_candidate(countries)
            if not candidate:
                raise RuntimeError(f"No available server found for '{target_country}'")

        # B. Fetch ProxyPass
        with console.status("[cyan]Obtaining proxy pass token from Guardian...[/cyan]"):
            proxy_pass = await guardian_client.fetch_proxy_pass(auth.access_token)

        # C. Upstream session
        session = H2UpstreamSession(
            upstream_host=candidate.host,
            upstream_port=candidate.port,
            bearer_token=proxy_pass.token,
        )

        with console.status(f"[cyan]Establishing HTTP/2 TLS tunnel to {candidate.host}...[/cyan]"):
            await session.connect()

        # D. Start local SOCKS5 server
        bytes_sent = 0
        bytes_received = 0

        def _on_stats(s: int, r: int):
            nonlocal bytes_sent, bytes_received
            bytes_sent += s
            bytes_received += r

        socks_server = LocalSocks5Server(
            bind_address=socks_bind,
            port=socks_port,
            session_provider=lambda: session,
            on_stats_update=_on_stats,
        )
        await socks_server.start()

        if enable_tun:
            console.print("[cyan]Activating virtual TUN network adapter...[/cyan]")
            vpn_node_ip = session.remote_ip or getattr(candidate, "edge_ip", None) or ""
            if tun_mgr.start_tun(socks_host=socks_bind, socks_port=socks_port, vpn_server_ip=vpn_node_ip):
                console.print("[green]✔ Virtual TUN adapter active (100% system traffic routed).[/green]")
            else:
                console.print("[yellow]⚠ Failed to start TUN adapter. Falling back to system proxy.[/yellow]")
                enable_sys_proxy = True

        if enable_sys_proxy:
            proxy_mgr.enable_system_proxy(socks_bind, socks_port)

        # E. Exit verification
        exit_ip = "Unknown"
        try:
            res = await exit_checker.check_exit(socks_bind, socks_port, candidate.country_code)
            exit_ip = res.get("ip", "Unknown")
        except Exception:
            pass

        loc_label = f"{candidate.country_name} ({candidate.country_code})"
        start_time = time.time()

        console.print(f"[bold green]✔ Connected to {loc_label}![/bold green] (Exit IP: [cyan]{exit_ip}[/cyan])")
        console.print("[dim]Press Ctrl+C at any time to disconnect cleanly and return to menu.[/dim]\n")

        # Live dashboard
        state = ConnectionState(
            status="CONNECTED",
            location=loc_label,
            edge_ip=exit_ip,
            server_hostname=candidate.host,
            socks_port=socks_port,
            start_time=start_time,
            tun_mode=enable_tun,
        )

        try:
            while True:
                state.bytes_sent = bytes_sent
                state.bytes_received = bytes_received
                await asyncio.sleep(1.0)
        except asyncio.CancelledError:
            pass
        finally:
            console.print("\n[yellow]Disconnecting tunnel...[/yellow]")
            if enable_tun:
                tun_mgr.stop_tun()
            if enable_sys_proxy:
                proxy_mgr.disable_system_proxy()
            await socks_server.stop()
            await session.close()
            console.print("[green]✔ Disconnected cleanly.[/green]")

    try:
        asyncio.run(_run_foreground())
    except KeyboardInterrupt:
        console.print("\n[green]Tunnel closed by user.[/green]")
    except Exception as err:
        console.print(f"[bold red]Connection error:[/bold red] {err}")
        if enable_tun:
            tun_mgr.stop_tun()
        if enable_sys_proxy:
            proxy_mgr.disable_system_proxy()

    Prompt.ask("\nPress Enter to return to menu...")


def handle_choose_location() -> None:
    """Browse countries and connect."""
    server_client = ServerListClient()

    with console.status("[cyan]Loading available countries...[/cyan]"):
        try:
            countries = asyncio.run(server_client.fetch_countries())
        except Exception as err:
            console.print(f"[bold red]Failed to load locations:[/bold red] {err}")
            Prompt.ask("\nPress Enter to return to menu...")
            return

    table = Table(box=box.ROUNDED, title="[bold cyan]Select a Country to Connect[/bold cyan]")
    table.add_column("#", style="bold yellow", width=4, justify="center")
    table.add_column("Country Name", style="bold white")
    table.add_column("Code", style="cyan", justify="center")

    for idx, c in enumerate(countries, 1):
        table.add_row(str(idx), c.name, c.code)

    console.print(table)
    choice = Prompt.ask("\nEnter country number (#) or 2-letter Code (or 'b' to go back)").strip()

    if choice.lower() in ("b", "back", "q", "exit"):
        return

    selected_code = "REC"
    if choice.isdigit():
        num = int(choice)
        if 1 <= num <= len(countries):
            selected_code = countries[num - 1].code
    elif len(choice) == 2:
        selected_code = choice.upper()
    elif choice.upper() == "REC":
        selected_code = "REC"

    handle_connect(country_code=selected_code)


def handle_settings() -> None:
    """View and modify settings."""
    settings_store = SettingsStore()

    while True:
        settings = settings_store.load()
        console.print("\n[bold cyan]─── Settings & Preferences ───[/bold cyan]")

        table = Table(box=box.ROUNDED, show_header=True)
        table.add_column("#", style="bold yellow", width=4, justify="center")
        table.add_column("Setting", style="bold white")
        table.add_column("Current Value", style="cyan")
        table.add_column("Description", style="dim")

        table.add_row("1", "SOCKS5 Port", str(settings.socks_port), "Local proxy listening port (1-65535)")
        table.add_row("2", "SOCKS5 Bind IP", settings.socks_host, "Local bind address (default 127.0.0.1)")
        table.add_row("3", "DoH Provider", settings.doh_provider, "automatic, cloudflare, google, quad9, off")
        table.add_row("4", "Auto System Proxy", str(settings.system_proxy), "Automatically configure OS proxy on connect")
        table.add_row("5", "Exit Check", str(settings.exit_check), "Verify exit IP with Cloudflare on connect")
        table.add_row("6", "Default Country", settings.default_country, "Default country code (REC, US, DE, etc.)")
        table.add_row("7", "Reset All", "-", "Restore all settings to factory defaults")
        table.add_row("0", "Back", "-", "Return to main menu")

        console.print(table)
        opt = Prompt.ask("Choose an option to edit", default="0")

        if opt == "0" or opt.lower() in ("b", "back", "q"):
            break
        elif opt == "1":
            new_port = IntPrompt.ask("Enter new SOCKS5 port (1-65535)", default=settings.socks_port)
            if 1 <= new_port <= 65535:
                settings_store.set("socks_port", new_port)
                console.print(f"[green]✔ SOCKS port set to {new_port}.[/green]")
        elif opt == "2":
            new_bind = Prompt.ask("Enter SOCKS bind IP", default=settings.socks_host)
            settings_store.set("socks_host", new_bind.strip())
            console.print(f"[green]✔ Bind address set to {new_bind}.[/green]")
        elif opt == "3":
            new_doh = Prompt.ask(
                "Choose DoH provider",
                choices=["automatic", "cloudflare", "google", "quad9", "off"],
                default=settings.doh_provider,
            )
            settings_store.set("doh_provider", new_doh)
            console.print(f"[green]✔ DoH provider set to {new_doh}.[/green]")
        elif opt == "4":
            new_sys = Confirm.ask("Enable OS system proxy by default?", default=settings.system_proxy)
            settings_store.set("system_proxy", new_sys)
            console.print(f"[green]✔ Auto system proxy set to {new_sys}.[/green]")
        elif opt == "5":
            new_ec = Confirm.ask("Enable exit check verification by default?", default=settings.exit_check)
            settings_store.set("exit_check", new_ec)
            console.print(f"[green]✔ Exit check set to {new_ec}.[/green]")
        elif opt == "6":
            new_cc = Prompt.ask("Enter default country code", default=settings.default_country).upper()
            settings_store.set("default_country", new_cc)
            console.print(f"[green]✔ Default country set to {new_cc}.[/green]")
        elif opt == "7":
            if Confirm.ask("Are you sure you want to reset all settings to defaults?", default=False):
                save_settings(Settings())
                console.print("[green]✔ Settings restored to defaults.[/green]")


# ---------------------------------------------------------------------------
# MAIN MENU LOOP
# ---------------------------------------------------------------------------


def run_interactive_menu() -> None:
    """Run the main interactive menu loop."""
    while True:
        try:
            print_banner(console)
            _render_menu_panel()

            choice = Prompt.ask(
                "[bold cyan]Select an option[/bold cyan] [yellow][0-9][/yellow]",
                default="1",
            ).strip()

            if choice in ("0", "q", "quit", "exit"):
                console.print("\n[bold yellow]Thank you for using FoxyVPN. Goodbye! 🦊[/bold yellow]\n")
                break
            elif choice == "1":
                handle_connect()
            elif choice == "2":
                handle_choose_location()
            elif choice == "3":
                handle_disconnect()
                Prompt.ask("\nPress Enter to return to menu...")
            elif choice == "4":
                handle_status()
            elif choice == "5":
                handle_quota()
            elif choice == "6":
                handle_locations()
            elif choice == "7":
                handle_verify()
            elif choice == "8":
                handle_accounts_management()
            elif choice == "9":
                handle_settings()
            else:
                console.print(f"[red]Invalid option '{choice}'. Please select a number from 0 to 9.[/red]")
                time.sleep(1)

        except (KeyboardInterrupt, EOFError):
            console.print("\n\n[bold yellow]Exiting FoxyVPN menu. Goodbye! 🦊[/bold yellow]\n")
            break
        except Exception as err:
            console.print(f"\n[bold red]An unexpected error occurred:[/bold red] {err}")
            Prompt.ask("\nPress Enter to return to menu...")
