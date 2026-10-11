"""Rich console UI components and terminal formatters for FoxyVPN.

Provides ASCII banner, quota usage progress bars, server location tables,
authentication/connection status tables, and live connection dashboard.
"""

from __future__ import annotations

import datetime
import time
from typing import Any

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from foxyvpn.core.models import (
    ConnectionState,
    Entitlement,
    ProxyCandidate,
    RuntimeAuth,
    VpnCountry,
)

BANNER_ART = r"""
  ______                 _    ______  _   _ 
 |  ____|               | |  |  ____|| \ | |
 | |__ ___  __  __ _   _| |  | |__   |  \| |
 |  __/ _ \ \ \/ /| | | | |  |  __|  | . ` |
 | | | (_) | >  < | |_| |_|  | |____ | |\  |
 |_|  \___/ /_/\_\ \__, (_)  |______||_| \_|
                    __/ |                   
                   |___/                    
"""

CLI_SUBTITLE = "Cross-Platform High-Performance Firefox VPN Client"
VERSION_STRING = "v1.0.0"


def format_bytes(num_bytes: int | float | None) -> str:
    """Format bytes into human-readable string (B, KB, MB, GB, TB)."""
    if num_bytes is None:
        return "N/A"
    try:
        n = float(num_bytes)
    except (ValueError, TypeError):
        return "N/A"

    if n < 0:
        return "0 B"
    for unit in ["B", "KB", "MB", "GB", "TB", "PB"]:
        if abs(n) < 1024.0 or unit == "PB":
            if unit == "B":
                return f"{int(n)} B"
            return f"{n:.2f} {unit}"
        n /= 1024.0
    return f"{n:.2f} PB"


def format_speed(bytes_per_sec: float | None) -> str:
    """Format transfer speed into bytes per second string."""
    if bytes_per_sec is None or bytes_per_sec < 0:
        return "0 B/s"
    return f"{format_bytes(bytes_per_sec)}/s"


def print_banner(console: Console | None = None) -> None:
    """Display stylized FoxyVPN ASCII art banner and application info."""
    c = console or Console()
    banner_text = Text(BANNER_ART, style="bold bright_yellow")
    subtitle = Text(f"{CLI_SUBTITLE}  •  {VERSION_STRING}\n", style="bold dark_orange")
    c.print(banner_text)
    c.print(subtitle)


def format_quota_bar(
    remaining_bytes: int | None,
    max_bytes: int | None,
    reset_epoch: int | None = None,
    console: Console | None = None,
) -> Panel:
    """Format bandwidth quota usage into a visual progress bar panel."""
    # Check for unlimited bandwidth
    if max_bytes is None or max_bytes <= 0:
        content = Text()
        content.append("Bandwidth Quota: ", style="bold")
        content.append("UNLIMITED", style="bold bright_green")
        content.append("  (No monthly usage caps apply)\n", style="dim")
        panel = Panel(
            content,
            title="[bold yellow]Bandwidth Quota[/bold yellow]",
            box=box.ROUNDED,
            border_style="green",
        )
        if console is not None:
            console.print(panel)
        return panel

    rem = max(0, remaining_bytes) if remaining_bytes is not None else 0
    total = max(1, max_bytes)
    used = max(0, total - rem)
    pct_used = min(100.0, (used / total) * 100.0)
    pct_rem = max(0.0, 100.0 - pct_used)

    # Determine status color
    if pct_used >= 90.0:
        bar_color = "red"
        status_style = "bold red"
    elif pct_used >= 70.0:
        bar_color = "yellow"
        status_style = "bold yellow"
    else:
        bar_color = "green"
        status_style = "bold green"

    # Construct ASCII progress bar (30 chars wide)
    bar_width = 30
    filled = int(round((pct_used / 100.0) * bar_width))
    unfilled = bar_width - filled
    bar_str = "█" * filled + "░" * unfilled

    lines = Text()
    lines.append(f"Usage: ", style="bold")
    lines.append(f"[{bar_str}] ", style=bar_color)
    lines.append(f"{pct_used:.1f}% used\n\n", style=status_style)

    lines.append("• Used:      ", style="dim")
    lines.append(f"{format_bytes(used)}\n", style="bold")
    lines.append("• Remaining: ", style="dim")
    lines.append(f"{format_bytes(rem)} ({pct_rem:.1f}%)\n", style="bold")
    lines.append("• Total Cap: ", style="dim")
    lines.append(f"{format_bytes(total)}\n", style="bold")

    if reset_epoch and reset_epoch > 0:
        now = time.time()
        if reset_epoch > now:
            diff = int(reset_epoch - now)
            days = diff // 86400
            hours = (diff % 86400) // 3600
            lines.append("• Resets In: ", style="dim")
            lines.append(f"{days}d {hours}h\n", style="cyan")
        else:
            reset_dt = datetime.datetime.fromtimestamp(reset_epoch, tz=datetime.timezone.utc)
            lines.append("• Reset Date:", style="dim")
            lines.append(f"{reset_dt.strftime('%Y-%m-%d %H:%M UTC')}\n", style="cyan")

    panel = Panel(
        lines,
        title="[bold yellow]Bandwidth Quota[/bold yellow]",
        box=box.ROUNDED,
        border_style=bar_color,
    )
    if console is not None:
        console.print(panel)
    return panel


def format_servers_table(
    countries: list[VpnCountry],
    pings: dict[str, float] | None = None,
    console: Console | None = None,
) -> Table:
    """Format VPN country and server location list into a Rich table."""
    table = Table(
        title="Available VPN Server Locations",
        box=box.ROUNDED,
        header_style="bold bright_cyan",
        title_style="bold bright_yellow",
    )
    table.add_column("#", style="dim", justify="right")
    table.add_column("Country", style="bold")
    table.add_column("Code", style="cyan", justify="center")
    table.add_column("Cities", justify="right")
    table.add_column("Servers", justify="right")
    table.add_column("Latency (ms)", justify="right")

    pings_map = pings or {}

    for idx, country in enumerate(countries, start=1):
        city_count = len(country.cities)
        server_count = sum(len(c.servers) for c in country.cities)

        # Determine ping for country code or individual hostnames
        latency_val: float | None = None
        if country.code in pings_map:
            latency_val = pings_map[country.code]
        else:
            # Check if any server host in this country has a ping recorded
            for city in country.cities:
                for srv in city.servers:
                    if srv.hostname in pings_map:
                        latency_val = pings_map[srv.hostname]
                        break
                if latency_val is not None:
                    break

        if latency_val is not None:
            if latency_val < 80.0:
                latency_str = f"[bold green]{latency_val:.1f}[/bold green]"
            elif latency_val < 160.0:
                latency_str = f"[bold yellow]{latency_val:.1f}[/bold yellow]"
            else:
                latency_str = f"[bold red]{latency_val:.1f}[/bold red]"
        else:
            latency_str = "[dim]--[/dim]"

        table.add_row(
            str(idx),
            country.name,
            country.code.upper(),
            str(city_count),
            str(server_count),
            latency_str,
        )

    if console is not None:
        console.print(table)
    return table


def format_status_table(
    auth: RuntimeAuth | None = None,
    entitlement: Entitlement | None = None,
    state: ConnectionState | None = None,
    console: Console | None = None,
) -> Table:
    """Format full CLI session status into a categorized Rich table."""
    table = Table(
        title="FoxyVPN System & Connection Status",
        box=box.ROUNDED,
        header_style="bold bright_yellow",
        title_style="bold bright_cyan",
    )
    table.add_column("Section", style="bold magenta", width=16)
    table.add_column("Property", style="bold", width=22)
    table.add_column("Status / Value")

    # 1. Authentication section
    if auth and auth.access_token:
        email = auth.email or "Active User"
        now = time.time()
        exp = auth.expires_at_epoch_seconds
        if exp > now:
            rem_m = int((exp - now) // 60)
            token_status = f"[green]Valid[/green] (expires in {rem_m} min)"
        else:
            token_status = "[red]Expired[/red]"
        table.add_row("Authentication", "Account", f"[cyan]{email}[/cyan]")
        table.add_row("Authentication", "Session Token", token_status)
    else:
        table.add_row("Authentication", "Account", "[dim]Not logged in[/dim]")
        table.add_row("Authentication", "Session Token", "[dim]None[/dim]")

    # 2. Entitlement section
    if entitlement:
        sub_status = (
            "[bold green]Subscribed[/bold green]"
            if entitlement.subscribed
            else "[yellow]Free Tier[/yellow]"
        )
        table.add_row("Entitlement", "Subscription", sub_status)
        if entitlement.limited_bandwidth:
            max_b = entitlement.max_bytes
            rem_b = entitlement.quota_remaining
            bw_val = f"Limited ({format_bytes(rem_b)} / {format_bytes(max_b)})"
        else:
            bw_val = "[bold green]Unlimited[/bold green]"
        table.add_row("Entitlement", "Bandwidth", bw_val)
    else:
        table.add_row("Entitlement", "Subscription", "[dim]Unknown[/dim]")

    # 3. Connection section
    conn_status = state.status.upper() if state and state.status else "DISCONNECTED"
    if conn_status == "CONNECTED":
        status_styled = "[bold green]CONNECTED[/bold green]"
    elif conn_status == "CONNECTING":
        status_styled = "[bold yellow]CONNECTING...[/bold yellow]"
    else:
        status_styled = "[dim]DISCONNECTED[/dim]"

    table.add_row("VPN Connection", "Status", status_styled)
    if state and conn_status == "CONNECTED":
        mode_styled = "[bold green]Virtual TUN Adapter (Full System)[/bold green]" if state.tun_mode else "[cyan]System Proxy / SOCKS5[/cyan]"
        table.add_row("VPN Connection", "Routing Mode", mode_styled)
        table.add_row("VPN Connection", "Location", f"[bold cyan]{state.location or 'Auto'}[/bold cyan]")
        table.add_row("VPN Connection", "Server", f"{state.server_hostname or 'N/A'}")
        table.add_row("VPN Connection", "Exit Egress IP", f"[bold green]{state.edge_ip or 'Verified'}[/bold green]")
        table.add_row("VPN Connection", "Local SOCKS5", f"127.0.0.1:{state.socks_port}")
        table.add_row(
            "VPN Connection",
            "Traffic",
            f"↑ {format_bytes(state.bytes_sent)}  |  ↓ {format_bytes(state.bytes_received)}",
        )
        if state.start_time and state.start_time > 0:
            uptime = max(0, int(time.time() - state.start_time))
            m = uptime // 60
            s = uptime % 60
            table.add_row("VPN Connection", "Uptime", f"{m}m {s}s")

    if console is not None:
        console.print(table)
    return table


def render_dashboard(
    candidate: ProxyCandidate | None = None,
    state: ConnectionState | None = None,
    speed_down: float = 0.0,
    speed_up: float = 0.0,
    system_proxy_active: bool = False,
) -> Panel:
    """Render a live connection dashboard panel suitable for rich.live.Live."""
    conn_state = state or ConnectionState(status="CONNECTED")
    location = (
        f"{candidate.country_name} ({candidate.country_code})"
        if candidate and candidate.country_name
        else (conn_state.location or "Active Node")
    )
    server_host = candidate.host if candidate else (conn_state.server_hostname or "gateway")
    exit_ip = conn_state.edge_ip or "Active"
    socks_addr = f"127.0.0.1:{conn_state.socks_port}"

    grid = Table.grid(expand=True)
    grid.add_column(ratio=1)
    grid.add_column(ratio=1)

    left_text = Text()
    left_text.append("Connection Details\n", style="bold bright_cyan underline")
    left_text.append("• Location:       ", style="dim")
    left_text.append(f"{location}\n", style="bold")
    left_text.append("• Upstream Host:  ", style="dim")
    left_text.append(f"{server_host}\n", style="bold")
    left_text.append("• Exit Node IP:   ", style="dim")
    left_text.append(f"{exit_ip}\n", style="bold bright_green")
    left_text.append("• Local SOCKS5:   ", style="dim")
    left_text.append(f"{socks_addr}\n", style="bold bright_yellow")
    left_text.append("• System Proxy:   ", style="dim")
    sys_proxy_style = "bold green" if system_proxy_active else "dim"
    left_text.append(f"{'ENABLED' if system_proxy_active else 'DISABLED'}\n", style=sys_proxy_style)

    right_text = Text()
    right_text.append("Live Traffic & Speeds\n", style="bold bright_yellow underline")
    right_text.append("• Download Speed: ", style="dim")
    right_text.append(f"{format_speed(speed_down)}\n", style="bold bright_green")
    right_text.append("• Upload Speed:   ", style="dim")
    right_text.append(f"{format_speed(speed_up)}\n", style="bold bright_cyan")
    right_text.append("• Total Received: ", style="dim")
    right_text.append(f"{format_bytes(conn_state.bytes_received)}\n", style="bold")
    right_text.append("• Total Sent:     ", style="dim")
    right_text.append(f"{format_bytes(conn_state.bytes_sent)}\n", style="bold")

    uptime_str = "--"
    if conn_state.start_time and conn_state.start_time > 0:
        elapsed = max(0, int(time.time() - conn_state.start_time))
        h = elapsed // 3600
        m = (elapsed % 3600) // 60
        s = elapsed % 60
        uptime_str = f"{h}h {m}m {s}s" if h > 0 else f"{m}m {s}s"

    right_text.append("• Session Uptime: ", style="dim")
    right_text.append(f"{uptime_str}\n", style="bold")

    grid.add_row(left_text, right_text)

    footer = Text("\n[Press Ctrl+C to disconnect]", style="italic dim center")
    content = Group(grid, footer)

    return Panel(
        content,
        title="[bold bright_yellow]FoxyVPN Live Dashboard[/bold bright_yellow]",
        box=box.ROUNDED,
        border_style="bright_yellow",
    )
