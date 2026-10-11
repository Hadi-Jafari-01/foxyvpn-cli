# FoxyVPN CLI 🦊

A high-performance, cross-platform Command Line Interface (CLI) client for **Mozilla Firefox VPN**, built to run natively on **Linux**, **macOS**, and **Windows**.

FoxyVPN CLI signs into Firefox Accounts (FxA), obtains a proxy pass from Mozilla's Guardian service, and carries network traffic through Firefox VPN's Fastly edge over an **HTTP/2 multiplexed tunnel**, exposing a local high-concurrency SOCKS5 proxy server with optional automatic OS-level system proxy configuration.

---

## ✨ Features

- **Cross-Platform**: First-class support for **Linux** (GNOME / CLI), **macOS** (`networksetup`), and **Windows** (WinINet / Registry).
- **Firefox Accounts (FxA) Sign-In**:
  - Full cryptographic PICL v1 key derivation (PBKDF2-HMAC-SHA256, HKDF-SHA256, Hawk HTTP authorization).
  - Built-in **Fastly Anti-Bot Challenge Solver** (Proof-of-Work SHA-256 brute force, PAT tokens, clientmetrics).
  - Two-Factor Authentication (2FA) support.
  - Automatic OAuth token refresh and session persistence.
- **Mozilla Guardian Integration**:
  - Automatically fetches and refreshes JWT ProxyPass tokens.
  - Bandwidth quota inspection and monthly reset tracking.
- **Mozilla Remote Settings Server Topology**:
  - Live discovery of countries, cities, and server nodes.
  - Multi-threaded concurrent TCP ping latency measurement (`foxyvpn locations --ping`).
- **High-Performance HTTP/2 Upstream Tunnel**:
  - Full HTTP/2 stream multiplexing with pure-Python `h2` protocol engine.
  - TLS ALPN `h2` negotiation.
  - Dynamic 16MB flow-control window update management.
  - Automatic PING keepalive watchdog.
  - Seamless in-flight JWT proxy pass rotation without dropping connections.
  - Upstream proxy chaining support (SOCKS5 / HTTP CONNECT).
- **Local RFC 1928 SOCKS5 Server**:
  - High-concurrency async bi-directional I/O relay.
  - IPv4, IPv6, and Domain name address resolution.
- **Private Encrypted DNS (DNS-over-HTTPS)**:
  - DoH resolver with automatic fallback across Cloudflare (`1.1.1.1`), Google (`8.8.8.8`), and Quad9 (`9.9.9.9`).
- **OS System Proxy Integration**:
  - Automatically configures and restores operating system proxy settings.
  - Provides shell export snippets for headless terminals (`ALL_PROXY`, `http_proxy`).
- **Exit Geolocation & Verification**:
  - Validates exit IP and ISO country code via Cloudflare trace (`/cdn-cgi/trace`).
- **Full-System L3 Virtual TUN Adapter**:
  - Wintun (Windows), `/dev/net/tun` (Linux), and `utun` (macOS) virtual network interface.
  - Automatically routes 100% of system traffic (TCP/UDP/ICMP/DNS) including terminal, games, and ping.
- **Daemon & Interactive Modes**:
  - Rich live dashboard with real-time transfer speeds and traffic counters.
  - Detached background daemon mode (`foxyvpn connect -d`).
- **Proxy Pool & Load Balancing Friendly**:
  - Ready for 9router, HAProxy, and custom proxy pools across multiple countries and ports.

---

## 🚀 Installation

### Option 1: Using `uv` (Recommended - Blazing Fast)
```bash
# Clone the repository
cd foxyvpn-cli

# Run directly without installation
uv run foxyvpn --help

# Or install as a tool
uv tool install .
```

### Option 2: Using standard `pip`
```bash
cd foxyvpn-cli
pip install .
```

### Option 3: Using `pipx`
```bash
pipx install .
```

---

## 📖 Quick Start

### 🎮 Interactive Menu Mode (Recommended - No commands to memorize!)
Simply run `foxyvpn` with no arguments, or `foxyvpn menu`:

```bash
uv run foxyvpn
# or:
foxyvpn menu
```

This launches the intuitive interactive dashboard where you can easily navigate between options using numbers:
```text
╭───────────────────────── Current Status ─────────────────────────╮
│  Account:      ● user@example.com                                │
│  VPN Tunnel:   ● CONNECTED (US | SOCKS: 127.0.0.1:10808)         │
│  System Proxy: ON                                                │
╰──────────────────────────────────────────────────────────────────╯
╭──────────────────────── FoxyVPN Main Menu ───────────────────────╮
│  [1]  ⚡  Quick Connect             (Auto-select lowest latency)  │
│  [2]  🌍  Choose Location & Connect (Browse 30+ countries)        │
│  [3]  🛑  Disconnect VPN            (Stop & restore system proxy)│
│  [4]  📊  Connection Status         (View active tunnel details) │
│  [5]  📦  Bandwidth Quota           (Monthly 50 GB allowance)    │
│  [6]  🏓  Server Locations & Pings  (List countries with pings)  │
│  [7]  🔍  Verify Exit IP & Location (Cloudflare trace check)     │
│  [8]  🔑  Account & Login           (Login, logout, switch user) │
│  [9]  ⚙️  Settings & Configuration  (Port, DoH, OS proxy toggle) │
│  [0]  🚪  Exit                                                   │
╰──────────────────────────────────────────────────────────────────╯
```

---

### 💻 Direct Command Line Usage (For Scripts / Advanced Users)

### 1. Sign In (Browser or Terminal)
```bash
# 🌐 Option A: Browser Login (Recommended - works locally or remotely over SSH)
foxyvpn login --browser
# Opens local browser automatically or gives a web link: http://<server-ip>:8765/

# 💻 Option B: Terminal Direct Login
foxyvpn login --email user@example.com --password "secret"

# 📋 Option C: One-Line Token Import from another machine
foxyvpn login --token <exported_token_string>
```

### 2. Multi-Account Management
```bash
# View all saved accounts
foxyvpn accounts

# Quick-switch to another account (using its 50 GB allowance)
foxyvpn switch user2@gmail.com

# Export current session token to transfer to a remote VPS
foxyvpn token export

# Import on the remote VPS
foxyvpn token import <string>
```

### 3. View Server Locations & Pings
```bash
# List all 30+ countries
foxyvpn locations

# List with live latency ping probes
foxyvpn locations --ping
```

### 3. Connect to VPN
```bash
# Connect to recommended location (auto-selected lowest latency)
foxyvpn connect

# Connect to a specific country (e.g. United States or Germany)
foxyvpn connect --country US
foxyvpn connect --country DE

# Connect and enable Full-System Virtual TUN Adapter (requires Admin/sudo)
foxyvpn connect --country US --tun

# Connect and automatically enable OS system proxy
foxyvpn connect --country US --system-proxy

# Run in background daemon mode
foxyvpn connect --country US --daemon

# Multi-Instance Proxy Pool for 9router / HAProxy
foxyvpn connect --country US --port 10801 --bind 0.0.0.0 --daemon
foxyvpn connect --country DE --port 10802 --bind 0.0.0.0 --daemon
foxyvpn connect --country SE --port 10803 --bind 0.0.0.0 --daemon
```

### 4. Check Status & Quota
```bash
# View account, subscription, and active connection status
foxyvpn status

# View monthly bandwidth quota usage
foxyvpn quota
```

### 5. Verify Exit IP & Country
```bash
foxyvpn verify
```

### 6. Disconnect
```bash
foxyvpn disconnect
```

---

## ⚙️ Configuration

View or update local configuration settings:

```bash
# View all settings
foxyvpn config show

# Change default SOCKS5 port
foxyvpn config set socks_port 10808

# Change default country
foxyvpn config set default_country US

# Configure DoH provider (automatic, cloudflare, google, quad9, off)
foxyvpn config set doh_provider cloudflare
```

### Config Directory Locations
- **Linux**: `~/.config/foxyvpn/`
- **macOS**: `~/Library/Application Support/foxyvpn/`
- **Windows**: `%APPDATA%\foxyvpn\`

---

## 🐧 Linux Terminal Proxy Exports

If you prefer using environment variables in terminal sessions rather than OS-wide proxy:

```bash
export ALL_PROXY=socks5://127.0.0.1:10808
export http_proxy=http://127.0.0.1:10808
export https_proxy=http://127.0.0.1:10808
```

---

## 🧪 Testing

The test suite includes 208 comprehensive unit and integration tests covering cryptography, Hawk auth, Fastly challenge solving, Guardian API, HTTP/2 multiplexing, SOCKS5 relay, DoH, TUN interface routing, and system proxy controllers.

```bash
uv run pytest -v
```

---

## 📜 License

MIT License.
