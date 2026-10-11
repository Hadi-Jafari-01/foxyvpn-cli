"""Browser-based authentication server for FoxyVPN.

Allows users to log in using a web browser on their local machine, remote laptop,
or mobile phone, even when FoxyVPN is running on a headless remote server over SSH.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import socket
import urllib.parse
import webbrowser
from typing import Any

from rich.console import Console

from foxyvpn.auth.fxa import FxaApiError, FxaAuthRepository
from foxyvpn.core.models import RuntimeAuth
from foxyvpn.core.store import TokenStore

logger = logging.getLogger("foxyvpn.auth.web_auth")
console = Console()

DEFAULT_WEB_AUTH_PORT = 8765


def get_local_ip() -> str:
    """Attempt to detect the primary local/outbound IP address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Does not actually establish a connection to 8.8.8.8
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


HTML_LOGIN_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>FoxyVPN - Firefox Accounts Login</title>
  <style>
    :root {
      --bg: #12121a;
      --card-bg: #1e1e2e;
      --text: #f0f0f5;
      --muted: #a0a0b8;
      --primary: #ff7139;
      --primary-hover: #ff8c5a;
      --accent: #8b5cf6;
      --border: #2e2e42;
      --error: #ef4444;
      --success: #10b981;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      padding: 1.5rem;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 2.5rem;
      width: 100%;
      max-width: 440px;
      box-shadow: 0 20px 40px rgba(0,0,0,0.4);
    }
    .logo {
      text-align: center;
      margin-bottom: 1.5rem;
      font-size: 3rem;
    }
    h1 {
      font-size: 1.5rem;
      font-weight: 700;
      text-align: center;
      margin-bottom: 0.5rem;
      background: linear-gradient(135deg, #ff7139, #a855f7);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    p.subtitle {
      color: var(--muted);
      text-align: center;
      font-size: 0.9rem;
      margin-bottom: 2rem;
    }
    .field {
      margin-bottom: 1.25rem;
    }
    label {
      display: block;
      font-size: 0.85rem;
      font-weight: 600;
      margin-bottom: 0.4rem;
      color: var(--text);
    }
    input {
      width: 100%;
      padding: 0.8rem 1rem;
      background: #141420;
      border: 1px solid var(--border);
      border-radius: 8px;
      color: #fff;
      font-size: 1rem;
      outline: none;
      transition: border-color 0.2s;
    }
    input:focus {
      border-color: var(--primary);
    }
    button {
      width: 100%;
      padding: 0.9rem;
      background: linear-gradient(135deg, var(--primary), var(--accent));
      color: #fff;
      border: none;
      border-radius: 8px;
      font-size: 1rem;
      font-weight: 600;
      cursor: pointer;
      margin-top: 0.5rem;
      transition: opacity 0.2s, transform 0.1s;
    }
    button:hover { opacity: 0.95; }
    button:active { transform: scale(0.99); }
    button:disabled { opacity: 0.5; cursor: not-allowed; }
    .status {
      margin-top: 1.25rem;
      padding: 0.8rem;
      border-radius: 8px;
      font-size: 0.9rem;
      text-align: center;
      display: none;
    }
    .status.error {
      background: rgba(239, 68, 68, 0.15);
      border: 1px solid var(--error);
      color: #fca5a5;
      display: block;
    }
    .status.success {
      background: rgba(16, 185, 129, 0.15);
      border: 1px solid var(--success);
      color: #6ee7b7;
      display: block;
    }
    .status.loading {
      background: rgba(139, 92, 246, 0.15);
      border: 1px solid var(--accent);
      color: #c4b5fd;
      display: block;
    }
    .hidden { display: none !important; }
    .footer {
      margin-top: 2rem;
      text-align: center;
      font-size: 0.8rem;
      color: var(--muted);
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">🦊</div>
    <h1>FoxyVPN Sign In</h1>
    <p class="subtitle">Authenticate with your Firefox Account</p>

    <div id="status-box" class="status"></div>

    <form id="login-form">
      <div id="credentials-step">
        <div class="field">
          <label for="email">Firefox Account Email</label>
          <input type="email" id="email" required placeholder="user@example.com" autocomplete="email">
        </div>
        <div class="field">
          <label for="password">Password</label>
          <input type="password" id="password" required placeholder="••••••••••••" autocomplete="current-password">
        </div>
        <button type="submit" id="btn-submit">Sign In to Firefox VPN</button>
      </div>

      <div id="twofactor-step" class="hidden">
        <div class="field">
          <label for="code">2-Factor Verification Code</label>
          <input type="text" id="code" placeholder="6-digit code" pattern="[0-9]*" inputmode="numeric" autocomplete="one-time-code">
        </div>
        <button type="button" id="btn-2fa">Verify & Complete Sign In</button>
      </div>
    </form>

    <div class="footer">
      Connected securely to local FoxyVPN CLI
    </div>
  </div>

  <script>
    const authKey = new URLSearchParams(window.location.search).get("key") || "";
    const form = document.getElementById("login-form");
    const credStep = document.getElementById("credentials-step");
    const twoFaStep = document.getElementById("twofactor-step");
    const statusBox = document.getElementById("status-box");
    const btnSubmit = document.getElementById("btn-submit");
    const btn2fa = document.getElementById("btn-2fa");
    let pendingSessionToken = null;

    function showStatus(text, type) {
      statusBox.textContent = text;
      statusBox.className = "status " + type;
    }

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const email = document.getElementById("email").value.trim();
      const password = document.getElementById("password").value;
      if (!email || !password) return;

      btnSubmit.disabled = true;
      showStatus("Signing in to Firefox Accounts...", "loading");

      try {
        const res = await fetch("/api/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, password, key: authKey })
        });
        const data = await res.json();

        if (data.needs_2fa) {
          pendingSessionToken = data.session_token;
          credStep.classList.add("hidden");
          twoFaStep.classList.remove("hidden");
          const isTotp = data.verification_method === "totp-2fa";
          const msg = isTotp
            ? "Enter the 6-digit code from your Authenticator app."
            : "📩 Mozilla sent a 6-digit confirmation code to your email (" + email + "). Please check your Inbox & Spam folder!";
          showStatus(msg, "loading");
          document.getElementById("code").focus();
        } else if (data.success) {
          showStatus("✔ Signed in successfully! You can close this tab now.", "success");
          credStep.classList.add("hidden");
        } else {
          showStatus(data.error || "Sign in failed. Please check credentials.", "error");
          btnSubmit.disabled = false;
        }
      } catch (err) {
        showStatus("Connection error: " + err.message, "error");
        btnSubmit.disabled = false;
      }
    });

    btn2fa.addEventListener("click", async () => {
      const code = document.getElementById("code").value.trim();
      if (!code || !pendingSessionToken) return;

      btn2fa.disabled = true;
      showStatus("Verifying 2FA code...", "loading");

      try {
        const res = await fetch("/api/2fa", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ session_token: pendingSessionToken, code, key: authKey })
        });
        const data = await res.json();
        if (data.success) {
          showStatus("✔ Verification complete! You can close this tab and return to terminal.", "success");
          twoFaStep.classList.add("hidden");
        } else {
          showStatus(data.error || "Invalid 2FA code. Please retry.", "error");
          btn2fa.disabled = false;
        }
      } catch (err) {
        showStatus("Connection error: " + err.message, "error");
        btn2fa.disabled = false;
      }
    });
  </script>
</body>
</html>
"""


class WebAuthServer:
    """Lightweight async HTTP authentication bridge."""

    def __init__(
        self,
        token_store: TokenStore | None = None,
        port: int = DEFAULT_WEB_AUTH_PORT,
        host: str = "0.0.0.0",
    ) -> None:
        self.token_store = token_store or TokenStore()
        self.fxa_repo = FxaAuthRepository(token_store=self.token_store)
        self.port = port
        self.host = host
        self.auth_key = secrets.token_hex(16)
        self.completed_event = asyncio.Event()
        self.authenticated_auth: RuntimeAuth | None = None
        self.server: asyncio.Server | None = None

    async def _handle_request(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            line = await reader.readline()
            if not line:
                writer.close()
                return

            req_line = line.decode("utf-8", errors="ignore").strip()
            parts = req_line.split()
            if len(parts) < 2:
                writer.close()
                return

            method, full_path = parts[0], parts[1]
            parsed_url = urllib.parse.urlparse(full_path)
            path = parsed_url.path
            query_params = urllib.parse.parse_qs(parsed_url.query)

            # Read headers
            content_length = 0
            while True:
                h_line = await reader.readline()
                if not h_line or h_line == b"\r\n" or h_line == b"\n":
                    break
                header_str = h_line.decode("utf-8", errors="ignore")
                if header_str.lower().startswith("content-length:"):
                    try:
                        content_length = int(header_str.split(":", 1)[1].strip())
                    except ValueError:
                        pass

            # Read body
            body_bytes = b""
            if content_length > 0:
                body_bytes = await reader.readexactly(content_length)

            # Route handling
            if method == "GET" and (path == "/" or path == "/login"):
                self._send_response(
                    writer, 200, "text/html; charset=utf-8", HTML_LOGIN_TEMPLATE.encode("utf-8")
                )
            elif method == "POST" and path == "/api/login":
                await self._handle_api_login(writer, body_bytes)
            elif method == "POST" and path == "/api/2fa":
                await self._handle_api_2fa(writer, body_bytes)
            else:
                self._send_response(writer, 404, "text/plain", b"Not Found")

        except Exception as err:
            logger.debug("Web auth request error: %s", err)
        finally:
            try:
                await writer.drain()
                writer.close()
            except Exception:
                pass

    def _send_response(
        self,
        writer: asyncio.StreamWriter,
        status_code: int,
        content_type: str,
        body: bytes,
    ) -> None:
        reason = "OK" if status_code == 200 else "Error"
        headers = [
            f"HTTP/1.1 {status_code} {reason}",
            f"Content-Type: {content_type}",
            f"Content-Length: {len(body)}",
            "Access-Control-Allow-Origin: *",
            "Connection: close",
            "\r\n",
        ]
        writer.write("\r\n".join(headers).encode("utf-8") + body)

    async def _handle_api_login(self, writer: asyncio.StreamWriter, body: bytes) -> None:
        try:
            data = json.loads(body.decode("utf-8"))
        except Exception:
            self._send_response(
                writer, 400, "application/json", json.dumps({"error": "Invalid JSON"}).encode()
            )
            return

        email = data.get("email", "").strip()
        password = data.get("password", "")

        try:
            async with self.fxa_repo:
                needs_2fa, result = await self.fxa_repo.login(email, password)
                if needs_2fa:
                    resp = {
                        "needs_2fa": True,
                        "session_token": str(result),
                        "verification_method": getattr(self.fxa_repo, "verification_method", "email-2fa"),
                    }
                    self._send_response(writer, 200, "application/json", json.dumps(resp).encode())
                elif isinstance(result, RuntimeAuth):
                    self.authenticated_auth = result
                    self.token_store.save_auth(result)
                    self.completed_event.set()
                    resp = {"success": True, "email": result.email}
                    self._send_response(writer, 200, "application/json", json.dumps(resp).encode())
                else:
                    session_token = str(result)
                    auth = await self.fxa_repo.fxa_credentials_oauth(session_token)
                    self.authenticated_auth = auth
                    self.token_store.save_auth(auth)
                    self.completed_event.set()
                    resp = {"success": True, "email": auth.email}
                    self._send_response(writer, 200, "application/json", json.dumps(resp).encode())
        except FxaApiError as err:
            self._send_response(
                writer, 400, "application/json", json.dumps({"error": err.message}).encode()
            )
        except Exception as err:
            self._send_response(
                writer, 500, "application/json", json.dumps({"error": str(err)}).encode()
            )

    async def _handle_api_2fa(self, writer: asyncio.StreamWriter, body: bytes) -> None:
        try:
            data = json.loads(body.decode("utf-8"))
        except Exception:
            self._send_response(
                writer, 400, "application/json", json.dumps({"error": "Invalid JSON"}).encode()
            )
            return

        session_token = data.get("session_token", "")
        code = data.get("code", "").strip()

        try:
            async with self.fxa_repo:
                auth = await self.fxa_repo.submit_2fa(session_token=session_token, code=code)
                self.authenticated_auth = auth
                self.token_store.save_auth(auth)
                self.completed_event.set()
                resp = {"success": True, "email": auth.email}
                self._send_response(writer, 200, "application/json", json.dumps(resp).encode())
        except Exception as err:
            self._send_response(
                writer, 400, "application/json", json.dumps({"error": str(err)}).encode()
            )

    async def start(self) -> str:
        """Start listening on the specified port and return accessible URLs."""
        # Try port fallback if port is in use
        for p in range(self.port, self.port + 10):
            try:
                self.server = await asyncio.start_server(
                    self._handle_request, self.host, p
                )
                self.port = p
                break
            except OSError:
                continue

        if not self.server:
            raise OSError(f"Could not bind web auth server on ports {self.port}-{self.port+9}")

        local_ip = get_local_ip()
        return f"http://{local_ip}:{self.port}/?key={self.auth_key}"

    async def wait_for_completion(self, timeout: float = 300.0) -> RuntimeAuth | None:
        """Wait until login completes via web browser or timeout expires."""
        try:
            await asyncio.wait_for(self.completed_event.wait(), timeout=timeout)
            return self.authenticated_auth
        except asyncio.TimeoutError:
            return None
        finally:
            await self.stop()

    async def stop(self) -> None:
        """Shut down the web auth server."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.server = None


def run_browser_login(
    port: int = DEFAULT_WEB_AUTH_PORT,
    timeout: float = 300.0,
    token_store: TokenStore | None = None,
) -> RuntimeAuth | None:
    """Launch the browser authentication server and wait for browser sign-in."""
    store = token_store or TokenStore()
    web_server = WebAuthServer(token_store=store, port=port)

    async def _runner():
        url = await web_server.start()
        local_url = f"http://localhost:{web_server.port}/?key={web_server.auth_key}"

        console.print("\n[bold cyan]🦊 Browser Authentication Started![/bold cyan]\n")
        console.print("[bold]Please open this URL in your web browser:[/bold]")
        console.print(f"  👉 [bold green]{local_url}[/bold green] (if on your local desktop)")
        console.print(f"  👉 [bold green]{url}[/bold green] (if connecting from remote PC/phone)\n")

        console.print("[dim]💡 Tip: If on a remote VPS behind a firewall, forward the port with:[/dim]")
        console.print(f"[dim]   ssh -L {web_server.port}:localhost:{web_server.port} user@your-server-ip[/dim]\n")

        # Try to open local browser automatically if graphical desktop exists
        try:
            webbrowser.open(local_url)
        except Exception:
            pass

        with console.status("[cyan]Waiting for authentication in browser... (Press Ctrl+C to cancel)[/cyan]"):
            auth = await web_server.wait_for_completion(timeout=timeout)
            return auth

    try:
        auth = asyncio.run(_runner())
        if auth:
            console.print(f"\n[bold green]✔ Successfully authenticated as {auth.email or 'Active User'} via browser![/bold green]\n")
        else:
            console.print("\n[yellow]Browser authentication timed out.[/yellow]\n")
        return auth
    except KeyboardInterrupt:
        console.print("\n[yellow]Browser authentication cancelled.[/yellow]\n")
        return None
