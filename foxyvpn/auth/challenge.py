"""Fastly Anti-Bot Challenge Solver for Firefox Accounts.

Solves HTTP 406 Fastly bot detection challenges (PoW, PAT, ClientMetrics)
on api.accounts.firefox.com and accounts.firefox.com.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from typing import Any

import httpx

SOLVE_TIMEOUT_SECONDS = 60.0
MAX_POST_BACK_ROUNDS = 3
SOLVER_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)
POW_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
HTML_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

CHALLENGE_PREFIX_REGEX = re.compile(r"/_fs-ch-[A-Za-z0-9]+")
INIT_CALL_REGEX = re.compile(r"init\((\[[^\]]*\]),\s*\"([^\"]+)\",\s*\"([^\"]+)\"")


class FastlyChallengeError(Exception):
    """Raised when Fastly challenge solving fails."""


class _NoChallengePage(Exception):
    """Internal exception when a host does not serve a challenge page."""


def solve_pow(base: str, target_hex: str) -> str | None:
    """Solve Fastly proof-of-work challenge.

    Brute-force a 2-character suffix from POW_ALPHABET such that
    SHA-256(base + suffix) matches target_hex.

    Args:
        base: The challenge base string.
        target_hex: Target SHA-256 hash in hex format (64 chars / 32 bytes).

    Returns:
        The 2-character suffix if found, otherwise None.
    """
    try:
        target = bytes.fromhex(target_hex)
    except Exception:
        return None

    if len(target) != 32:
        return None

    base_bytes = base.encode("utf-8")
    for a in POW_ALPHABET:
        for b in POW_ALPHABET:
            suffix = a + b
            if hashlib.sha256(base_bytes + suffix.encode("utf-8")).digest() == target:
                return suffix
    return None


def base_origin(prefix_url: str) -> str:
    """Extract origin from prefix URL before /_fs-ch-."""
    idx = prefix_url.find("/_fs-ch-")
    return prefix_url[:idx] if idx > 0 else prefix_url


def client_metrics_answer() -> dict[str, Any]:
    """Generate clientmetrics answer object."""
    return {
        "ty": "clientmetrics",
        "webdriver": False,
        "bot_detection_result": {
            "bot_detected": False,
            "bot_kind": None,
        },
        "browser_metrics": {
            "client_data": "{}",
            "error_trace": None,
        },
        "detector_results": {},
        "v": 2,
    }


def parse_challenge_init(script: str) -> tuple[list[dict[str, Any]], str]:
    """Parse challenge list and token from Fastly challenge script."""
    matches = list(INIT_CALL_REGEX.finditer(script))
    if not matches:
        raise FastlyChallengeError("challenge init() call not found in script")
    last = matches[-1]
    try:
        challenges = json.loads(last.group(1))
    except Exception as e:
        raise FastlyChallengeError(f"could not parse challenge list: {e}") from e
    if not challenges:
        raise FastlyChallengeError("empty challenge list")
    token = last.group(2)
    return challenges, token


class FastlyChallengeSolver:
    """Solves Fastly anti-bot challenge pages and retains session cookies."""

    def __init__(self, cookies: httpx.Cookies | None = None) -> None:
        self.cookies = cookies if cookies is not None else httpx.Cookies()

    @staticmethod
    def solve_pow(base: str, target_hex: str) -> str | None:
        return solve_pow(base, target_hex)

    @staticmethod
    def client_metrics_answer() -> dict[str, Any]:
        return client_metrics_answer()

    async def fetch_text(
        self,
        client: httpx.AsyncClient,
        url: str,
        accept: str = HTML_ACCEPT,
    ) -> str:
        headers = {
            "User-Agent": SOLVER_USER_AGENT,
            "Accept": accept,
        }
        response = await client.get(url, headers=headers)
        if response.is_error and response.status_code != 406:
            raise FastlyChallengeError(f"GET {url} returned HTTP {response.status_code}")
        return response.text

    async def fetch_challenge_page(
        self,
        client: httpx.AsyncClient,
        page_url: str,
    ) -> tuple[str, bool]:
        body = await self.fetch_text(client, page_url, HTML_ACCEPT)
        is_challenge = ("/_fs-ch-" in body) and (
            "Client Challenge" in body or "/script.js" in body or "fst-post-back" in body
        )
        return body, is_challenge

    async def fetch_pat(
        self,
        client: httpx.AsyncClient,
        prefix_url: str,
        token: str,
    ) -> str:
        pat_url = f"{prefix_url}/pat?token={urllib.parse.quote(token)}"
        headers = {
            "Accept": "text/plain",
            "Content-Type": "application/json",
            "User-Agent": SOLVER_USER_AGENT,
            "Origin": base_origin(prefix_url),
        }
        response = await client.post(pat_url, headers=headers, content=b"")
        if response.status_code in (400, 401):
            return ""
        if response.is_error:
            raise FastlyChallengeError(f"PAT request returned HTTP {response.status_code}")
        try:
            data = response.json()
        except Exception as e:
            raise FastlyChallengeError(f"could not parse PAT response: {e}") from e
        auth = data.get("auth", "")
        if not auth:
            raise FastlyChallengeError("empty PAT auth token")
        return auth

    async def answer_challenge(
        self,
        client: httpx.AsyncClient,
        prefix_url: str,
        token: str,
        challenge: dict[str, Any],
    ) -> dict[str, Any]:
        c_type = challenge.get("ty")
        data = challenge.get("data") or {}
        if c_type == "pow":
            base = data.get("base", "")
            target_hash = data.get("hash", "")
            answer = solve_pow(base, target_hash)
            if answer is None:
                raise FastlyChallengeError(f"no proof-of-work solution found for base {base}")
            return {
                "ty": "pow",
                "base": base,
                "answer": answer,
                "hmac": data.get("hmac", ""),
                "expires": data.get("expires", ""),
            }
        elif c_type == "pat":
            auth = await self.fetch_pat(client, prefix_url, token)
            return {
                "ty": "pat",
                "auth": auth,
            }
        elif c_type == "clientmetrics":
            return client_metrics_answer()
        else:
            raise FastlyChallengeError(
                f"unsupported Fastly challenge type '{c_type}' (captcha cannot be solved automatically)"
            )

    def _install_challenge_cookies(
        self,
        solver: httpx.AsyncClient,
        target_client: httpx.AsyncClient | None = None,
    ) -> None:
        cookies_found = list(solver.cookies.jar)
        if not cookies_found:
            raise FastlyChallengeError("challenge completed but no cookies were issued")
        for cookie in cookies_found:
            domain = cookie.domain or ".firefox.com"
            path = cookie.path or "/"
            self.cookies.set(cookie.name, cookie.value, domain=domain, path=path)
            if target_client is not None and target_client is not solver:
                target_client.cookies.set(cookie.name, cookie.value, domain=domain, path=path)

    async def solve_on_host(
        self,
        base: str,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        should_close = False
        if client is not None:
            solver = client
        else:
            solver = httpx.AsyncClient(
                cookies=self.cookies,
                timeout=SOLVE_TIMEOUT_SECONDS,
                follow_redirects=True,
                trust_env=False,
            )
            should_close = True

        try:
            page_url = f"{base}/"
            page, is_challenge = await self.fetch_challenge_page(solver, page_url)
            if not is_challenge:
                raise _NoChallengePage()

            prefix_match = CHALLENGE_PREFIX_REGEX.search(page)
            if not prefix_match:
                raise FastlyChallengeError(f"challenge asset prefix not found on {base}")
            prefix_url = f"{base}{prefix_match.group(0)}"

            script = await self.fetch_text(
                solver,
                f"{prefix_url}/script.js?reload=true",
                accept="*/*",
            )
            challenges, token = parse_challenge_init(script)

            for _ in range(MAX_POST_BACK_ROUNDS):
                answers = []
                for ch in challenges:
                    ans = await self.answer_challenge(solver, prefix_url, token, ch)
                    answers.append(ans)

                post_body = {
                    "token": token,
                    "data": answers,
                }
                post_headers = {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": SOLVER_USER_AGENT,
                    "Origin": base_origin(prefix_url),
                }
                response = await solver.post(
                    f"{prefix_url}/fst-post-back",
                    headers=post_headers,
                    json=post_body,
                )
                if response.is_error:
                    raise FastlyChallengeError(
                        f"challenge post-back returned HTTP {response.status_code}"
                    )
                try:
                    body = response.json()
                except Exception as e:
                    raise FastlyChallengeError(
                        f"could not parse post-back JSON response: {e}"
                    ) from e

                if body.get("status") == "success":
                    _, still_challenged = await self.fetch_challenge_page(solver, page_url)
                    if still_challenged:
                        raise FastlyChallengeError("challenge cookie not accepted on this exit IP")
                    self._install_challenge_cookies(solver, client)
                    return

                next_challenges = body.get("ch")
                next_token = body.get("tok", "")
                if not next_challenges or not next_token:
                    raise FastlyChallengeError(f"unexpected post-back response: {body}")
                challenges = next_challenges
                token = next_token

            raise FastlyChallengeError(
                f"Fastly challenge did not complete within {MAX_POST_BACK_ROUNDS} rounds"
            )
        finally:
            if should_close:
                await solver.aclose()

    async def solve_and_install(
        self,
        client: httpx.AsyncClient | None = None,
        bases: list[str] | None = None,
    ) -> dict[str, str]:
        """Solve challenge on Firefox Accounts domains and install cookies.

        Args:
            client: Optional httpx.AsyncClient to use and install cookies into.
            bases: Optional list of base URLs to probe.

        Returns:
            Dictionary of session cookie name-value pairs.
        """
        target_bases = bases or [
            "https://api.accounts.firefox.com",
            "https://accounts.firefox.com",
        ]
        last_error: Exception | None = None
        for base in target_bases:
            try:
                await self.solve_on_host(base, client)
                return {c.name: c.value for c in self.cookies.jar}
            except _NoChallengePage:
                continue
            except FastlyChallengeError as e:
                last_error = e

        raise last_error or FastlyChallengeError("host did not serve a Fastly challenge page")
