"""Fastly Challenge Solver for Mozilla accounts and Guardian endpoints."""

from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from typing import Any

import httpx

SOLVER_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)
POW_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
HTML_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

CHALLENGE_PREFIX_REGEX = re.compile(r"/_fs-ch-[A-Za-z0-9]+")
INIT_CALL_REGEX = re.compile(r'init\((\[[^\]]*\]),\s*"([^"]+)",\s*"([^"]+)"')
MAX_POST_BACK_ROUNDS = 3
SOLVE_TIMEOUT_SECONDS = 60.0


class FastlyChallengeError(Exception):
    """Raised when Fastly challenge cannot be resolved."""
    pass


class NoChallengePage(Exception):
    """Raised when the probed host does not serve a challenge page."""
    pass


def base_origin(prefix_url: str) -> str:
    idx = prefix_url.find("/_fs-ch-")
    return prefix_url[:idx] if idx > 0 else prefix_url


def solve_pow(base: str, target_hex: str) -> str | None:
    """Brute force a 2-character alphanumeric suffix matching target SHA-256."""
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
            digest = hashlib.sha256(base_bytes + suffix.encode("utf-8")).digest()
            if digest == target:
                return suffix
    return None


def client_metrics_answer() -> dict[str, Any]:
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


class FastlyChallengeSolver:
    """Solves Fastly proof-of-work / PAT / metrics challenge pages."""

    def __init__(self, cookies: httpx.Cookies | None = None) -> None:
        self.cookies = cookies if cookies is not None else httpx.Cookies()

    async def solve_and_install(self, client: httpx.AsyncClient | None = None) -> None:
        last_error: Exception | None = None
        created_client = False
        target_client = client

        if target_client is None:
            target_client = httpx.AsyncClient(
                cookies=self.cookies,
                timeout=SOLVE_TIMEOUT_SECONDS,
                follow_redirects=True,
                trust_env=False,
            )
            created_client = True

        try:
            for base in ["https://api.accounts.firefox.com", "https://accounts.firefox.com"]:
                try:
                    await self._solve_on_host(target_client, base)
                    if created_client:
                        # Copy cookies from target_client to self.cookies
                        self.cookies.update(target_client.cookies)
                    elif client is not None:
                        # Ensure solver cookies are synced with client cookies
                        client.cookies.update(target_client.cookies)
                    return
                except NoChallengePage:
                    continue
                except FastlyChallengeError as exc:
                    last_error = exc

            if last_error is not None:
                raise last_error
            raise FastlyChallengeError("host did not serve a Fastly challenge page")
        finally:
            if created_client:
                await target_client.aclose()

    async def _solve_on_host(self, client: httpx.AsyncClient, base: str) -> None:
        page_url = f"{base}/"
        headers = {
            "User-Agent": SOLVER_USER_AGENT,
            "Accept": HTML_ACCEPT,
        }
        resp = await client.get(page_url, headers=headers)
        body = resp.text

        is_challenge = "/_fs-ch-" in body and "Client Challenge" in body
        if not is_challenge:
            raise NoChallengePage()

        prefix_match = CHALLENGE_PREFIX_REGEX.search(body)
        if not prefix_match:
            raise FastlyChallengeError(f"challenge asset prefix not found on {base}")
        prefix_url = base + prefix_match.group(0)

        script_resp = await client.get(
            f"{prefix_url}/script.js?reload=true",
            headers={"User-Agent": SOLVER_USER_AGENT, "Accept": "*/*"},
        )
        if script_resp.status_code >= 400:
            raise FastlyChallengeError(f"failed to fetch challenge script: {script_resp.status_code}")

        challenges, token = self._parse_challenge_init(script_resp.text)

        for _ in range(MAX_POST_BACK_ROUNDS):
            answers: list[dict[str, Any]] = []
            for ch in challenges:
                ans = await self._answer_challenge(client, prefix_url, token, ch)
                answers.append(ans)

            post_body = {"token": token, "data": answers}
            post_headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": SOLVER_USER_AGENT,
                "Origin": base_origin(prefix_url),
            }
            post_resp = await client.post(
                f"{prefix_url}/fst-post-back",
                json=post_body,
                headers=post_headers,
            )
            if post_resp.status_code >= 400:
                raise FastlyChallengeError(f"challenge post-back returned HTTP {post_resp.status_code}")

            res_data = post_resp.json()
            if res_data.get("status") == "success":
                # Verify challenge is cleared
                chk = await client.get(page_url, headers=headers)
                still_challenged = "/_fs-ch-" in chk.text and "Client Challenge" in chk.text
                if still_challenged:
                    raise FastlyChallengeError("challenge cookie not accepted on this exit IP")
                return

            next_ch = res_data.get("ch")
            next_tok = res_data.get("tok", "")
            if not next_ch or not next_tok:
                raise FastlyChallengeError(f"unexpected post-back response: {res_data}")
            challenges = next_ch
            token = next_tok

        raise FastlyChallengeError(
            f"Fastly challenge did not complete within {MAX_POST_BACK_ROUNDS} rounds"
        )

    def _parse_challenge_init(self, script: str) -> tuple[list[dict[str, Any]], str]:
        matches = list(INIT_CALL_REGEX.finditer(script))
        if not matches:
            raise FastlyChallengeError("challenge init() call not found in script")
        last = matches[-1]
        try:
            challenges = json.loads(last.group(1))
        except Exception as exc:
            raise FastlyChallengeError(f"could not parse challenge list: {exc}") from exc
        if not challenges:
            raise FastlyChallengeError("empty challenge list")
        return challenges, last.group(2)

    async def _fetch_pat(self, client: httpx.AsyncClient, prefix_url: str, token: str) -> str:
        pat_url = f"{prefix_url}/pat?token={urllib.parse.quote(token)}"
        headers = {
            "Accept": "text/plain",
            "Content-Type": "application/json",
            "User-Agent": SOLVER_USER_AGENT,
            "Origin": base_origin(prefix_url),
        }
        resp = await client.post(pat_url, headers=headers)
        if resp.status_code in (400, 401):
            return ""
        if resp.status_code >= 400:
            raise FastlyChallengeError(f"PAT request returned HTTP {resp.status_code}")
        try:
            data = resp.json()
        except Exception as exc:
            raise FastlyChallengeError(f"could not parse PAT response: {exc}") from exc
        auth = data.get("auth", "")
        if not auth:
            raise FastlyChallengeError("empty PAT auth token")
        return auth

    async def _answer_challenge(
        self,
        client: httpx.AsyncClient,
        prefix_url: str,
        token: str,
        challenge: dict[str, Any],
    ) -> dict[str, Any]:
        ch_type = challenge.get("ty", "")
        data = challenge.get("data", {})

        if ch_type == "pow":
            base = data.get("base", "")
            target_hash = data.get("hash", "")
            ans = solve_pow(base, target_hash)
            if not ans:
                raise FastlyChallengeError(f"no proof-of-work solution found for base {base}")
            return {
                "ty": "pow",
                "base": base,
                "answer": ans,
                "hmac": data.get("hmac", ""),
                "expires": data.get("expires", ""),
            }
        elif ch_type == "pat":
            auth = await self._fetch_pat(client, prefix_url, token)
            return {
                "ty": "pat",
                "auth": auth,
            }
        elif ch_type == "clientmetrics":
            return client_metrics_answer()
        else:
            raise FastlyChallengeError(
                f"unsupported Fastly challenge type '{ch_type}' (captcha cannot be solved automatically)"
            )
