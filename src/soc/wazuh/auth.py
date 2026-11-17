"""Authenticate to the Wazuh manager API and get a JWT.

Run with:  python -m soc.wazuh.auth   (or `make wazuh-check`)
"""

from __future__ import annotations

import base64
import json
import ssl
import sys
import urllib.error
import urllib.request

from soc.checks import CheckResult, load_env

AUTH_PATH = "/security/user/authenticate"
TIMEOUT_S = 10


def basic_auth_header(user: str, password: str) -> str:
    """HTTP Basic auth: base64("user:password"). Encoding, NOT encryption -> needs TLS."""
    raw = f"{user}:{password}".encode()
    return "Basic " + base64.b64encode(raw).decode()


def token_from_response(payload: dict) -> str | None:
    """Wazuh wraps results as {"data": {"token": "..."}, "error": 0}."""
    return (payload.get("data") or {}).get("token")


def ssl_context(verify: bool) -> ssl.SSLContext:
    """The lab uses a self-signed CA, so verification is off unless configured.

    Phase 3 TODO: verify against the generated root CA instead of disabling checks.
    """
    if verify:
        return ssl.create_default_context()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def get_token(url: str, user: str, password: str, verify_tls: bool = False) -> str:
    req = urllib.request.Request(
        url.rstrip("/") + AUTH_PATH,
        method="POST",
        headers={"Authorization": basic_auth_header(user, password)},
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT_S, context=ssl_context(verify_tls)) as resp:
        token = token_from_response(json.load(resp))
    if not token:
        raise ValueError("API response had no token")
    return token


def check_wazuh_api(env: dict[str, str]) -> CheckResult:
    url = env.get("WAZUH_API_URL", "https://localhost:55000")
    user, password = env.get("WAZUH_API_USER"), env.get("WAZUH_API_PASSWORD")
    if not user or not password:
        return CheckResult("wazuh", False, "set WAZUH_API_USER / WAZUH_API_PASSWORD in .env")
    try:
        token = get_token(url, user, password, env.get("WAZUH_VERIFY_TLS") == "true")
    except urllib.error.HTTPError as exc:
        hint = "wrong credentials" if exc.code == 401 else "API still starting? retry in ~30s"
        return CheckResult("wazuh", False, f"{url} HTTP {exc.code} ({hint})")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return CheckResult("wazuh", False, f"{url} unreachable ({exc})")
    # A JWT is header.payload.signature; show only the start, never the whole token.
    return CheckResult("wazuh", True, f"{url} token issued ({token[:12]}..., {token.count('.') + 1} parts)")


def main() -> int:
    r = check_wazuh_api(load_env())
    print(f"[{'OK' if r.ok else 'FAIL':4}] {r.name:7} {r.detail}")
    return 0 if r.ok else 1


if __name__ == "__main__":
    sys.exit(main())
