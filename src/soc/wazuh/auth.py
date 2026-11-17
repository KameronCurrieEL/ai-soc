"""Authenticate to the Wazuh manager API and get a JWT.

Run with:  python -m soc.wazuh.auth   (or `make wazuh-check`)
"""

from __future__ import annotations

import ssl
import sys
import urllib.error

from soc.checks import CheckResult, load_env
from soc.wazuh.client import TlsConfig, basic_auth_header, request_json, tls_from_env

AUTH_PATH = "/security/user/authenticate"


def token_from_response(payload: dict) -> str | None:
    """Wazuh wraps results as {"data": {"token": "..."}, "error": 0}."""
    return (payload.get("data") or {}).get("token")


def get_token(url: str, user: str, password: str, tls: TlsConfig = TlsConfig()) -> str:
    payload = request_json(
        url.rstrip("/") + AUTH_PATH,
        method="POST",
        headers={"Authorization": basic_auth_header(user, password)},
        tls=tls,
    )
    token = token_from_response(payload)
    if not token:
        raise ValueError("API response had no token")
    return token


def check_wazuh_api(env: dict[str, str]) -> CheckResult:
    url = env.get("WAZUH_API_URL", "https://localhost:55000")
    user, password = env.get("WAZUH_API_USER"), env.get("WAZUH_API_PASSWORD")
    if not user or not password:
        return CheckResult("wazuh", False, "set WAZUH_API_USER / WAZUH_API_PASSWORD in .env")
    try:
        token = get_token(url, user, password, tls_from_env(env, "WAZUH_API"))
    except urllib.error.HTTPError as exc:
        hint = "wrong credentials" if exc.code == 401 else "API still starting? retry in ~30s"
        return CheckResult("wazuh", False, f"{url} HTTP {exc.code} ({hint})")
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, ssl.SSLCertVerificationError):
            return CheckResult("wazuh", False, f"{url} TLS certificate rejected ({exc.reason.verify_message})")
        return CheckResult("wazuh", False, f"{url} unreachable ({exc})")
    except (OSError, ValueError) as exc:
        return CheckResult("wazuh", False, f"{url} unreachable ({exc})")
    # A JWT is header.payload.signature; show only the start, never the whole token.
    return CheckResult("wazuh", True, f"{url} token issued ({token[:12]}..., {token.count('.') + 1} parts)")


def main() -> int:
    r = check_wazuh_api(load_env())
    print(f"[{'OK' if r.ok else 'FAIL':4}] {r.name:7} {r.detail}")
    return 0 if r.ok else 1


if __name__ == "__main__":
    sys.exit(main())
