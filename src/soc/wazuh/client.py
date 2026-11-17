"""Shared HTTPS + JSON helper for the Wazuh manager API and the indexer.

One place for TLS settings, timeouts and JSON encoding, so the API modules
only describe *what* to ask for, not *how* to send it.
"""

from __future__ import annotations

import base64
import json
import ssl
import urllib.request

TIMEOUT_S = 10


def basic_auth_header(user: str, password: str) -> str:
    """HTTP Basic auth: base64("user:password"). Encoding, NOT encryption -> needs TLS."""
    raw = f"{user}:{password}".encode()
    return "Basic " + base64.b64encode(raw).decode()


def ssl_context(verify: bool) -> ssl.SSLContext:
    """The lab uses a self-signed CA, so verification is off unless configured.

    TODO (end of Phase 3): verify against the generated root CA instead of disabling checks.
    """
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def request_json(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: dict | None = None,
    verify_tls: bool = False,
) -> dict:
    """Send one HTTPS request and return the decoded JSON response.

    Raises urllib.error.HTTPError / URLError on failure; callers decide how to report it.
    """
    all_headers = dict(headers or {})
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        all_headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=all_headers)
    with urllib.request.urlopen(req, timeout=TIMEOUT_S, context=ssl_context(verify_tls)) as resp:
        return json.load(resp)
