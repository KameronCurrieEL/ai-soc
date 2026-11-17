"""Shared HTTPS + JSON helper for the Wazuh manager API and the indexer.

One place for TLS settings, timeouts and JSON encoding, so the API modules
only describe *what* to ask for, not *how* to send it.
"""

from __future__ import annotations

import base64
import json
import ssl
import urllib.request
from dataclasses import dataclass

TIMEOUT_S = 10


@dataclass(frozen=True)
class TlsConfig:
    """How to check the server's certificate.

    verify:      False = accept any certificate (lab fallback, vulnerable to MITM).
    ca_file:     PEM file of the CA (or the pinned self-signed cert) we trust.
    server_name: name the certificate must carry, if different from the URL host
                 (e.g. connect to localhost, but the cert says "wazuh.indexer").
    """

    verify: bool = False
    ca_file: str | None = None
    server_name: str | None = None


def tls_from_env(env: dict[str, str], prefix: str) -> TlsConfig:
    """Read e.g. WAZUH_INDEXER_CA_FILE / WAZUH_INDEXER_TLS_NAME; WAZUH_VERIFY_TLS switches it on."""
    return TlsConfig(
        verify=env.get("WAZUH_VERIFY_TLS") == "true",
        ca_file=env.get(f"{prefix}_CA_FILE") or None,
        server_name=env.get(f"{prefix}_TLS_NAME") or None,
    )


class _ExpectedNameContext(ssl.SSLContext):
    """SSLContext that checks the certificate against a fixed name instead of the URL host."""

    expected_name: str | None = None

    def wrap_socket(self, sock, *args, server_hostname=None, **kwargs):  # type: ignore[override]
        return super().wrap_socket(sock, *args, server_hostname=self.expected_name or server_hostname, **kwargs)


def basic_auth_header(user: str, password: str) -> str:
    """HTTP Basic auth: base64("user:password"). Encoding, NOT encryption -> needs TLS."""
    raw = f"{user}:{password}".encode()
    return "Basic " + base64.b64encode(raw).decode()


def ssl_context(tls: TlsConfig) -> ssl.SSLContext:
    ctx = _ExpectedNameContext(ssl.PROTOCOL_TLS_CLIENT)  # defaults: verify cert + hostname
    if not tls.verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if tls.ca_file:
        ctx.load_verify_locations(cafile=tls.ca_file)
    else:
        ctx.load_default_certs()
    ctx.expected_name = tls.server_name
    return ctx


def request_json(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: dict | None = None,
    tls: TlsConfig = TlsConfig(),
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
    with urllib.request.urlopen(req, timeout=TIMEOUT_S, context=ssl_context(tls)) as resp:
        return json.load(resp)
