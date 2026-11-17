"""Talk to the Wazuh indexer (OpenSearch, port 9200), where alerts are stored.

The manager API (55000) knows about agents; the indexer holds the alert documents.
Alerts go to daily indices named wazuh-alerts-4.x-YYYY.MM.DD, so we search the
pattern wazuh-alerts-* and filter by time in the query.

Run with:  python -m soc.wazuh.indexer   (part of `make wazuh-check`)
"""

from __future__ import annotations

import ssl
import sys
import urllib.error
from dataclasses import dataclass

from soc.checks import CheckResult, load_env
from soc.wazuh.client import TlsConfig, basic_auth_header, request_json, tls_from_env

ALERTS_INDEX = "wazuh-alerts-*"


@dataclass(frozen=True)
class IndexerSettings:
    url: str
    user: str
    password: str
    tls: TlsConfig


def indexer_settings(env: dict[str, str]) -> IndexerSettings | None:
    """Read indexer connection settings from .env. None if credentials are missing."""
    user, password = env.get("WAZUH_INDEXER_USER"), env.get("WAZUH_INDEXER_PASSWORD")
    if not user or not password:
        return None
    return IndexerSettings(
        url=env.get("WAZUH_INDEXER_URL", "https://localhost:9200").rstrip("/"),
        user=user,
        password=password,
        tls=tls_from_env(env, "WAZUH_INDEXER"),
    )


def search(settings: IndexerSettings, query: dict, index: str = ALERTS_INDEX) -> dict:
    """Run an OpenSearch _search request and return the raw response."""
    return request_json(
        f"{settings.url}/{index}/_search",
        method="POST",
        headers={"Authorization": basic_auth_header(settings.user, settings.password)},
        body=query,
        tls=settings.tls,
    )


def check_indexer(env: dict[str, str]) -> CheckResult:
    """Health check: can we log in and is the cluster usable?

    green = all good, yellow = data safe but replicas unassigned (normal on one node), red = broken.
    """
    s = indexer_settings(env)
    if s is None:
        return CheckResult("indexer", False, "set WAZUH_INDEXER_USER / WAZUH_INDEXER_PASSWORD in .env")
    try:
        health = request_json(
            f"{s.url}/_cluster/health",
            headers={"Authorization": basic_auth_header(s.user, s.password)},
            tls=s.tls,
        )
    except urllib.error.HTTPError as exc:
        hint = "wrong credentials" if exc.code == 401 else "indexer still starting?"
        return CheckResult("indexer", False, f"{s.url} HTTP {exc.code} ({hint})")
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, ssl.SSLCertVerificationError):
            return CheckResult("indexer", False, f"{s.url} TLS certificate rejected ({exc.reason.verify_message})")
        return CheckResult("indexer", False, f"{s.url} unreachable ({exc})")
    except (OSError, ValueError) as exc:
        return CheckResult("indexer", False, f"{s.url} unreachable ({exc})")
    status = health.get("status", "unknown")
    return CheckResult("indexer", status in ("green", "yellow"), f"{s.url} cluster status {status}")


def main() -> int:
    r = check_indexer(load_env())
    print(f"[{'OK' if r.ok else 'FAIL':4}] {r.name:7} {r.detail}")
    return 0 if r.ok else 1


if __name__ == "__main__":
    sys.exit(main())
