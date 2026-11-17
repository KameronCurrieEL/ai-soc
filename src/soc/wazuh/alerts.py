"""Fetch recent Wazuh alerts from the indexer.

Run with:  python -m soc.wazuh.alerts --last 1h [--min-level 5] [--agent 001] [--rule 60122] [--save]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from soc.checks import load_env
from soc.wazuh.indexer import indexer_settings, search

MAX_RESULTS = 1000
RAW_DIR = Path("data/raw")  # gitignored: real, unsanitized alerts
_WINDOW = re.compile(r"^(\d{1,4})([mhd])$")


def parse_window(text: str) -> str:
    """'1h' -> 'now-1h' (OpenSearch date math). Strict, so user input can't alter the query."""
    m = _WINDOW.match(text.strip())
    if not m or int(m.group(1)) == 0:
        raise ValueError(f"invalid time window {text!r}: use e.g. 30m, 1h, 7d")
    return f"now-{m.group(1)}{m.group(2)}"


def build_alerts_query(
    since: str,
    min_level: int = 0,
    agent_id: str | None = None,
    rule_ids: list[str] | None = None,
    size: int = 50,
) -> dict:
    """Build the OpenSearch query. Filters only (no scoring needed), newest first."""
    filters: list[dict] = [{"range": {"timestamp": {"gte": since}}}]
    if min_level > 0:
        filters.append({"range": {"rule.level": {"gte": min_level}}})
    if agent_id:
        filters.append({"term": {"agent.id": agent_id}})
    if rule_ids:
        filters.append({"terms": {"rule.id": rule_ids}})
    return {
        "size": max(1, min(size, MAX_RESULTS)),
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": filters}},
    }


def alerts_from_response(resp: dict) -> list[dict]:
    """Extract the alert documents (_source) from an OpenSearch search response."""
    return [hit["_source"] for hit in resp.get("hits", {}).get("hits", []) if "_source" in hit]


def total_hits(resp: dict) -> int:
    """How many alerts matched in total (may be more than we fetched)."""
    total = resp.get("hits", {}).get("total", 0)
    return total.get("value", 0) if isinstance(total, dict) else int(total)


def summarize_alert(alert: dict) -> str:
    """One readable line per alert. Full normalization is Phase 4's job."""
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    ev = alert.get("data", {}).get("win", {}).get("eventdata", {})
    extra = []
    if ev.get("targetUserName"):
        extra.append(f"user={ev['targetUserName']}")
    if ev.get("ipAddress") and ev["ipAddress"] != "-":
        extra.append(f"src={ev['ipAddress']}")
    mitre = ",".join(rule.get("mitre", {}).get("id", []))
    return (
        f"{alert.get('timestamp', '')[:19]}  {agent.get('id', '?'):>3} {agent.get('name', ''):<14} "
        f"rule {rule.get('id', '?'):>6} lvl {rule.get('level', '?'):>2}  "
        f"{rule.get('description', '')}"
        + (f"  [{mitre}]" if mitre else "")
        + (f"  {' '.join(extra)}" if extra else "")
    )


def save_raw(alerts: list[dict], directory: Path = RAW_DIR) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"alerts-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.json"
    path.write_text(json.dumps(alerts, indent=2) + "\n")
    return path


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Fetch recent Wazuh alerts from the indexer.")
    p.add_argument("--last", default="1h", help="time window, e.g. 30m, 1h, 7d (default 1h)")
    p.add_argument("--min-level", type=int, default=0, help="minimum rule level (0-15)")
    p.add_argument("--agent", help="agent id, e.g. 001")
    p.add_argument("--rule", action="append", help="rule id; repeat for several")
    p.add_argument("--limit", type=int, default=50, help=f"max alerts to fetch (<= {MAX_RESULTS})")
    p.add_argument("--save", action="store_true", help=f"save raw alerts to {RAW_DIR}/")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        since = parse_window(args.last)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    settings = indexer_settings(load_env())
    if settings is None:
        print("set WAZUH_INDEXER_USER / WAZUH_INDEXER_PASSWORD in .env", file=sys.stderr)
        return 1
    query = build_alerts_query(since, args.min_level, args.agent, args.rule, args.limit)
    resp = search(settings, query)
    alerts = alerts_from_response(resp)
    for a in reversed(alerts):  # print oldest -> newest, like a log
        print(summarize_alert(a))
    print(f"-- showing {len(alerts)} of {total_hits(resp)} matching alerts (last {args.last})")
    if args.save and alerts:
        print(f"-- saved raw alerts to {save_raw(alerts)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
