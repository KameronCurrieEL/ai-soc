"""One pipeline run: fetch -> normalize -> decide (+AI) -> incidents -> queue.

The pipeline only ever PROPOSES. Approval and execution live in soc.agent.approval.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field, replace

from soc.agent.incidents import group_incidents
from soc.agent.approval import run_autopilot
from soc.agent.store import audit, get_setting, save_alerts, save_incidents
from soc.decision.engine import decide_batch, hardening_backlog
from soc.parsing.normalize import normalize
from soc.parsing.schema import Alert
from soc.wazuh.alerts import alerts_from_response, build_alerts_query, parse_window
from soc.wazuh.indexer import indexer_settings, search

MAX_ALERTS = 1000
DEFAULT_SENSOR = "wazuh-lab"


def _tag(alerts: list[Alert], sensor: str) -> list[Alert]:
    """Stamp each normalized alert with the sensor it came from (multi-source)."""
    return [replace(a, sensor=sensor) for a in alerts]


@dataclass
class RunStats:
    alerts: int = 0
    decisions_with_proposals: int = 0
    ai_calls: int = 0
    incidents: int = 0
    saved: dict = field(default_factory=dict)
    backlog_checks: int = 0
    autopilot_actions: int = 0


def fetch_alerts(env: dict[str, str], last: str, sensor: str = DEFAULT_SENSOR) -> list[Alert]:
    settings = indexer_settings(env)
    if settings is None:
        raise RuntimeError("set WAZUH_INDEXER_USER / WAZUH_INDEXER_PASSWORD in .env")
    resp = search(settings, build_alerts_query(parse_window(last), size=MAX_ALERTS))
    return _tag([normalize(r) for r in alerts_from_response(resp)], sensor)


def alerts_from_file(path: str, sensor: str) -> list[Alert]:
    """Load raw alerts (a JSON list of Wazuh-format dicts) from another source, normalize, tag the sensor.

    Lets a second collector feed the same pipeline without a live Wazuh. The file is untrusted data:
    we only read JSON and run it through the same normalizer, which tolerates missing/odd fields.
    """
    import json
    from pathlib import Path
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        raw = raw.get("alerts") or raw.get("hits", {}).get("hits") or [raw]
    return _tag([normalize(r) for r in raw], sensor)


def make_ai_analyst(env: dict[str, str], notes: dict[str, str], stats: RunStats):
    """Wrap the AI analyst: returns severity for the engine, keeps the summary for the incident."""
    from soc.ai.analyst import analyze
    from soc.ai.llm import llm_from_env
    llm = llm_from_env(env)

    def analyst(alert: Alert) -> str | None:
        stats.ai_calls += 1
        r = analyze(alert, llm)
        if r.analysis:
            notes[alert.id] = f"[{r.analysis.severity}] {r.analysis.summary}"
            return r.analysis.severity
        return None
    return analyst


def run_pipeline(conn: sqlite3.Connection, alerts: list[Alert], analyst=None,
                 ai_notes: dict[str, str] | None = None, stats: RunStats | None = None) -> RunStats:
    stats = stats or RunStats()
    stats.alerts = len(alerts)
    results = decide_batch(alerts, analyst)
    save_alerts(conn, results)
    stats.decisions_with_proposals = sum(1 for _, d in results if d.proposals)
    incidents = group_incidents(results, ai_notes=ai_notes)
    stats.incidents = len(incidents)
    stats.saved = save_incidents(conn, incidents)
    stats.backlog_checks = sum(len(v) for v in hardening_backlog(alerts).values())
    if get_setting(conn, "autopilot", "off") == "on":   # D6: auto-contain rule-critical incidents (dry-run)
        stats.autopilot_actions = len(run_autopilot(conn, dry_run=True))
    with conn:
        audit(conn, "pipeline", "pipeline_run", alerts=stats.alerts, ai_calls=stats.ai_calls,
              incidents=stats.incidents, autopilot_actions=stats.autopilot_actions, **stats.saved)
    return stats
