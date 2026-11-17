"""Group decisions into incidents: what a human actually triages.

Two decisions join the same incident if they share a key (rule family + entity, e.g.
"brute_force" + source IP) and happen within WINDOW_S of the incident's last activity.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from soc.decision.correlate import parse_time
from soc.decision.models import Decision, Proposal, max_priority
from soc.parsing.schema import Alert

WINDOW_S = 3600  # 60 minutes of inactivity closes the grouping window


@dataclass
class Incident:
    key: str                  # e.g. "brute_force|::1@windows-host"
    title: str
    priority: str
    first_seen: str
    last_seen: str
    alert_ids: list[str] = field(default_factory=list)
    proposals: list[Proposal] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    vetoed: list[str] = field(default_factory=list)

    @property
    def id(self) -> str:
        """Stable id: same key + same start -> same id on every pipeline run."""
        digest = hashlib.sha1(f"{self.key}|{self.first_seen}".encode()).hexdigest()[:8]
        return f"INC-{digest}"


def incident_key(alert: Alert, decision: Decision) -> str:
    """Rule family + the entity it's about."""
    family = decision.proposals[0].rule if decision.proposals else "other"
    if family in ("brute_force", "success_after_brute_force"):
        entity = alert.src_ip or "unknown-src"
    else:
        entity = decision.proposals[0].target if decision.proposals else alert.rule_id
    return f"{family}|{entity}@{alert.agent_name or alert.agent_id}"


def _title(alert: Alert, family: str) -> str:
    titles = {
        "brute_force": f"Brute force from {alert.src_ip or 'unknown source'}",
        "success_after_brute_force": f"Possible compromise: logon after brute force from {alert.src_ip}",
        "security_agent_stopped": f"Security monitoring stopped on {alert.agent_name}",
        "new_service": f"New service on {alert.details.get('host') or alert.agent_name}",
    }
    return titles.get(family, alert.description)


def group_incidents(results: list[tuple[Alert, Decision]], window_s: int = WINDOW_S) -> list[Incident]:
    """Only decisions with proposals become incidents; low noise stays out of the queue."""
    actionable = sorted(((a, d) for a, d in results if d.proposals), key=lambda x: parse_time(x[0].timestamp))
    open_by_key: dict[str, Incident] = {}
    incidents: list[Incident] = []
    for alert, d in actionable:
        key = incident_key(alert, d)
        inc = open_by_key.get(key)
        if inc and (parse_time(alert.timestamp) - parse_time(inc.last_seen)).total_seconds() > window_s:
            inc = None  # too long since the last activity: start a new incident
        if inc is None:
            inc = Incident(key, _title(alert, d.proposals[0].rule), d.priority, alert.timestamp, alert.timestamp)
            open_by_key[key] = inc
            incidents.append(inc)
        inc.priority = max_priority(inc.priority, d.priority)
        inc.last_seen = alert.timestamp
        inc.alert_ids.append(alert.id)
        for p in d.proposals:
            # one proposal per (action, target) per incident, keep the highest priority
            same = next((q for q in inc.proposals if (q.action, q.target) == (p.action, p.target)), None)
            if same is None:
                inc.proposals.append(p)
            elif max_priority(same.priority, p.priority) != same.priority:
                inc.proposals[inc.proposals.index(same)] = p
        inc.reasons += [r for r in d.reasons if r not in inc.reasons]
        inc.vetoed += [v for v in d.vetoed if v not in inc.vetoed]
    return incidents
