"""Read-only views over stored alerts: timeline, entities, plain-English summary, activity.

Pure functions over the data already in SQLite: no Wazuh or model calls, so pages stay fast.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from soc.parsing.schema import ip_scope

PRIORITY_ORDER = ("low", "medium", "high", "critical")

# Entity types an analyst pivots on. label, how to read it from a normalized alert dict.
ENTITY_TYPES = {
    "user": ("Target account", lambda a: [a.get("user")]),
    "requester": ("Started by", lambda a: [a.get("details", {}).get("requested_by")]),
    "ip": ("Source IP", lambda a: [a.get("src_ip")]),
    "host": ("Host", lambda a: [a.get("details", {}).get("host") or a.get("agent_name")]),
    "process": ("Process", lambda a: [a.get("details", {}).get("process")]),
    "technique": ("MITRE technique", lambda a: list(a.get("mitre_ids", []))),
    "rule": ("Detection rule", lambda a: [f"{a.get('rule_id')} {a.get('description', '')}".strip()]),
}


def parse_any_time(ts: str) -> datetime:
    """Wazuh '...260+0000' and audit '...+00:00' formats -> aware datetime."""
    ts = ts.strip()
    if len(ts) > 5 and ts[-5] in "+-" and ts[-3] != ":":
        ts = ts[:-2] + ":" + ts[-2:]
    return datetime.fromisoformat(ts)


def alert_data(row) -> dict:
    """A stored alert row (sqlite3.Row or dict with a JSON 'data' column) -> the normalized alert dict."""
    return json.loads(row["data"])


# ---------- entities ----------

@dataclass
class Entity:
    type: str
    label: str
    value: str
    count: int
    note: str = ""   # e.g. IP scope


def entities(alert_rows: list) -> dict[str, list[Entity]]:
    """Every user/IP/host/process/technique involved, with how often it appears."""
    out: dict[str, list[Entity]] = {}
    alerts = [alert_data(r) for r in alert_rows]
    for etype, (label, read) in ENTITY_TYPES.items():
        counts: Counter[str] = Counter()
        notes: dict[str, str] = {}
        for a in alerts:
            for v in read(a):
                if v:
                    counts[v] += 1
                    if etype == "ip" and a.get("src_ip_scope"):
                        notes[v] = a["src_ip_scope"]
        if counts:
            out[etype] = [Entity(etype, label, v, n, notes.get(v, "")) for v, n in counts.most_common()]
    return out


def hosts_and_ips(incident, alert_rows: list) -> tuple[list[str], list[str]]:
    """Affected hosts and source IPs (most frequent first).

    Incidents saved before alerts were stored have no alert rows: fall back to the incident
    key "family|entity@agent", whose entity is the source IP for logon incidents.
    """
    if alert_rows:
        ents = entities(alert_rows)
        return [e.value for e in ents.get("host", [])], [e.value for e in ents.get("ip", [])]
    _, _, rest = incident["key"].partition("|")
    entity, _, agent = rest.rpartition("@")
    return ([agent] if agent else []), ([entity] if ip_scope(entity) else [])


def matches_entity(alert: dict, etype: str, value: str) -> bool:
    if etype not in ENTITY_TYPES:
        return False
    return value in [v for v in ENTITY_TYPES[etype][1](alert) if v]


# ---------- timeline ----------

@dataclass
class TimelineItem:
    at: datetime
    kind: str            # alert | pipeline | human
    title: str
    priority: str = ""
    count: int = 1
    until: datetime | None = None
    actor: str = ""
    detail: str = ""
    alert_ids: list[str] = field(default_factory=list)


AUDIT_TITLES = {
    "incident_created": "Incident opened by the pipeline",
    "incident_escalated": "Priority raised",
    "proposal_created": "Action proposed",
    "proposal_approved": "Action approved",
    "proposal_rejected": "Action rejected",
    "proposal_executed": "Action executed (dry-run)",
    "approval_refused": "Approval refused by safety checks",
    "incident_closed": "Incident closed",
}


def timeline(alert_rows: list, audit_rows: list, collapse_s: int = 300) -> list[TimelineItem]:
    """Alerts and audit events in one chronological story.

    Consecutive alerts with the same rule within collapse_s merge into one line ("27x ..."),
    so a long attack stays readable.
    """
    items: list[TimelineItem] = []
    for row in sorted(alert_rows, key=lambda r: r["timestamp"]):
        a = alert_data(row)
        at = parse_any_time(row["timestamp"])
        prev = items[-1] if items else None
        if (prev and prev.kind == "alert" and prev.title == a.get("description")
                and (at - (prev.until or prev.at)).total_seconds() <= collapse_s):
            prev.count += 1
            prev.until = at
            prev.alert_ids.append(row["id"])
            prev.priority = max(prev.priority, row["priority"], key=PRIORITY_ORDER.index)
            continue
        detail_bits = [f"rule {a.get('rule_id')}"]
        if a.get("user"):
            detail_bits.append(f"account {a['user']}")
        if a.get("src_ip"):
            detail_bits.append(f"from {a['src_ip']}")
        if a.get("details", {}).get("failure_reason"):
            detail_bits.append(a["details"]["failure_reason"].split(" ", 1)[-1])
        items.append(TimelineItem(at, "alert", a.get("description", ""), row["priority"],
                                  detail=" · ".join(detail_bits), alert_ids=[row["id"]]))
    for e in audit_rows:
        detail = json.loads(e["detail"])
        bits = [f"{k}: {v}" for k, v in detail.items() if k in ("action", "target", "reason", "note", "verdict", "old", "new")]
        items.append(TimelineItem(parse_any_time(e["at"]), "pipeline" if e["actor"] == "pipeline" else "human",
                                  AUDIT_TITLES.get(e["event"], e["event"]), actor=e["actor"], detail=" · ".join(bits)))
    return sorted(items, key=lambda i: (i.at, i.kind != "alert"))


# ---------- plain-English summary ----------

def plain_summary(incident, alert_rows: list) -> str:
    """One paragraph anyone can read, built only from parsed facts (no model involved)."""
    alerts = [alert_data(r) for r in alert_rows]
    family = incident["key"].split("|", 1)[0]
    ents = entities(alert_rows)
    first = parse_any_time(incident["first_seen"]).strftime("%H:%M")
    last = parse_any_time(incident["last_seen"]).strftime("%H:%M")
    when = f"between {first} and {last} UTC" if first != last else f"at {first} UTC"
    total = sum(max(a.get("related_count", 0), 1) if a.get("source") == "soc_correlation" else 1 for a in alerts)

    def top(etype: str) -> str | None:
        return ents[etype][0].value if etype in ents else None

    if family == "brute_force":
        ip, scope, user = top("ip"), (ents.get("ip") or [Entity("", "", "", 0)])[0].note, top("user")
        attempts = max([a.get("related_count", 0) for a in alerts] + [len(alerts)])
        who = f"the account '{user}'" if user else "an account"
        if scope == "public":
            advice = "It came from the internet, so blocking that address is proposed."
        else:
            starter = top("requester")
            by = f" (they were started by '{starter}')" if starter else ""
            advice = ("It came from this machine or the local network, so nothing gets blocked: "
                      f"the next step is to find out who or what started them{by}.")
        return f"Someone tried and failed to sign in to {who} about {attempts} times {when}, from {ip or 'an unknown source'}. {advice}"
    if family == "success_after_brute_force":
        return (f"After many failed attempts, a sign-in to '{top('user')}' SUCCEEDED from {top('ip')} {when}. "
                "Treat the account and the computer as compromised until proven otherwise.")
    if family == "security_agent_stopped":
        return (f"The Wazuh security agent on {top('host') or 'a computer'} stopped {when}. While it is off, "
                "nothing on that machine is being watched. Confirm it was a planned restart.")
    if family == "new_service":
        return (f"A new Windows service was installed on {top('host') or 'a computer'} {when}. "
                "Services start automatically, which attackers use to stay on a machine. Check that it is expected software.")
    return f"{incident['title']}: {total} related alert(s) {when}."


# ---------- activity chart ----------

@dataclass
class Bucket:
    start: datetime
    counts: dict[str, int]

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def activity(alert_rows: list, hours: int = 24, now: datetime | None = None) -> list[Bucket]:
    """Alerts per hour for the last `hours`, split by priority (for a stacked bar chart)."""
    now = (now or datetime.now(timezone.utc)).replace(minute=0, second=0, microsecond=0)
    start = now - timedelta(hours=hours - 1)
    buckets = [Bucket(start + timedelta(hours=i), {p: 0 for p in PRIORITY_ORDER}) for i in range(hours)]
    for r in alert_rows:
        at = parse_any_time(r["timestamp"]).replace(minute=0, second=0, microsecond=0)
        idx = int((at - start).total_seconds() // 3600)
        if 0 <= idx < hours:
            buckets[idx].counts[r["priority"]] = buckets[idx].counts.get(r["priority"], 0) + 1
    return buckets
