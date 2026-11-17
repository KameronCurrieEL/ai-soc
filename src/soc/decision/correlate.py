"""Our own failed-logon correlation, independent of Wazuh's rule 60204.

Wazuh missed a 10-failure burst that arrived in the same millisecond (Phase 2). We count
over a batch of stored alerts, sorted by time, so arrival order can't hide a burst.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from soc.parsing.schema import Alert

FAILED_LOGON_EVENT = "4625"
WINDOW_S = 300   # 5 minutes
THRESHOLD = 5    # failures from one source within the window


@dataclass
class Burst:
    source: str                 # src IP, or "local:<agent>" when Windows logged no IP
    src_ip: str | None
    src_ip_scope: str | None
    count: int
    first: str
    last: str
    users: list[str] = field(default_factory=list)
    alert_ids: list[str] = field(default_factory=list)
    agent_name: str = ""
    requested_by: list[str] = field(default_factory=list)  # who started the logon attempts (subject user)


def parse_time(ts: str) -> datetime:
    """Wazuh format: 2026-11-17T19:43:36.260+0000"""
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f%z")


def source_key(a: Alert) -> str:
    return a.src_ip or f"local:{a.agent_id}"


def find_bursts(alerts: list[Alert], window_s: int = WINDOW_S, threshold: int = THRESHOLD) -> list[Burst]:
    """Group single failed logons by source; report each source's largest burst within the window."""
    by_source: dict[str, list[Alert]] = {}
    for a in alerts:
        if a.event_id == FAILED_LOGON_EVENT and "T1110" not in a.mitre_ids:  # singles only, not 60204 itself
            by_source.setdefault(source_key(a), []).append(a)

    bursts = []
    for key, items in by_source.items():
        items.sort(key=lambda a: parse_time(a.timestamp))
        times = [parse_time(a.timestamp) for a in items]
        best_start, best_len, start = 0, 0, 0
        for end in range(len(items)):          # sliding window over sorted times
            while (times[end] - times[start]).total_seconds() > window_s:
                start += 1
            if end - start + 1 > best_len:
                best_start, best_len = start, end - start + 1
        if best_len >= threshold:
            group = items[best_start:best_start + best_len]
            bursts.append(Burst(
                source=key, src_ip=group[0].src_ip, src_ip_scope=group[0].src_ip_scope, count=best_len,
                first=group[0].timestamp, last=group[-1].timestamp,
                users=sorted({a.user for a in group if a.user}), alert_ids=[a.id for a in group],
                agent_name=group[0].agent_name,
                requested_by=sorted({r for a in group if (r := a.details.get("requested_by"))}),
            ))
    return bursts
