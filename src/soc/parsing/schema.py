"""Our own alert schema: the one shape every later stage (AI, decisions, audit) relies on.

Wazuh field names stay inside the parser. If we swapped SIEMs, only the parser changes.
"""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class Alert:
    id: str                     # Wazuh alert id, to trace back to the original
    timestamp: str              # ISO 8601, UTC
    source: str                 # windows_event | fim | sca | wazuh | other
    rule_id: str
    rule_level: int             # Wazuh 0-15
    wazuh_severity: str         # level mapped to low/medium/high/critical (Wazuh's view, not the AI's)
    description: str
    agent_id: str
    agent_name: str
    mitre_ids: tuple[str, ...] = ()
    mitre_tactics: tuple[str, ...] = ()
    user: str | None = None
    src_ip: str | None = None
    src_ip_scope: str | None = None   # loopback | private | public
    event_id: str | None = None       # e.g. Windows 4625
    related_count: int = 0            # correlation alerts: how many earlier events led to this one
    details: dict[str, str] = field(default_factory=dict)  # source-specific, human-readable extras

    def to_dict(self) -> dict:
        d = asdict(self)
        d["mitre_ids"], d["mitre_tactics"] = list(self.mitre_ids), list(self.mitre_tactics)
        return d


def wazuh_severity(level: int) -> str:
    """Same bands as the Wazuh dashboard: 0-6 low, 7-11 medium, 12-14 high, 15 critical."""
    if level >= 15:
        return "critical"
    if level >= 12:
        return "high"
    if level >= 7:
        return "medium"
    return "low"


def ip_scope(ip: str | None) -> str | None:
    """Classify an address so later stages never propose blocking ourselves or the LAN."""
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.is_loopback:
        return "loopback"
    if addr.is_private or addr.is_link_local:
        return "private"
    return "public"
