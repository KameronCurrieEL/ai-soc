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
    src_ip_scope: str | None = None   # loopback | private | public | reserved
    event_id: str | None = None       # e.g. Windows 4625
    related_count: int = 0            # correlation alerts: how many earlier events led to this one
    sensor: str = "wazuh-lab"         # which collector/SIEM this alert came from (multi-source)
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


# Explicit, so "private" means "our own network" (Python's is_private also includes
# reserved/documentation ranges, which would mislead the decision engine).
PRIVATE_NETS = [ipaddress.ip_network(n) for n in
                ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")]


def ip_scope(ip: str | None) -> str | None:
    """loopback | private | public | reserved: so later stages never propose blocking ourselves or the LAN."""
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local or any(addr in net for net in PRIVATE_NETS if net.version == addr.version):
        return "private"
    if addr.is_global:
        return "public"
    return "reserved"  # documentation, multicast, unspecified, ...
