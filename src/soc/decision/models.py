"""What the decision engine produces: prioritized, explained action proposals.

A Proposal is only a suggestion. Nothing in soc.decision executes anything;
Phase 7 queues proposals for human approval.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

PRIORITIES = ("low", "medium", "high", "critical")  # same scale as the AI analyst's severity

# Actions the engine may propose. Only some change the system (Phase 7 gates those).
ACTIONS = {
    "investigate": "human review, no change to any system",
    "harden_config": "fix a configuration weakness (backlog task)",
    "block_ip": "block a source IP on the host firewall",
    "disable_account": "disable a local user account",
    "isolate_host": "cut the host off the network except the SOC",
}
CHANGES_SYSTEM = {"block_ip", "disable_account", "isolate_host"}


def max_priority(*levels: str | None) -> str:
    """Highest of the given priorities; unknown/None values are ignored."""
    known = [p for p in levels if p in PRIORITIES]
    return max(known, key=PRIORITIES.index) if known else "low"


@dataclass(frozen=True)
class Proposal:
    action: str            # key of ACTIONS
    target: str            # IP, account, host, or config check
    priority: str          # low | medium | high | critical
    rule: str              # which rule proposed it (traceability)
    reason: str            # plain-English why, shown to the approver
    alert_id: str = ""

    @property
    def changes_system(self) -> bool:
        return self.action in CHANGES_SYSTEM

    def to_dict(self) -> dict:
        return {**asdict(self), "changes_system": self.changes_system}


@dataclass
class Decision:
    """Everything the engine concluded about one alert."""

    alert_id: str
    priority: str                    # final: max(rule priority, AI severity)
    rule_priority: str               # from deterministic rules / Wazuh level only
    ai_severity: str | None = None   # may raise, never lower
    proposals: list[Proposal] = field(default_factory=list)
    vetoed: list[str] = field(default_factory=list)   # proposals blocked by safety guards, with why
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["proposals"] = [p.to_dict() for p in self.proposals]
        return d
