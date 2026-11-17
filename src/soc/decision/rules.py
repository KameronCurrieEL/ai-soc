"""Deterministic detection rules: normalized Alert -> RuleHit (or None).

Rules read only parsed fields (scope, MITRE ids, event ids, paths), never free text an
attacker controls, so the prompt-injection trick from the Phase 5 eval has no effect here.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from soc.decision.models import Proposal
from soc.parsing.schema import Alert

# Folders any user can write to: a service binary there is a classic persistence red flag.
USER_WRITABLE_PATHS = ("\\users\\public\\", "\\appdata\\", "\\temp\\", "\\programdata\\", "\\downloads\\")


@dataclass
class RuleHit:
    rule: str
    priority: str
    reason: str
    proposals: list[Proposal] = field(default_factory=list)


Rule = Callable[[Alert], "RuleHit | None"]


def _p(alert: Alert, rule: str, action: str, target: str | None, priority: str, reason: str) -> list[Proposal]:
    return [Proposal(action, target, priority, rule, reason, alert.id)] if target else []


def brute_force(alert: Alert) -> RuleHit | None:
    """Correlated logon failures (Wazuh 60204 / MITRE T1110) that did NOT succeed."""
    if "T1110" not in alert.mitre_ids or alert.event_id == "4624":
        return None
    who = f"user {alert.user!r}" if alert.user else "an unknown user"
    if alert.src_ip_scope == "public":
        reason = f"{alert.related_count or 'multiple'} failed logons for {who} from public IP {alert.src_ip}"
        props = _p(alert, "brute_force", "block_ip", alert.src_ip, "high", reason)
        props += _p(alert, "brute_force", "investigate", alert.user, "high",
                    f"check whether {who} is a real account and if it was targeted elsewhere")
        return RuleHit("brute_force", "high", reason, props)
    origin = alert.src_ip or "an unknown source"
    reason = (f"repeated failed logons for {who} from {origin} ({alert.src_ip_scope or 'unknown scope'}): "
              "local origin, so find the process or person generating them instead of blocking")
    requester = alert.details.get("requested_by") or alert.agent_name
    return RuleHit("brute_force", "medium", reason,
                   _p(alert, "brute_force", "investigate", requester, "medium", reason))


def success_after_brute_force(alert: Alert) -> RuleHit | None:
    """A SUCCESSFUL logon tied to a brute-force pattern: assume compromise."""
    if "T1110" not in alert.mitre_ids or alert.event_id != "4624":
        return None
    reason = f"successful logon as {alert.user!r} after repeated failures from {alert.src_ip}: likely compromised"
    props = _p(alert, "success_after_brute_force", "isolate_host", alert.agent_name, "critical", reason)
    props += _p(alert, "success_after_brute_force", "disable_account", alert.user, "critical", reason)
    props += _p(alert, "success_after_brute_force", "block_ip", alert.src_ip, "critical", reason)
    return RuleHit("success_after_brute_force", "critical", reason, props)


def security_agent_stopped(alert: Alert) -> RuleHit | None:
    """Losing visibility is an attacker's first move (T1562 Impair Defenses). Owner rated this high."""
    if alert.rule_id != "506" and "T1562" not in alert.mitre_ids:
        return None
    reason = f"security monitoring stopped on {alert.agent_name or 'an agent'}: confirm it was a planned restart"
    return RuleHit("security_agent_stopped", "high", reason,
                   _p(alert, "security_agent_stopped", "investigate", alert.agent_name or alert.agent_id, "high", reason))


def new_service(alert: Alert) -> RuleHit | None:
    """New Windows service (event 7045). High if the binary lives in a user-writable folder."""
    if alert.event_id != "7045":
        return None
    params = alert.details.get("event_params", "")
    host = alert.details.get("host") or alert.agent_name
    if any(p in params.lower() for p in USER_WRITABLE_PATHS):
        reason = f"new service with a binary in a user-writable folder ({params}): likely persistence (T1543.003)"
        return RuleHit("new_service", "high", reason, _p(alert, "new_service", "investigate", host, "high", reason))
    reason = f"new service installed ({params or 'details missing'}): verify it is expected software"
    return RuleHit("new_service", "medium", reason, _p(alert, "new_service", "investigate", host, "medium", reason))


def config_benchmark(alert: Alert) -> RuleHit | None:
    """SCA results are configuration findings, not attacks (owner's call): always low."""
    if alert.source != "sca":
        return None
    result = alert.details.get("result")
    check = alert.details.get("check") or alert.description
    if result == "failed":
        # No proposal: hundreds of these would bury real threats in the approval queue.
        # They go to the hardening backlog report instead (engine.hardening_backlog).
        return RuleHit("config_benchmark", "low", f"hardening check failed (see backlog): {check}")
    return RuleHit("config_benchmark", "low", f"configuration check {result or 'summary'}: no action")


RULES: tuple[Rule, ...] = (success_after_brute_force, brute_force, security_agent_stopped, new_service, config_benchmark)


def run_rules(alert: Alert) -> list[RuleHit]:
    return [hit for rule in RULES if (hit := rule(alert))]
