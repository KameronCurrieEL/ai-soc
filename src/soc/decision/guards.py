"""Safety guards: veto proposals that could hurt us, no matter which rule (or model) asked.

Guards run AFTER the rules, so a buggy rule still can't propose blocking ourselves.
Each guard returns None if the proposal is allowed, or a reason string if vetoed.
"""

from __future__ import annotations

from soc.decision.models import ACTIONS, Proposal
from soc.parsing.schema import ip_scope

# Accounts that must never be disabled automatically (lockout / breaks Windows).
PROTECTED_ACCOUNTS = {"system", "local service", "network service", "administrator", "-", ""}


def check_action_known(p: Proposal) -> str | None:
    return None if p.action in ACTIONS else f"unknown action {p.action!r}"


def check_block_ip(p: Proposal) -> str | None:
    """Only public IPs may be blocked: blocking loopback/LAN/reserved = self-inflicted outage."""
    if p.action != "block_ip":
        return None
    scope = ip_scope(p.target)
    if scope != "public":
        return f"refuse to block {p.target!r}: scope is {scope or 'not an IP'}, only public IPs can be blocked"
    return None


def check_disable_account(p: Proposal) -> str | None:
    if p.action != "disable_account":
        return None
    name = p.target.strip().lower()
    if name in PROTECTED_ACCOUNTS or name.endswith("$"):  # $ = computer/machine account
        return f"refuse to disable protected account {p.target!r}"
    return None


GUARDS = (check_action_known, check_block_ip, check_disable_account)


def apply_guards(proposals: list[Proposal]) -> tuple[list[Proposal], list[str]]:
    """Split proposals into (allowed, veto reasons)."""
    allowed, vetoed = [], []
    for p in proposals:
        reasons = [r for g in GUARDS if (r := g(p))]
        if reasons:
            vetoed.extend(f"{p.rule}: {r}" for r in reasons)
        else:
            allowed.append(p)
    return allowed, vetoed
