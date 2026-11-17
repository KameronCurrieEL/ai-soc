import pytest

from soc.decision.guards import apply_guards
from soc.decision.models import Proposal, max_priority


def P(action, target):
    return Proposal(action, target, "high", "test-rule", "why")


@pytest.mark.parametrize("ip", ["::1", "127.0.0.1", "192.168.1.5", "10.0.0.1", "172.24.0.1",
                                "203.0.113.50", "0.0.0.0", "not-an-ip", ""])
def test_never_block_non_public_ips(ip):
    allowed, vetoed = apply_guards([P("block_ip", ip)])
    assert allowed == [] and "refuse to block" in vetoed[0]


def test_public_ip_block_allowed():
    allowed, vetoed = apply_guards([P("block_ip", "8.8.8.8")])
    assert len(allowed) == 1 and vetoed == []


@pytest.mark.parametrize("acct", ["SYSTEM", "Administrator", "WIN-LAB01$", "Network Service", "-"])
def test_protected_accounts_never_disabled(acct):
    allowed, vetoed = apply_guards([P("disable_account", acct)])
    assert allowed == [] and "protected account" in vetoed[0]


def test_normal_account_disable_allowed_and_unknown_action_vetoed():
    allowed, vetoed = apply_guards([P("disable_account", "bob"), P("format_disk", "C:")])
    assert [p.target for p in allowed] == ["bob"] and "unknown action" in vetoed[0]


def test_investigate_is_never_vetoed():
    assert apply_guards([P("investigate", "::1")]) == ([P("investigate", "::1")], [])


def test_max_priority_ignores_unknown():
    assert max_priority("low", "high", "medium") == "high"
    assert max_priority(None, "bogus") == "low"
    assert max_priority("medium", None) == "medium"


def test_changes_system_flag():
    assert P("block_ip", "8.8.8.8").changes_system and not P("investigate", "x").changes_system
