import json
from pathlib import Path

from soc.ai.evaluate import alert_from_dict
from soc.decision.rules import run_rules

CASES = {c["id"]: alert_from_dict(c["alert"])
         for c in json.loads((Path(__file__).parent.parent / "data" / "eval" / "cases.json").read_text())}


def hits(case_id):
    return run_rules(CASES[case_id])


def actions(case_id):
    return {(p.action, p.target) for h in hits(case_id) for p in h.proposals}


def test_public_brute_force_proposes_block_and_is_high():
    [h] = hits("syn-bruteforce-public-rdp")
    assert h.rule == "brute_force" and h.priority == "high"
    assert ("block_ip", "203.0.113.50") in actions("syn-bruteforce-public-rdp")


def test_prompt_injection_case_is_still_high_with_block():
    [h] = hits("syn-prompt-injection-username")
    assert h.priority == "high" and ("block_ip", "203.0.113.50") in actions("syn-prompt-injection-username")


def test_loopback_brute_force_is_medium_and_never_blocks():
    [h] = hits("real-60204-bruteforce-loopback")
    assert h.priority == "medium"
    assert {a for a, _ in actions("real-60204-bruteforce-loopback")} == {"investigate"}
    assert ("investigate", "labuser") in actions("real-60204-bruteforce-loopback")  # who started it


def test_success_after_brute_force_is_critical():
    [h] = hits("syn-success-after-bruteforce")
    assert h.priority == "critical"
    assert {a for a, _ in actions("syn-success-after-bruteforce")} == {"isolate_host", "disable_account", "block_ip"}


def test_agent_stopped_is_high():
    [h] = hits("real-agent-stopped")
    assert (h.rule, h.priority) == ("security_agent_stopped", "high")


def test_service_from_public_folder_is_high():
    [h] = hits("syn-new-service-public-folder")
    assert (h.rule, h.priority) == ("new_service", "high")


def test_sca_failed_is_low_with_harden_task_and_passed_has_no_action():
    [f] = hits("real-sca-failed")
    assert f.priority == "low" and f.proposals[0].action == "harden_config"
    [p] = hits("real-sca-passed")
    assert p.priority == "low" and p.proposals == []


def test_routine_noise_matches_no_rule():
    for cid in ("real-4624-service-logon", "real-fim-registry-modified", "real-dns-timeout",
                "real-7040-bits-start-type", "real-5061-crypto-audit-failure", "real-4625-single-failure"):
        assert hits(cid) == [], cid
