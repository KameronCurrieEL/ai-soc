import json

import pytest

from soc.ai.responder import (actions_to_proposals, build_prompt, parse, select_skills, validate, Assessment)


def good(**kw):
    base = {"assessment": "Likely a real brute force from the internet.", "confidence": "high",
            "attacker_next_steps": [{"technique": "T1110", "step": "try more passwords", "watch_for": "a success 4624"}],
            "actions": [{"action": "block_ip", "target": "8.8.8.8", "urgency": "immediate", "reason": "public source"}]}
    return json.dumps({**base, **kw})


def test_parse_accepts_valid_and_rejects_bad():
    a, errs = parse(good())
    assert not errs and a.confidence == "high" and a.actions[0]["action"] == "block_ip"
    assert parse("not json")[1]
    assert "confidence" in " ".join(parse(good(confidence="definitely"))[1])
    bad_action = json.dumps({"assessment": "x", "confidence": "low", "attacker_next_steps": [],
                             "actions": [{"action": "nuke", "target": "x", "reason": "y"}]})
    assert parse(bad_action)[1]


def test_actions_become_proposals_only_for_incident_entities_and_safe_targets():
    a = Assessment("x", "high", [], [
        {"action": "block_ip", "target": "8.8.8.8", "urgency": "immediate", "reason": "public"},   # ok
        {"action": "block_ip", "target": "203.0.113.9", "urgency": "soon", "reason": "not in incident"},  # not an entity
        {"action": "block_ip", "target": "::1", "urgency": "immediate", "reason": "loopback"},      # entity but guard vetoes
        {"action": "disable_account", "target": "administrator", "urgency": "soon", "reason": "protected"},  # guard vetoes
        {"action": "investigate", "target": "whoever", "urgency": "routine", "reason": "look"},     # investigate: any target ok
    ])
    allowed, rejected = actions_to_proposals(a, allowed_targets={"8.8.8.8", "::1", "administrator"})
    actions = {(p.action, p.target): p for p in allowed}
    assert ("block_ip", "8.8.8.8") in actions and ("investigate", "whoever") in actions
    assert actions[("block_ip", "8.8.8.8")].priority == "critical"      # immediate -> critical
    assert all(p.rule == "ai_responder" for p in allowed)
    assert len(allowed) == 2 and len(rejected) == 3                      # the other three are blocked


def test_select_skills_matches_category_and_keywords():
    names = [s["name"] for s in select_skills("brute_force", "failed logon user admin from 8.8.8.8")]
    assert any("active-directory" in n or "netexec" in n or "privesc" in n for n in names)
    wifi = select_skills("new_service", "deauth on 2.4 ghz wifi BSSID evil twin")
    assert any(s["category"] == "wireless" for s in wifi)


def test_prompt_injects_skills_and_context_and_keeps_rules():
    p = build_prompt("Incident INC-1: brute force", select_skills("brute_force", "logon"))
    assert "INC-1: brute force" in p and "Allowed actions ONLY" in p
    assert "{relevant_skills}" not in p and "{incident_context}" not in p
