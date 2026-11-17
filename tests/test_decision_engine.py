import json
from pathlib import Path

from soc.ai.evaluate import alert_from_dict
from soc.decision.engine import burst_to_alert, decide, decide_batch, hardening_backlog, needs_ai
from soc.decision.correlate import Burst
from soc.parsing.schema import Alert

CASES = {c["id"]: alert_from_dict(c["alert"])
         for c in json.loads((Path(__file__).parent.parent / "data" / "eval" / "cases.json").read_text())}


def test_ai_cannot_lower_rule_priority():
    d = decide(CASES["syn-prompt-injection-username"], ai_severity="low")
    assert d.priority == "high" and d.rule_priority == "high"
    assert any("can't lower" in r for r in d.reasons)
    assert any(p.action == "investigate" for p in d.proposals)
    # the rule proposed a block, but the guard re-checks the IP itself: 203.0.113.50 is a
    # documentation (reserved) address, so it vetoes it despite the "public" label in the data
    assert any("refuse to block '203.0.113.50'" in v and "reserved" in v for v in d.vetoed)


def test_ai_can_raise_priority_but_adds_no_actions():
    d = decide(CASES["real-dns-timeout"], ai_severity="critical")
    assert d.priority == "critical" and d.rule_priority == "low" and d.proposals == []
    assert any("AI raised" in r for r in d.reasons)


def test_no_rule_falls_back_to_wazuh_severity():
    d = decide(CASES["real-4624-service-logon"])
    assert d.priority == "low" and "no rule matched" in d.reasons[0]


def test_loopback_bruteforce_never_produces_block():
    d = decide(CASES["real-60204-bruteforce-loopback"], ai_severity="critical")
    assert all(p.action != "block_ip" for p in d.proposals) and d.vetoed == []


def test_guard_vetoes_are_reported():
    a = CASES["syn-success-after-bruteforce"]
    d = decide(Alert(**{**a.__dict__, "user": "Administrator"}))
    assert any("protected account" in v for v in d.vetoed)
    assert all(p.action != "disable_account" for p in d.proposals)


def test_prefilter():
    assert needs_ai(CASES["syn-bruteforce-public-rdp"], decide(CASES["syn-bruteforce-public-rdp"]))
    assert not needs_ai(CASES["real-sca-failed"], decide(CASES["real-sca-failed"]))
    assert not needs_ai(CASES["real-dns-timeout"], decide(CASES["real-dns-timeout"]))


def test_public_burst_from_own_correlation_proposes_block():
    b = Burst("8.8.8.8", "8.8.8.8", "public", 9, "2026-11-17T19:00:00.000+0000",
              "2026-11-17T19:01:00.000+0000", ["bob"], [], "host")
    d = decide(burst_to_alert(b))
    assert d.priority == "high" and any(p.action == "block_ip" and p.target == "8.8.8.8" for p in d.proposals)


def test_batch_adds_bursts_and_calls_ai_only_when_needed():
    singles = [Alert(f"a{i}", f"2026-11-17T19:43:3{i}.000+0000", "windows_event", "60122", 5, "low", "f",
                     "001", "h", user="u", src_ip="::1", src_ip_scope="loopback", event_id="4625") for i in range(6)]
    calls = []
    results = decide_batch(singles + [CASES["real-dns-timeout"]], analyst=lambda a: calls.append(a.id) or "medium")
    assert len(results) == 8  # 7 alerts + 1 burst
    assert calls == [results[-1][0].id]  # only the medium burst went to the AI


def test_hardening_backlog_groups_and_dedupes_failed_checks():
    f = CASES["real-sca-failed"]
    backlog = hardening_backlog([f, f, CASES["real-sca-passed"], CASES["real-dns-timeout"]])
    [(policy, checks)] = backlog.items()
    assert "CIS" in policy and len(checks) == 1
