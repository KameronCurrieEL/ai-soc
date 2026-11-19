import pytest

from soc.agent.approval import run_autopilot
from soc.agent.incidents import Incident
from soc.agent.store import add_agent_proposals, audit_entries, connect, get_proposals, save_incidents
from soc.decision.models import Proposal


@pytest.fixture
def db(tmp_path):
    return connect(tmp_path / "soc.db")


def crit_incident(db, props):
    inc = Incident("success_after_brute_force|8.8.8.8@h", "Compromise", "critical",
                   "2026-11-17T10:00:00.000+0000", "2026-11-17T10:01:00.000+0000", ["a1"], props, [], [])
    save_incidents(db, [inc])
    return inc.id


def test_autopilot_executes_rule_critical_system_actions_only(db):
    inc_id = crit_incident(db, [
        Proposal("isolate_host", "winhost", "critical", "success_after_brute_force", "compromised"),
        Proposal("block_ip", "8.8.8.8", "critical", "success_after_brute_force", "attacker ip"),
        Proposal("investigate", "admin", "critical", "success_after_brute_force", "check"),   # not system-changing
    ])
    acted = run_autopilot(db, dry_run=True)
    done = {a["action"] for a in acted}
    assert done == {"isolate_host", "block_ip"}                       # investigate left for a human
    statuses = {p["action"]: p["status"] for p in get_proposals(db, inc_id)}
    assert statuses["isolate_host"] == "executed" and statuses["block_ip"] == "executed"
    assert statuses["investigate"] == "proposed"
    events = [(e["actor"], e["event"]) for e in audit_entries(db)]
    assert ("autopilot", "autopilot_engaged") in events
    assert ("autopilot", "proposal_executed") in events and ("autopilot", "proposal_approved") in events


def test_autopilot_ignores_ai_suggested_and_non_critical(db):
    inc_id = crit_incident(db, [Proposal("investigate", "x", "critical", "success_after_brute_force", "r")])
    # an AI-suggested critical action must NOT be auto-run (source='agent')
    add_agent_proposals(db, inc_id, [Proposal("block_ip", "9.9.9.9", "critical", "ai_responder", "ai says so")])
    acted = run_autopilot(db, dry_run=True)
    assert acted == []
    assert all(p["status"] == "proposed" for p in get_proposals(db, inc_id))


def test_autopilot_skips_unsafe_target_and_audits_refusal(db):
    # a (hypothetical) rule-critical block on a loopback IP: validation refuses it, nothing runs
    inc_id = crit_incident(db, [Proposal("block_ip", "127.0.0.1", "critical", "success_after_brute_force", "bad")])
    # guards would normally stop this at creation; force it in to prove the autopilot safety net
    db.execute("UPDATE proposals SET priority='critical', source='rule'")
    db.commit()
    acted = run_autopilot(db, dry_run=True)
    assert acted == []
    assert [e for e in audit_entries(db) if e["event"] == "approval_refused" and e["actor"] == "autopilot"]
