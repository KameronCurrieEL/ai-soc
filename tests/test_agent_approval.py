import sqlite3

import pytest

from soc.agent.approval import ApprovalError, approve, close_incident, reject, run_approved
from soc.agent.incidents import Incident
from soc.agent.store import audit_entries, connect, get_incident, get_proposals, save_incidents
from soc.decision.models import Proposal


@pytest.fixture
def db():
    conn = connect(":memory:")
    inc = Incident("k", "Brute force from 8.8.8.8", "high", "2026-11-17T10:00:00.000+0000",
                   "2026-11-17T10:01:00.000+0000", ["a1"],
                   [Proposal("block_ip", "8.8.8.8", "high", "brute_force", "why"),
                    Proposal("investigate", "bob", "high", "brute_force", "why"),
                    Proposal("disable_account", "bob; Stop-Computer", "high", "x", "why")], [], [])
    save_incidents(conn, [inc])
    return conn, inc.id


def pid(conn, inc_id, action):
    return next(p["id"] for p in get_proposals(conn, inc_id) if p["action"] == action)


def events(conn):
    return [e["event"] for e in reversed(audit_entries(conn))]


def test_happy_path_approve_then_dry_run(db):
    conn, inc_id = db
    p = pid(conn, inc_id, "block_ip")
    approve(conn, p, "kameron", "confirmed external brute force")
    out = run_approved(conn, p, "kameron")
    assert out.startswith("[dry-run]") and "New-NetFirewallRule" in out
    assert events(conn)[-2:] == ["proposal_approved", "proposal_executed"]
    assert audit_entries(conn)[0]["detail"].count("Remove-NetFirewallRule") == 1  # rollback recorded


def test_cannot_run_without_approval(db):
    conn, inc_id = db
    with pytest.raises(ApprovalError, match="only approved"):
        run_approved(conn, pid(conn, inc_id, "block_ip"), "kameron")


def test_cannot_approve_twice_or_approve_rejected(db):
    conn, inc_id = db
    p = pid(conn, inc_id, "block_ip")
    approve(conn, p, "kameron")
    with pytest.raises(ApprovalError, match="expected 'proposed'"):
        approve(conn, p, "someone-else")
    q = pid(conn, inc_id, "investigate")
    reject(conn, q, "kameron", "known test")
    with pytest.raises(ApprovalError):
        approve(conn, q, "kameron")


def test_pipeline_or_anonymous_cannot_approve(db):
    conn, inc_id = db
    for actor in ("", "  ", "pipeline", "PIPELINE"):
        with pytest.raises(ApprovalError, match="named human"):
            approve(conn, pid(conn, inc_id, "block_ip"), actor)


def test_reject_needs_reason(db):
    conn, inc_id = db
    with pytest.raises(ApprovalError, match="reason"):
        reject(conn, pid(conn, inc_id, "block_ip"), "kameron", " ")


def test_unsafe_target_cannot_be_approved_and_refusal_is_audited(db):
    conn, inc_id = db
    p = pid(conn, inc_id, "disable_account")
    with pytest.raises(ApprovalError, match="unsafe"):
        approve(conn, p, "kameron")
    assert events(conn)[-1] == "approval_refused"
    assert next(x for x in get_proposals(conn, inc_id) if x["id"] == p)["status"] == "proposed"


def test_close_incident_requires_all_proposals_resolved(db):
    conn, inc_id = db
    with pytest.raises(ApprovalError, match="still pending"):
        close_incident(conn, inc_id, "kameron", "done")
    for p in get_proposals(conn, inc_id):
        reject(conn, p["id"], "kameron", "lab test")
    close_incident(conn, inc_id, "kameron", "lab test, no real attacker")
    assert get_incident(conn, inc_id)["status"] == "closed"


def test_failed_transition_leaves_no_audit_entry(db):
    conn, inc_id = db
    before = len(audit_entries(conn, limit=1000))
    with pytest.raises(ApprovalError):
        run_approved(conn, pid(conn, inc_id, "block_ip"), "kameron")
    assert len(audit_entries(conn, limit=1000)) == before
