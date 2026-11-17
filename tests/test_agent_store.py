import sqlite3

import pytest

from soc.agent.incidents import Incident
from soc.agent.store import (audit, audit_entries, connect, get_proposals, list_incidents, save_incidents)
from soc.decision.models import Proposal


def inc(first="2026-11-17T19:45:53.000+0000", last="2026-11-17T19:46:11.000+0000", alerts=("a1",),
        priority="medium", props=(("investigate", "labuser"),)):
    return Incident("brute_force|::1@host", "Brute force from ::1", priority, first, last, list(alerts),
                    [Proposal(a, t, priority, "brute_force", "why") for a, t in props], ["r1"], [])


@pytest.fixture
def db():
    return connect(":memory:")


def test_new_incident_and_proposal_are_saved_and_audited(db):
    assert save_incidents(db, [inc()]) == {"new": 1, "updated": 0, "new_proposals": 1}
    [row] = list_incidents(db)
    assert row["title"] == "Brute force from ::1" and row["status"] == "open"
    [p] = get_proposals(db, row["id"])
    assert (p["action"], p["target"], p["status"]) == ("investigate", "labuser", "proposed")
    assert [e["event"] for e in audit_entries(db)] == ["proposal_created", "incident_created"]


def test_rerun_is_idempotent(db):
    save_incidents(db, [inc()])
    assert save_incidents(db, [inc()]) == {"new": 0, "updated": 0, "new_proposals": 0}
    assert len(list_incidents(db)) == 1 and len(audit_entries(db)) == 2


def test_shifted_window_merges_into_existing_incident(db):
    save_incidents(db, [inc()])
    later = inc(first="2026-11-17T19:50:00.000+0000", last="2026-11-17T19:55:00.000+0000", alerts=("a2",),
                priority="high", props=(("investigate", "labuser"), ("block_ip", "8.8.8.8")))
    assert save_incidents(db, [later]) == {"new": 0, "updated": 1, "new_proposals": 1}
    [row] = list_incidents(db)
    assert row["priority"] == "high" and row["last_seen"].startswith("2026-11-17T19:55")
    assert "incident_escalated" in [e["event"] for e in audit_entries(db)]


def test_much_later_activity_is_a_new_incident(db):
    save_incidents(db, [inc()])
    save_incidents(db, [inc(first="2026-11-18T09:00:00.000+0000", last="2026-11-18T09:01:00.000+0000")])
    assert len(list_incidents(db)) == 2


def test_audit_log_cannot_be_changed_or_deleted(db):
    audit(db, "tester", "something", note="x")
    db.commit()
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        db.execute("UPDATE audit_log SET actor = 'attacker'")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        db.execute("DELETE FROM audit_log")
    assert audit_entries(db)[0]["actor"] == "tester"


def test_list_orders_by_priority(db):
    a = inc()
    b = Incident("agent|host", "Agent stopped", "high", a.first_seen, a.last_seen, ["x"],
                 [Proposal("investigate", "host", "high", "security_agent_stopped", "why")], [], [])
    save_incidents(db, [a, b])
    assert [r["priority"] for r in list_incidents(db)] == ["high", "medium"]
