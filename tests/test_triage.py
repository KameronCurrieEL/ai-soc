import pytest

from soc.agent.approval import bulk_close
from soc.agent.incidents import Incident
from soc.agent.store import (assign_incident, connect, get_incident, get_proposals, query_incidents, save_incidents)
from soc.decision.models import Proposal


@pytest.fixture
def db(tmp_path):
    conn = connect(tmp_path / "soc.db")
    incs = [
        Incident("brute_force|a@h", "Brute force A", "high", "2026-11-17T10:00:00.000+0000",
                 "2026-11-17T10:01:00.000+0000", ["a1"], [Proposal("investigate", "a", "high", "brute_force", "r")], [], []),
        Incident("new_service|b@h", "New service B", "medium", "2026-11-17T11:00:00.000+0000",
                 "2026-11-17T11:01:00.000+0000", ["a2"], [Proposal("investigate", "b", "medium", "new_service", "r")], [], []),
    ]
    save_incidents(conn, incs)
    return conn, [i.id for i in incs]


def test_query_filters(db):
    conn, _ = db
    assert len(query_incidents(conn, status="open")) == 2
    assert len(query_incidents(conn, priority="high")) == 1
    assert query_incidents(conn, q="new service")[0]["title"] == "New service B"
    assert query_incidents(conn, q="'; DROP TABLE incidents;--") == []        # injection-safe
    assert len(query_incidents(conn, status="open")) == 2                       # table intact


def test_assign_and_filter_by_assignee(db):
    conn, ids = db
    assert assign_incident(conn, ids[0], "dana")
    assert get_incident(conn, ids[0])["assignee"] == "dana"
    assert [r["id"] for r in query_incidents(conn, assignee="dana")] == [ids[0]]
    assign_incident(conn, ids[0], None)
    assert get_incident(conn, ids[0])["assignee"] is None


def test_bulk_close_rejects_pending_then_closes(db):
    conn, ids = db
    res = bulk_close(conn, ids, "dana", "benign", "batch triage: lab noise")
    assert res["closed"] == 2 and not res["errors"]
    assert all(get_incident(conn, i)["status"] == "closed" for i in ids)
    assert all(p["status"] == "rejected" for i in ids for p in get_proposals(conn, i))


def test_bulk_close_requires_verdict(db):
    conn, ids = db
    with pytest.raises(Exception, match="verdict"):
        bulk_close(conn, ids, "dana", "", "note")
