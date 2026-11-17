import re

import pytest

from soc.agent.incidents import Incident
from soc.agent.pipeline import RunStats
from soc.agent.store import audit_entries, connect, get_proposals, save_incidents
from soc.decision.models import Proposal
from soc.web.app import create_app

XSS = "<script>alert(1)</script>"


@pytest.fixture
def env(tmp_path):
    db = tmp_path / "soc.db"
    conn = connect(db)
    inc = Incident("k", f"Brute force {XSS}", "high", "2026-11-17T10:00:00.000+0000", "2026-11-17T10:01:00.000+0000",
                   ["a1"], [Proposal("block_ip", "8.8.8.8", "high", "brute_force", "why"),
                            Proposal("investigate", XSS, "high", "brute_force", "why")], [], [])
    save_incidents(conn, [inc])
    conn.close()
    app = create_app(db, pipeline_runner=lambda c: RunStats(alerts=3, incidents=1, saved={"new": 0}))
    app.config["TESTING"] = True
    return app.test_client(), db, inc.id


def token(client, path="/"):
    html = client.get(path).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def pid(db, inc_id, action):
    return next(p["id"] for p in get_proposals(connect(db), inc_id) if p["action"] == action)


def test_pages_render(env):
    client, _, inc_id = env
    assert client.get("/").status_code == 200
    page = client.get(f"/incident/{inc_id}").get_data(as_text=True)
    assert "New-NetFirewallRule" in page and "Remove-NetFirewallRule" in page  # command + rollback preview
    assert client.get("/audit").status_code == 200
    assert client.get("/incident/INC-nope").status_code == 404


def test_log_data_is_html_escaped(env):
    client, _, inc_id = env
    for path in ("/", f"/incident/{inc_id}"):
        html = client.get(path).get_data(as_text=True)
        assert XSS not in html and "&lt;script&gt;" in html


def test_security_headers(env):
    client, _, _ = env
    h = client.get("/").headers
    assert "frame-ancestors 'none'" in h["Content-Security-Policy"] and h["X-Frame-Options"] == "DENY"
    assert h["X-Content-Type-Options"] == "nosniff"


def test_post_without_or_with_wrong_csrf_token_is_refused(env):
    client, db, inc_id = env
    p = pid(db, inc_id, "block_ip")
    assert client.post(f"/proposal/{p}/approve", data={"by": "kameron"}).status_code == 400
    client.get("/")  # get a session
    assert client.post(f"/proposal/{p}/approve", data={"by": "kameron", "csrf_token": "forged"}).status_code == 400
    assert get_proposals(connect(db), inc_id)[0]["status"] == "proposed"


def test_foreign_host_header_is_refused(env):
    client, _, _ = env
    assert client.get("/", headers={"Host": "evil.example:8765"}).status_code == 400
    assert client.get("/", headers={"Host": "127.0.0.1:8765"}).status_code == 200


def test_approve_then_execute_writes_audit_with_actor(env):
    client, db, inc_id = env
    t = token(client)
    p = pid(db, inc_id, "block_ip")
    r = client.post(f"/proposal/{p}/approve", data={"by": "kameron", "note": "ok", "csrf_token": t}, follow_redirects=True)
    assert "approved" in r.get_data(as_text=True)
    r = client.post(f"/proposal/{p}/execute", data={"by": "kameron", "csrf_token": t}, follow_redirects=True)
    assert "[dry-run]" in r.get_data(as_text=True)
    events = [(e["actor"], e["event"]) for e in audit_entries(connect(db))]
    assert ("kameron", "proposal_executed") in events and ("kameron", "proposal_approved") in events


def test_refusals_are_shown_not_crashes(env):
    client, db, inc_id = env
    t = token(client)
    p = pid(db, inc_id, "block_ip")
    r = client.post(f"/proposal/{p}/execute", data={"by": "kameron", "csrf_token": t}, follow_redirects=True)
    assert r.status_code == 200 and "Refused" in r.get_data(as_text=True)
    r = client.post(f"/proposal/{p}/approve", data={"by": "pipeline", "csrf_token": t}, follow_redirects=True)
    assert "named human" in r.get_data(as_text=True)


def test_refresh_uses_pipeline_runner(env):
    client, _, _ = env
    r = client.post("/run", data={"csrf_token": token(client)}, follow_redirects=True)
    assert "3 alerts" in r.get_data(as_text=True)
