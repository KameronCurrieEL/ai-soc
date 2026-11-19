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


def test_close_in_browser_requires_verdict_and_records_it(env):
    client, db, inc_id = env
    t = token(client, f"/incident/{inc_id}")
    for p in get_proposals(connect(db), inc_id):
        client.post(f"/proposal/{p['id']}/reject", data={"by": "kameron", "reason": "lab", "csrf_token": t})
    r = client.post(f"/incident/{inc_id}/close", data={"by": "kameron", "note": "lab", "csrf_token": t},
                    follow_redirects=True)
    assert "verdict is required" in r.get_data(as_text=True)
    client.post(f"/incident/{inc_id}/close",
                data={"by": "kameron", "note": "lab test", "verdict": "benign", "csrf_token": t})
    closed = [e for e in audit_entries(connect(db)) if e["event"] == "incident_closed"]
    assert len(closed) == 1 and closed[0]["actor"] == "kameron" and '"benign"' in closed[0]["detail"]


def _store_alert(db, alert_id, ip, scope, user, ts="2026-11-17T10:00:30.000+0000"):
    import json as _json
    data = {"id": alert_id, "timestamp": ts, "source": "soc_correlation", "rule_id": "soc-burst",
            "description": "Burst of failed logons", "agent_name": "windows-host", "user": user,
            "src_ip": ip, "src_ip_scope": scope, "mitre_ids": ["T1110"], "related_count": 12,
            "details": {"host": "WIN-LAB01"}}
    conn = connect(db)
    with conn:
        conn.execute("INSERT INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                     (alert_id, ts, "soc_correlation", "soc-burst", "high", data["description"], "windows-host",
                      user, ip, _json.dumps(data), "{}"))


def _incident(db, key, ip_alert_id):
    inc = Incident(key, "Brute force", "high", "2026-11-17T10:00:00.000+0000", "2026-11-17T10:01:00.000+0000",
                   [ip_alert_id], [Proposal("investigate", "x", "high", "brute_force", "why")], [], [])
    save_incidents(connect(db), [inc])
    return inc.id


def test_incident_page_shows_summary_location_timeline(env, monkeypatch):
    from soc.enrich import geoip
    monkeypatch.setattr(geoip, "default_db", lambda: geoip.GeoDB([("8.8.8.0", "8.8.8.255", "US")]))
    client, db, _ = env
    _store_alert(db, "b1", "8.8.8.8", "public", XSS)
    inc_id = _incident(db, "brute_force|8.8.8.8@windows-host", "b1")
    page = client.get(f"/incident/{inc_id}").get_data(as_text=True)
    assert "United States (US)" in page and "DB-IP" in page              # location + required attribution
    assert "blocking that address is proposed" in page                     # plain-English summary
    assert "Incident opened by the pipeline" in page and "WIN-LAB01" in page   # timeline + host
    assert XSS not in page and "&lt;script&gt;" in page                    # username from logs escaped


def test_old_incident_without_stored_alerts_falls_back_to_key(env, monkeypatch):
    from soc.enrich import geoip
    monkeypatch.setattr(geoip, "default_db", lambda: pytest.fail("no public IP: database must not load"))
    client, db, _ = env
    inc_id = _incident(db, "brute_force|::1@windows-host", "never-stored")
    page = client.get(f"/incident/{inc_id}").get_data(as_text=True)
    assert "This computer (windows-host)" in page and "weren't stored" in page
    assert "DB-IP" not in page


def test_entity_page_pivots_from_ip_to_accounts_and_incidents(env, monkeypatch):
    from soc.enrich import geoip
    monkeypatch.setattr(geoip, "default_db", lambda: geoip.GeoDB([("8.8.8.0", "8.8.8.255", "US")]))
    client, db, _ = env
    _store_alert(db, "b1", "8.8.8.8", "public", "admin")
    _store_alert(db, "b2", "8.8.8.8", "public", "backup", ts="2026-11-17T10:00:40.000+0000")
    inc_id = _incident(db, "brute_force|8.8.8.8@windows-host", "b1")
    monkeypatch.setattr("soc.agent.store.recent_alerts",
                        lambda conn, hours=24: conn.execute("SELECT * FROM alerts ORDER BY timestamp").fetchall())
    page = client.get("/entity?type=ip&value=8.8.8.8").get_data(as_text=True)
    assert "United States (US)" in page and inc_id in page and "2 stored alert(s)" in page
    assert "/entity?type=user&amp;value=admin" in page and "/entity?type=user&amp;value=backup" in page
    # and the incident page links into the pivot
    assert "/entity?type=ip&amp;value=8.8.8.8" in client.get(f"/incident/{inc_id}").get_data(as_text=True)


def test_entity_page_finds_old_incident_by_key_and_encodes_ipv6(env):
    client, db, _ = env
    inc_id = _incident(db, "brute_force|::1@windows-host", "never-stored")
    page = client.get("/entity?type=ip&value=::1").get_data(as_text=True)
    assert inc_id in page and "This computer (windows-host)" in page
    # the link on the incident page round-trips (IPv6 colons survive URL encoding)
    import html
    href = re.search(r'href="(/entity\?type=ip[^"]+)"', client.get(f"/incident/{inc_id}").get_data(as_text=True)).group(1)
    assert inc_id in client.get(html.unescape(href)).get_data(as_text=True)


def test_entity_page_rejects_bad_input_and_escapes_value(env):
    client, _, _ = env
    assert client.get("/entity?type=bogus&value=x").status_code == 404
    assert client.get("/entity?type=ip").status_code == 404
    page = client.get("/entity", query_string={"type": "user", "value": XSS}).get_data(as_text=True)
    assert XSS not in page and "&lt;script&gt;" in page


def test_index_shows_activity_chart_without_inline_styles(env):
    client, db, _ = env
    from datetime import datetime, timedelta, timezone
    from soc.agent.store import wazuh_ts
    _store_alert(db, "c1", "::1", "loopback", "u", ts=wazuh_ts(datetime.now(timezone.utc) - timedelta(minutes=5)))
    page = client.get("/").get_data(as_text=True)
    assert "Alerts, last 24 hours" in page and 'class="seg-high"' in page and "1 alert (1 high)" in page
    assert "style=" not in page            # CSP default-src 'self' would block inline styles
