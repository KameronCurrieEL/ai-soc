import re

import pytest

from soc.agent.incidents import Incident
from soc.agent.pipeline import RunStats
from soc.agent.store import audit_entries, connect, create_user, get_proposals, save_incidents
from soc.decision.models import Proposal
from soc.web.app import create_app
from soc.web.auth import hash_password

XSS = "<script>alert(1)</script>"


class FakeLLM:
    """Stands in for Ollama: records what it was sent, streams a canned answer."""
    name = "fake-model"
    sent: list = []
    answer = ["Looks like ", "a local test. ", XSS]

    def stream(self, messages):
        FakeLLM.sent.append(messages)
        yield from FakeLLM.answer


class FakeResponder:
    """Stands in for the agent brain: returns a fixed JSON assessment + suggested actions."""
    name = "fake-responder"
    reply = None  # set per test

    def _reply(self):
        import json as _json
        return FakeResponder.reply or _json.dumps({
            "assessment": "Looks like a real brute force.", "confidence": "high",
            "attacker_next_steps": [{"technique": "T1110", "step": "keep trying", "watch_for": "a 4624 success"}],
            "actions": [{"action": "block_ip", "target": "8.8.8.8", "urgency": "immediate", "reason": "public source"},
                        {"action": "isolate_host", "target": "windows-host", "urgency": "soon", "reason": "contain"}],
        })

    def complete(self, system, user, schema=None):
        return self._reply()

    def stream(self, messages, num_ctx=4096, fmt=None):
        text = self._reply()
        for i in range(0, len(text), 20):   # emit in chunks, like Ollama streaming
            yield text[i:i + 20]


def make_client(db, role="analyst", name="kameron", login=True, tenant="default"):
    """A test client, logged in as `role` unless login=False. Seeds the user if needed."""
    conn = connect(db)
    if not conn.execute("SELECT 1 FROM users WHERE username = ?", (name,)).fetchone():
        create_user(conn, name, hash_password("pw-" + name), role, tenant)
    conn.close()
    app = create_app(db, pipeline_runner=lambda c: RunStats(alerts=3, incidents=1, saved={"new": 0}),
                     llm_factory=FakeLLM, responder_factory=FakeResponder,
                     ai_status=lambda: (True, "fake-model online"))
    app.config["TESTING"] = True
    client = app.test_client()
    if login:
        t = re.search(r'name="csrf_token" value="([^"]+)"', client.get("/login").get_data(as_text=True)).group(1)
        client.post("/login", data={"username": name, "password": "pw-" + name, "csrf_token": t})
    return client


@pytest.fixture
def env(tmp_path):
    db = tmp_path / "soc.db"
    conn = connect(db)
    inc = Incident("k", f"Brute force {XSS}", "high", "2026-11-17T10:00:00.000+0000", "2026-11-17T10:01:00.000+0000",
                   ["a1"], [Proposal("block_ip", "8.8.8.8", "high", "brute_force", "why"),
                            Proposal("investigate", XSS, "high", "brute_force", "why")], [], [])
    save_incidents(conn, [inc])
    conn.close()
    return make_client(db, role="analyst"), db, inc.id


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
    assert client.get("/", headers={"Host": "localhost:8765"}).status_code == 200   # allowed host, session valid


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
    # executing a proposal that isn't approved yet is refused and shown, not a crash
    r = client.post(f"/proposal/{p}/execute", data={"csrf_token": t}, follow_redirects=True)
    assert r.status_code == 200 and "Refused" in r.get_data(as_text=True)


def test_viewer_cannot_act_but_can_read(tmp_path):
    from soc.agent.store import connect, save_incidents
    db = tmp_path / "soc.db"
    conn = connect(db)
    inc = Incident("k", "Brute force", "high", "2026-11-17T10:00:00.000+0000", "2026-11-17T10:01:00.000+0000",
                   ["a1"], [Proposal("block_ip", "8.8.8.8", "high", "brute_force", "why")], [], [])
    save_incidents(conn, [inc]); conn.close()
    viewer = make_client(db, role="viewer", name="val")
    assert viewer.get(f"/incident/{inc.id}").status_code == 200          # read: allowed
    t = token(viewer, f"/incident/{inc.id}")
    p = next(x["id"] for x in get_proposals(connect(db), inc.id) if x["action"] == "block_ip")
    assert viewer.post(f"/proposal/{p}/approve", data={"csrf_token": t}).status_code == 403   # act: forbidden
    assert viewer.post("/run", data={"csrf_token": t}).status_code == 403
    assert viewer.get("/users").status_code == 403                        # admin-only


def test_login_required_and_actor_is_session_user(tmp_path):
    from soc.agent.store import audit_entries, connect, save_incidents
    db = tmp_path / "soc.db"
    conn = connect(db)
    inc = Incident("k", "Brute force", "high", "2026-11-17T10:00:00.000+0000", "2026-11-17T10:01:00.000+0000",
                   ["a1"], [Proposal("block_ip", "8.8.8.8", "high", "brute_force", "why")], [], [])
    save_incidents(conn, [inc]); conn.close()
    anon = make_client(db, login=False)
    assert anon.get("/").status_code == 302 and anon.get("/api/alerts.json").status_code == 401
    analyst = make_client(db, role="analyst", name="dana")
    t = token(analyst, f"/incident/{inc.id}")
    p = next(x["id"] for x in get_proposals(connect(db), inc.id) if x["action"] == "block_ip")
    # even if the form tries to spoof 'by', the audit actor is the logged-in user
    analyst.post(f"/proposal/{p}/approve", data={"by": "someone-else", "csrf_token": t})
    actors = [e["actor"] for e in audit_entries(connect(db)) if e["event"] == "proposal_approved"]
    assert actors == ["dana"]


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


def _store_alert(db, alert_id, ip, scope, user, ts="2026-11-17T10:00:30.000+0000", sensor="wazuh-lab"):
    import json as _json
    data = {"id": alert_id, "timestamp": ts, "source": "soc_correlation", "rule_id": "soc-burst",
            "description": "Burst of failed logons", "agent_name": "windows-host", "user": user,
            "src_ip": ip, "src_ip_scope": scope, "mitre_ids": ["T1110"], "related_count": 12,
            "sensor": sensor, "details": {"host": "WIN-LAB01"}}
    conn = connect(db)
    with conn:
        conn.execute("INSERT INTO alerts (id, timestamp, source, rule_id, priority, description, agent_name, "
                     "user, src_ip, sensor, data, decision) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                     (alert_id, ts, "soc_correlation", "soc-burst", "high", data["description"], "windows-host",
                      user, ip, sensor, _json.dumps(data), "{}"))


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


def test_metrics_page_counts_verdicts(env):
    client, db, inc_id = env
    t = token(client)
    for p in get_proposals(connect(db), inc_id):
        client.post(f"/proposal/{p['id']}/reject", data={"by": "kameron", "reason": "lab", "csrf_token": t})
    client.post(f"/incident/{inc_id}/close", data={"by": "kameron", "note": "rule fired on my test",
                                                   "verdict": "false_positive", "csrf_token": t})
    page = client.get("/metrics").get_data(as_text=True)
    assert "Detection quality" in page and "100%" in page and "<code>k</code>" in page


# ---------- AI assistant ----------

def test_assistant_streams_answer_stores_chat_and_changes_nothing(env):
    client, db, inc_id = env
    FakeLLM.sent.clear()
    before = [(p["id"], p["status"]) for p in get_proposals(connect(db), inc_id)]
    t = token(client, f"/incident/{inc_id}")
    r = client.post(f"/assistant/{inc_id}/ask", data={"question": "Is this malicious?", "csrf_token": t},
                    headers={"X-Stream": "1"})
    assert r.status_code == 200 and r.mimetype == "text/plain"
    assert r.get_data(as_text=True) == "Looks like a local test. " + XSS          # streamed as plain text
    # the model saw the incident facts inside the untrusted-data block, plus the question
    user_msg = FakeLLM.sent[-1][-1]["content"]
    assert user_msg.startswith("<soc_data>") and inc_id in user_msg and "Is this malicious?" in user_msg
    assert "cannot approve" in FakeLLM.sent[-1][0]["content"]
    # both turns are stored and shown, escaped
    page = client.get(f"/incident/{inc_id}").get_data(as_text=True)
    assert "Is this malicious?" in page and "a local test." in page and XSS not in page
    # asking the AI never changes proposals or the audit log
    assert [(p["id"], p["status"]) for p in get_proposals(connect(db), inc_id)] == before
    assert not [e for e in audit_entries(connect(db)) if "assistant" in e["event"] or e["actor"] == "fake-model"]


def test_assistant_works_without_javascript_and_from_suggestion_button(env):
    client, db, inc_id = env
    t = token(client, f"/incident/{inc_id}")
    # textarea empty + suggestion button value: both are named "question"
    r = client.post(f"/assistant/{inc_id}/ask", data={"question": ["", "What should I check before approving?"],
                                                     "csrf_token": t})
    assert r.status_code == 302 and r.headers["Location"].endswith("#assistant")
    page = client.get(f"/incident/{inc_id}").get_data(as_text=True)
    assert "What should I check before approving?" in page and "Looks like" in page


def test_assistant_overview_scope_and_history_is_sent_back(env):
    client, _, inc_id = env
    FakeLLM.sent.clear()
    t = token(client)
    client.post("/assistant/overview/ask", data={"question": "first", "csrf_token": t}, headers={"X-Stream": "1"}).get_data()
    client.post("/assistant/overview/ask", data={"question": "second", "csrf_token": t}, headers={"X-Stream": "1"}).get_data()
    last = FakeLLM.sent[-1]
    assert [m["role"] for m in last] == ["system", "user", "assistant", "user"]   # earlier turn included
    assert inc_id in last[-1]["content"] and "Open incidents: 1" in last[-1]["content"]


def test_assistant_rejects_bad_input(env):
    client, _, _ = env
    t = token(client)
    assert client.post("/assistant/overview/ask", data={"question": "hi"}).status_code == 400          # no CSRF token
    assert client.post("/assistant/INC-nope/ask", data={"question": "hi", "csrf_token": t}).status_code == 404
    r = client.post("/assistant/overview/ask", data={"question": "  ", "csrf_token": t}, headers={"X-Stream": "1"})
    assert r.status_code == 400


def test_assistant_failure_is_reported_and_not_stored(env, monkeypatch):
    client, db, _ = env

    def broken(self, messages):
        raise ConnectionError("Ollama unreachable")
        yield  # pragma: no cover

    monkeypatch.setattr(FakeLLM, "stream", broken)
    t = token(client)
    body = client.post("/assistant/overview/ask", data={"question": "hi", "csrf_token": t},
                       headers={"X-Stream": "1"}).get_data(as_text=True)
    assert "[assistant unavailable: Ollama unreachable]" in body
    from soc.agent.store import chat_history
    assert [m["role"] for m in chat_history(connect(db), "overview")] == ["user"]


def test_pages_show_ai_status_and_load_only_same_origin_script(env):
    client, _, _ = env
    page = client.get("/").get_data(as_text=True)
    assert "fake-model online" in page and 'src="/static/assistant.js"' in page
    assert "<script>" not in page and "style=" not in page        # no inline script/style: CSP stays strict


# ---------- responder agent + autopilot ----------

def _public_incident(db):
    inc = Incident("brute_force|8.8.8.8@windows-host", "Brute force from 8.8.8.8", "high",
                   "2026-11-17T10:00:00.000+0000", "2026-11-17T10:01:00.000+0000", ["a1"],
                   [Proposal("block_ip", "8.8.8.8", "high", "brute_force", "public brute force")], [], [])
    save_incidents(connect(db), [inc])
    return inc.id


def test_responder_adds_vetted_proposals_and_stores_assessment(env):
    client, db, _ = env
    inc_id = _public_incident(db)
    t = token(client, f"/incident/{inc_id}")
    r = client.post(f"/incident/{inc_id}/respond", data={"by": "kameron", "csrf_token": t}, follow_redirects=True)
    page = r.get_data(as_text=True)
    assert "Looks like a real brute force." in page and "keep trying" in page and "a 4624 success" in page
    # the AI's block_ip (8.8.8.8 is in the incident) became an agent proposal, source=agent
    agent = [p for p in get_proposals(connect(db), inc_id) if p["source"] == "agent"]
    # block_ip 8.8.8.8 already exists as a RULE proposal (deduped); the new isolate_host is added as agent
    assert any(p["action"] == "isolate_host" and p["target"] == "windows-host" for p in agent)
    # asking the responder is logged, but it approved/executed nothing
    events = [(e["actor"], e["event"]) for e in audit_entries(connect(db))]
    assert ("ai_responder", "agent_assessed") in events
    assert not any(ev in ("proposal_approved", "proposal_executed") for _, ev in events)


def test_responder_blocks_invented_and_unsafe_targets(env):
    import json as _json
    client, db, _ = env
    inc_id = _public_incident(db)
    FakeResponder.reply = _json.dumps({
        "assessment": "x", "confidence": "low", "attacker_next_steps": [],
        "actions": [{"action": "block_ip", "target": "203.0.113.200", "urgency": "soon", "reason": "not in incident"},
                    {"action": "disable_account", "target": "administrator", "urgency": "soon", "reason": "protected"}]})
    t = token(client, f"/incident/{inc_id}")
    client.post(f"/incident/{inc_id}/respond", data={"by": "kameron", "csrf_token": t})
    FakeResponder.reply = None
    assert [p for p in get_proposals(connect(db), inc_id) if p["source"] == "agent"] == []  # both rejected


def test_autopilot_toggle_persists_and_is_audited(env):
    client, db, _ = env
    t = token(client)
    assert "Autopilot off" in client.get("/").get_data(as_text=True)
    client.post("/autopilot", data={"enabled": "on", "by": "kameron", "csrf_token": t})
    from soc.agent.store import get_setting
    assert get_setting(connect(db), "autopilot") == "on"
    page = client.get("/").get_data(as_text=True)
    assert "Autopilot is ON" in page and "Autopilot ON" in page
    assert ("kameron", "autopilot_enabled") in [(e["actor"], e["event"]) for e in audit_entries(connect(db))]
    client.post("/autopilot", data={"enabled": "off", "by": "kameron", "csrf_token": t})
    assert get_setting(connect(db), "autopilot") == "off"


def test_overview_dashboard_renders_kpis_and_severity(env):
    client, db, inc_id = env
    from datetime import datetime, timedelta, timezone
    from soc.agent.store import wazuh_ts
    _store_alert(db, "o1", "8.8.8.8", "public", "admin", ts=wazuh_ts(datetime.now(timezone.utc) - timedelta(minutes=5)))
    page = client.get("/").get_data(as_text=True)
    assert "Security overview" in page
    for kpi in ("Pending approval", "Open incidents", "Median time to close", "Autopilot (24h)"):
        assert kpi in page
    assert "Open incidents by severity" in page and 'class="fill-high"' in page   # the fixture incident is high
    assert "Top source IPs" in page and "8.8.8.8" in page                          # entity ranking
    assert "/incident/" + inc_id in page                                           # recent incidents link
    assert "style=" not in page                                                     # CSP stays strict


def test_queue_moved_to_its_own_route(env):
    client, _, _ = env
    assert client.get("/queue").status_code == 200
    assert "AI assistant" in client.get("/queue").get_data(as_text=True)   # assistant lives on the queue page


# ---------- live alert feed (step B1) ----------

def test_alert_feed_page_and_json_api(env):
    client, db, _ = env
    from datetime import datetime, timedelta, timezone
    from soc.agent.store import wazuh_ts
    now = datetime.now(timezone.utc)
    _store_alert(db, "f1", "8.8.8.8", "public", "admin", ts=wazuh_ts(now - timedelta(minutes=2)))
    _store_alert(db, "f2", "::1", "loopback", "soc-test-user", ts=wazuh_ts(now - timedelta(minutes=1)))
    page = client.get("/alerts").get_data(as_text=True)
    assert "Live alerts" in page and 'id="feed-body"' in page and 'src="/static/live.js"' in page
    assert "8.8.8.8" in page and "soc-test-user" in page
    data = client.get("/api/alerts.json").get_json()
    assert "generated" in data and len(data["alerts"]) == 2
    assert data["alerts"][0]["id"] == "f2"            # newest first
    assert {"id", "ts", "priority", "rule_id", "src_ip", "scope"} <= set(data["alerts"][0])


def test_feed_filters_are_injection_safe_and_work(env):
    client, db, _ = env
    _store_alert(db, "g1", "8.8.8.8", "public", "admin")
    _store_alert(db, "g2", "::1", "loopback", "bob")
    # priority filter
    hi = client.get("/api/alerts.json?priority=high").get_json()["alerts"]
    assert hi and all(a["priority"] == "high" for a in hi)
    # text search (parameterized LIKE): a SQLi-looking string just matches nothing, never errors
    assert client.get("/api/alerts.json", query_string={"q": "'; DROP TABLE alerts;--"}).get_json()["alerts"] == []
    from soc.agent.store import connect as _c
    assert _c(db).execute("SELECT COUNT(*) n FROM alerts").fetchone()["n"] == 2   # table intact
    assert len(client.get("/api/alerts.json", query_string={"q": "bob"}).get_json()["alerts"]) == 1


def test_feed_api_escapes_in_page_not_in_json(env):
    client, db, _ = env
    _store_alert(db, "x1", "8.8.8.8", "public", XSS)
    assert XSS not in client.get("/alerts").get_data(as_text=True)      # HTML page autoescapes
    assert XSS in client.get("/api/alerts.json").get_json()["alerts"][0]["user"]   # JSON carries raw; JS uses textContent


def test_feed_filters_by_sensor_and_overview_lists_sources(env):
    client, db, _ = env
    from datetime import datetime, timedelta, timezone
    from soc.agent.store import wazuh_ts
    now = datetime.now(timezone.utc)
    _store_alert(db, "s1", "8.8.8.8", "public", "a", ts=wazuh_ts(now - timedelta(minutes=3)), sensor="wazuh-lab")
    _store_alert(db, "s2", "9.9.9.9", "public", "b", ts=wazuh_ts(now - timedelta(minutes=2)), sensor="wazuh-branch2")
    feed = client.get("/alerts").get_data(as_text=True)
    assert "wazuh-branch2" in feed and 'name="sensor"' in feed          # sensor shown + filter dropdown
    only = client.get("/api/alerts.json?sensor=wazuh-branch2").get_json()["alerts"]
    assert only and all(a["sensor"] == "wazuh-branch2" for a in only)
    ov = client.get("/").get_data(as_text=True)
    assert "Sources" in ov and "wazuh-branch2" in ov                     # overview Sources card


def test_responder_streaming_saves_assessment_and_proposals(env):
    client, db, _ = env
    inc_id = _public_incident(db)       # key has @windows-host, so that host is a valid target
    t = token(client, f"/incident/{inc_id}")
    r = client.post(f"/incident/{inc_id}/respond", data={"csrf_token": t}, headers={"X-Stream": "1"})
    assert r.status_code == 200 and r.mimetype == "text/plain"
    body = r.get_data(as_text=True)
    assert "Looks like a real brute force" in body          # the model output streamed through
    assert "\u0004OK" in body                                # completion sentinel for the JS
    # after the stream, the assessment is stored and the vetted action became an agent proposal
    from soc.agent.store import latest_assessment
    a = latest_assessment(connect(db), inc_id)
    assert a and a["confidence"] == "high"
    agent = [p for p in get_proposals(connect(db), inc_id) if p["source"] == "agent"]
    assert any(p["action"] == "isolate_host" for p in agent)


def test_responder_stream_still_requires_analyst(tmp_path):
    from soc.agent.store import connect, save_incidents
    db = tmp_path / "soc.db"
    conn = connect(db)
    inc = Incident("k", "BF", "high", "2026-11-17T10:00:00.000+0000", "2026-11-17T10:01:00.000+0000",
                   ["a1"], [Proposal("investigate", "x", "high", "brute_force", "why")], [], [])
    save_incidents(conn, [inc]); conn.close()
    viewer = make_client(db, role="viewer", name="val")
    t = token(viewer, f"/incident/{inc.id}")
    assert viewer.post(f"/incident/{inc.id}/respond", data={"csrf_token": t}, headers={"X-Stream": "1"}).status_code == 403


def test_overview_json_api_returns_kpis_and_counts(env):
    client, db, _ = env
    data = client.get("/api/overview.json").get_json()
    assert "generated" in data
    assert set(data["kpis"]) == {"pending", "open", "alerts_24h", "autopilot_24h"}
    assert set(data["counts"]) == {"critical", "high", "medium", "low"}
    assert data["kpis"]["open"] >= 1 and data["counts"]["high"] >= 1   # fixture has one open high incident
    # overview page wires the live updater + data hooks
    page = client.get("/").get_data(as_text=True)
    assert 'data-kpi="pending"' in page and 'data-sev="high"' in page and 'src="/static/overview.js"' in page


def test_overview_json_requires_login(tmp_path):
    db = tmp_path / "soc.db"
    anon = make_client(db, login=False)
    assert anon.get("/api/overview.json").status_code == 401
