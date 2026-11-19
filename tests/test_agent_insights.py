import json
from datetime import datetime, timezone

from soc.agent.insights import activity, entities, matches_entity, parse_any_time, pivot, plain_summary, timeline


def row(i, ts, prio="medium", desc="Logon Failure", ip="::1", scope="loopback", user="soc-test-user", **extra):
    data = {"id": f"a{i}", "timestamp": ts, "source": "windows_event", "rule_id": "60122", "description": desc,
            "agent_name": "windows-host", "user": user, "src_ip": ip, "src_ip_scope": scope,
            "mitre_ids": ["T1110"], "related_count": 0,
            "details": {"host": "WIN-LAB01", "requested_by": "labuser", "process": "C:\\svchost.exe",
                        "failure_reason": "0xc0000064 user does not exist"}, **extra}
    return {"id": f"a{i}", "timestamp": ts, "priority": prio, "data": json.dumps(data)}


def aud(at, actor, event, **detail):
    return {"at": at, "actor": actor, "event": event, "detail": json.dumps(detail)}


T = "2026-11-17T19:4{}:00.000+0000"


def test_parse_both_time_formats():
    assert parse_any_time("2026-11-17T19:43:36.260+0000") == parse_any_time("2026-11-17T19:43:36.260+00:00")


def test_entities_counted_with_ip_scope():
    e = entities([row(1, T.format(3)), row(2, T.format(4)), row(3, T.format(5), ip="8.8.8.8", scope="public")])
    assert [(x.value, x.count, x.note) for x in e["ip"]] == [("::1", 2, "loopback"), ("8.8.8.8", 1, "public")]
    assert e["user"][0].value == "soc-test-user" and e["requester"][0].value == "labuser"
    assert e["technique"][0].value == "T1110"


def test_matches_entity():
    a = json.loads(row(1, T.format(3))["data"])
    assert matches_entity(a, "ip", "::1") and matches_entity(a, "technique", "T1110")
    assert not matches_entity(a, "ip", "8.8.8.8") and not matches_entity(a, "bogus", "x")


def test_timeline_collapses_repeats_and_interleaves_audit():
    alerts = [row(i, f"2026-11-17T19:43:{10 + i:02d}.000+0000") for i in range(5)]
    alerts.append(row(9, "2026-11-17T19:46:00.000+0000", prio="high", desc="Multiple Windows Logon Failures"))
    audits = [aud("2026-11-17T20:00:00+00:00", "pipeline", "incident_created", title="x"),
              aud("2026-11-17T20:05:00+00:00", "kameron", "incident_closed", verdict="benign", note="test")]
    items = timeline(alerts, audits)
    assert [(i.kind, i.count) for i in items] == [("alert", 5), ("alert", 1), ("pipeline", 1), ("human", 1)]
    assert items[0].until is not None and "user does not exist" in items[0].detail
    assert items[-1].title == "Incident closed" and "verdict: benign" in items[-1].detail


def test_plain_summary_brute_force_local_and_public():
    inc = {"key": "brute_force|::1@windows-host", "title": "Brute force from ::1",
           "first_seen": "2026-11-17T19:43:36.000+0000", "last_seen": "2026-11-17T19:46:13.000+0000"}
    s = plain_summary(inc, [row(1, T.format(3), related_count=27)])
    assert "about 27 times" in s and "nothing gets blocked" in s and "labuser" in s and "19:43 and 19:46" in s
    pub = plain_summary({**inc, "key": "brute_force|8.8.8.8@h"}, [row(1, T.format(3), ip="8.8.8.8", scope="public")])
    assert "blocking that address is proposed" in pub


def test_plain_summary_agent_stopped():
    inc = {"key": "security_agent_stopped|windows-host@windows-host", "title": "t",
           "first_seen": "2026-11-17T19:41:09.000+0000", "last_seen": "2026-11-17T19:41:09.000+0000"}
    s = plain_summary(inc, [row(1, "2026-11-17T19:41:09.000+0000")])
    assert "stopped at 19:41 UTC" in s and "planned restart" in s


def test_activity_buckets():
    now = datetime(2026, 11, 17, 20, 30, tzinfo=timezone.utc)
    b = activity([row(1, "2026-11-17T19:43:00.000+0000"), row(2, "2026-11-17T19:59:00.000+0000", prio="high"),
                  row(3, "2026-11-16T10:00:00.000+0000")], hours=24, now=now)
    assert len(b) == 24 and b[-2].counts["medium"] == 1 and b[-2].counts["high"] == 1 and b[-2].total == 2
    assert sum(x.total for x in b) == 2  # the old one is outside the window


def inc_row(inc_id, key, alert_ids):
    return {"id": inc_id, "key": key, "alert_ids": json.dumps(alert_ids)}


def test_pivot_on_ip_finds_alerts_incidents_and_co_occurring_accounts():
    alerts = [row(1, T.format(3), ip="8.8.8.8", scope="public", user="admin"),
              row(2, T.format(4), ip="8.8.8.8", scope="public", user="backup"),
              row(3, T.format(5), ip="::1", user="soc-test-user")]
    incs = [inc_row("INC-a", "brute_force|8.8.8.8@windows-host", ["a1", "a2"]),
            inc_row("INC-b", "brute_force|::1@windows-host", ["a3"])]
    p = pivot("ip", "8.8.8.8", alerts, incs)
    assert [r["id"] for r in p.alerts] == ["a1", "a2"]
    assert [i["id"] for i in p.incidents] == ["INC-a"]
    assert sorted(e.value for e in p.related["user"]) == ["admin", "backup"]   # which accounts this IP tried
    assert "ip" not in p.related                                               # itself is not "related"


def test_pivot_falls_back_to_incident_key_when_alerts_not_stored():
    old = inc_row("INC-old", "brute_force|::1@windows-host", ["never-stored"])
    assert [i["id"] for i in pivot("ip", "::1", [], [old]).incidents] == ["INC-old"]
    assert [i["id"] for i in pivot("host", "windows-host", [], [old]).incidents] == ["INC-old"]
    assert pivot("user", "soc-test-user", [], [old]).incidents == []   # key doesn't know users


def test_pivot_unknown_type_matches_nothing():
    assert pivot("bogus", "x", [row(1, T.format(3))], []).alerts == []


def test_verdict_stats_fp_rate_and_time_to_close():
    from soc.agent.insights import verdict_stats

    def inc(key, status, verdict=None, minutes=0):
        return {"key": key, "status": status, "verdict": verdict, "verdict_at": None,
                "created_at": "2026-11-17T20:00:00+00:00",
                "updated_at": f"2026-11-17T20:{minutes:02d}:00+00:00"}
    rows = [inc("brute_force|a@h", "closed", "false_positive", 10), inc("brute_force|b@h", "closed", "benign", 20),
            inc("brute_force|c@h", "closed", "true_positive", 40), inc("brute_force|d@h", "closed", "false_positive", 30),
            inc("new_service|x@h", "open"), inc("new_service|y@h", "closed", None, 4)]
    bf, ns = verdict_stats(rows)
    assert (bf.family, bf.closed, bf.judged, bf.fp_rate) == ("brute_force", 4, 4, 0.5)   # benign is not an FP
    assert bf.median_close_minutes == 25
    assert (ns.open, ns.no_verdict, ns.fp_rate) == (1, 1, None)
