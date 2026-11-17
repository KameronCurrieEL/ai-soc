from soc.agent.incidents import group_incidents
from soc.decision.engine import decide
from soc.parsing.schema import Alert


def bf(i, ts, ip="::1", agent="host"):
    return Alert(f"a{i}", ts, "windows_event", "60204", 10, "medium", "Multiple Windows Logon Failures", "001", agent,
                 mitre_ids=("T1110",), user="u", src_ip=ip, src_ip_scope="loopback" if ip == "::1" else "public",
                 event_id="4625", related_count=8, details={"requested_by": "labuser"})


def run(alerts):
    return group_incidents([(a, decide(a)) for a in alerts])


def test_same_source_within_window_is_one_incident():
    [inc] = run([bf(1, "2026-11-17T19:45:53.000+0000"), bf(2, "2026-11-17T19:46:00.000+0000"),
                 bf(3, "2026-11-17T19:46:11.000+0000")])
    assert inc.alert_ids == ["a1", "a2", "a3"] and len(inc.proposals) == 1
    assert inc.title == "Brute force from ::1" and inc.priority == "medium"
    assert inc.first_seen.startswith("2026-11-17T19:45:53") and inc.last_seen.startswith("2026-11-17T19:46:11")


def test_gap_longer_than_window_starts_new_incident():
    incs = run([bf(1, "2026-11-17T10:00:00.000+0000"), bf(2, "2026-11-17T12:00:00.000+0000")])
    assert len(incs) == 2 and incs[0].id != incs[1].id


def test_different_sources_are_different_incidents():
    incs = run([bf(1, "2026-11-17T10:00:00.000+0000"), bf(2, "2026-11-17T10:01:00.000+0000", ip="8.8.8.8")])
    assert {i.title for i in incs} == {"Brute force from ::1", "Brute force from 8.8.8.8"}
    public = next(i for i in incs if "8.8.8.8" in i.title)
    assert public.priority == "high" and any(p.action == "block_ip" for p in public.proposals)


def test_incident_id_is_stable_across_runs():
    alerts = [bf(1, "2026-11-17T10:00:00.000+0000")]
    assert run(alerts)[0].id == run(alerts)[0].id


def test_alerts_without_proposals_never_become_incidents():
    noise = Alert("n", "2026-11-17T10:00:00.000+0000", "wazuh", "999", 3, "low", "noise", "000", "m")
    assert run([noise]) == []


def test_unsorted_input_is_grouped_by_time():
    [inc] = run([bf(2, "2026-11-17T10:05:00.000+0000"), bf(1, "2026-11-17T10:00:00.000+0000")])
    assert inc.alert_ids == ["a1", "a2"]
