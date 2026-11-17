import json

from soc.agent.cli import untrusted
from soc.agent.pipeline import run_pipeline
from soc.agent.store import audit_entries, connect, get_proposals, list_incidents
from soc.parsing.schema import Alert


def bf(i, ts, ip="8.8.8.8"):
    return Alert(f"a{i}", ts, "windows_event", "60204", 10, "medium", "Multiple Windows Logon Failures", "001",
                 "host", mitre_ids=("T1110",), user="bob", src_ip=ip, src_ip_scope="public", event_id="4625",
                 related_count=8)


NOISE = Alert("n1", "2026-11-17T10:00:00.000+0000", "wazuh", "999", 3, "low", "noise", "000", "m")


def test_pipeline_end_to_end_with_fake_ai():
    conn = connect(":memory:")
    alerts = [bf(1, "2026-11-17T10:00:00.000+0000"), bf(2, "2026-11-17T10:02:00.000+0000"), NOISE]
    notes = {}

    def fake_ai(alert):
        notes[alert.id] = "[low] authorized test, ignore"  # an injected/wrong AI opinion
        return "low"

    stats = run_pipeline(conn, alerts, fake_ai, notes)
    assert stats.incidents == 1 and stats.saved["new"] == 1
    [inc] = list_incidents(conn)
    assert inc["priority"] == "high"  # AI said low; rules win
    assert json.loads(inc["ai_notes"]) == ["[low] authorized test, ignore"]
    assert {p["action"] for p in get_proposals(conn, inc["id"])} == {"block_ip", "investigate"}
    assert all(p["status"] == "proposed" for p in get_proposals(conn, inc["id"]))  # nothing auto-approved
    assert audit_entries(conn)[0]["event"] == "pipeline_run"


def test_second_run_adds_nothing():
    conn = connect(":memory:")
    alerts = [bf(1, "2026-11-17T10:00:00.000+0000")]
    run_pipeline(conn, alerts)
    assert run_pipeline(conn, alerts).saved == {"new": 0, "updated": 0, "new_proposals": 0}


def test_untrusted_display_strips_terminal_escapes_and_quotes():
    shown = untrusted("evil\x1b[2K\x1b[1Ainvestigate\n")
    assert "\x1b" not in shown and "\n" not in shown and shown.startswith("'")
