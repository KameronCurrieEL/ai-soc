import json

import pytest

from soc.agent.pipeline import alerts_from_file, run_pipeline, RunStats
from soc.agent.store import connect, latest_alerts, sensor_stats, sensors


def test_alerts_from_file_tags_sensor(tmp_path):
    raw = json.load(open("data/samples/win_60204_multiple_logon_failures.json"))
    f = tmp_path / "branch.json"
    f.write_text(json.dumps([raw]))
    alerts = alerts_from_file(str(f), "wazuh-branch2")
    assert alerts and all(a.sensor == "wazuh-branch2" for a in alerts)


def test_ingest_through_pipeline_is_queryable_by_sensor(tmp_path):
    raw = json.load(open("data/samples/win_60204_multiple_logon_failures.json"))
    f = tmp_path / "branch.json"; f.write_text(json.dumps([raw, raw]))
    conn = connect(tmp_path / "soc.db")
    run_pipeline(conn, alerts_from_file(str(f), "wazuh-branch2"), None, {}, RunStats())
    assert "wazuh-branch2" in sensors(conn)
    rows = latest_alerts(conn, sensor="wazuh-branch2")
    assert rows and all(r["sensor"] == "wazuh-branch2" for r in rows)
    assert latest_alerts(conn, sensor="nope") == []
    stats = {s["sensor"]: s["count"] for s in sensor_stats(conn, hours=200)}
    assert stats.get("wazuh-branch2", 0) >= 1
