import json
from pathlib import Path

import pytest

from soc.wazuh.alerts import (
    alerts_from_response, build_alerts_query, parse_window, save_raw, summarize_alert, total_hits,
)

SAMPLES = Path(__file__).parent.parent / "data" / "samples"


def load(name: str) -> dict:
    return json.loads((SAMPLES / name).read_text())


@pytest.mark.parametrize("text,expected", [("30m", "now-30m"), ("1h", "now-1h"), ("7d", "now-7d")])
def test_parse_window_valid(text, expected):
    assert parse_window(text) == expected


@pytest.mark.parametrize("bad", ["", "1", "h", "0h", "1w", "1h||+1d", "-1h", "now-1h"])
def test_parse_window_rejects_anything_else(bad):
    with pytest.raises(ValueError):
        parse_window(bad)


def filters(q: dict) -> list[dict]:
    return q["query"]["bool"]["filter"]


def test_minimal_query_has_only_time_filter_and_sorts_newest_first():
    q = build_alerts_query("now-1h")
    assert filters(q) == [{"range": {"timestamp": {"gte": "now-1h"}}}]
    assert q["sort"] == [{"timestamp": {"order": "desc"}}]


def test_all_filters_added():
    q = build_alerts_query("now-1h", min_level=5, agent_id="001", rule_ids=["60122", "60204"])
    assert {"range": {"rule.level": {"gte": 5}}} in filters(q)
    assert {"term": {"agent.id": "001"}} in filters(q)
    assert {"terms": {"rule.id": ["60122", "60204"]}} in filters(q)


@pytest.mark.parametrize("size,expected", [(0, 1), (50, 50), (999999, 1000)])
def test_size_is_clamped(size, expected):
    assert build_alerts_query("now-1h", size=size)["size"] == expected


def test_response_parsing():
    resp = {"hits": {"total": {"value": 42, "relation": "eq"},
                     "hits": [{"_source": {"rule": {"id": "1"}}}, {"_id": "no-source"}]}}
    assert alerts_from_response(resp) == [{"rule": {"id": "1"}}]
    assert total_hits(resp) == 42
    assert alerts_from_response({}) == [] and total_hits({}) == 0


def test_summary_of_failed_logon_sample():
    line = summarize_alert(load("win_4625_logon_failure_unknown_user.json"))
    assert "60122" in line and "user=soc-test-user" in line and "src=::1" in line and "T1531" in line


def test_summary_of_brute_force_sample_has_mitre():
    line = summarize_alert(load("win_60204_multiple_logon_failures.json"))
    assert "60204" in line and "lvl 10" in line and "T1110" in line


def test_summary_survives_empty_alert():
    assert "rule" in summarize_alert({})


def test_save_raw_writes_json(tmp_path):
    path = save_raw([{"a": 1}], tmp_path)
    assert json.loads(path.read_text()) == [{"a": 1}]
