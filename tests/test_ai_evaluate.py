import json
from pathlib import Path

import pytest

from soc.ai.contract import SEVERITIES
from soc.ai.evaluate import alert_from_dict, grade, summarize

CASES = json.loads((Path(__file__).parent.parent / "data" / "eval" / "cases.json").read_text())


@pytest.mark.parametrize("got,expected,ok,want", [
    ("high", "high", ["high", "critical"], "exact"),
    ("critical", "high", ["high", "critical"], "acceptable"),
    ("medium", "high", ["high", "critical"], "under"),
    ("low", "low", ["low"], "exact"),
    ("medium", "low", ["low"], "over"),
    (None, "low", ["low"], "invalid"),
])
def test_grade(got, expected, ok, want):
    assert grade(got, expected, ok) == want


def test_summarize_rates():
    s = summarize(["exact", "acceptable", "under", "invalid"])
    assert s == {"cases": 4, "valid_rate": 0.75, "exact_rate": 0.25, "acceptable_rate": 0.5,
                 "under_calls": 1, "over_calls": 0, "invalid": 1}


def test_eval_cases_are_well_formed():
    assert len(CASES) >= 10 and len({c["id"] for c in CASES}) == len(CASES)
    for c in CASES:
        assert c["expected"] in SEVERITIES and c["expected"] in c["acceptable"]
        assert set(c["acceptable"]) <= set(SEVERITIES) and c["why"]
        alert_from_dict(c["alert"])  # must load into our schema


def test_eval_set_covers_every_severity_and_source():
    assert {c["expected"] for c in CASES} == set(SEVERITIES)
    assert {"windows_event", "fim", "sca", "wazuh"} <= {c["alert"]["source"] for c in CASES}
