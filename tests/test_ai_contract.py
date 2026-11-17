import json

import pytest

from soc.ai.contract import ANALYSIS_SCHEMA, FIELDS, parse_analysis, validate

GOOD = {"summary": "Brute force against a non-existent user from localhost.",
        "severity": "medium",
        "risks": ["Password guessing"],
        "recommendations": ["Check which process made the attempts"]}


def test_valid_reply_parses():
    a, errors = parse_analysis(json.dumps(GOOD))
    assert errors == [] and a.severity == "medium" and a.risks == ("Password guessing",)
    assert a.to_dict() == GOOD


def test_truncated_json_is_rejected_with_position():
    a, errors = parse_analysis('{"summary": "cut off by max_tok')
    assert a is None and errors[0].startswith("invalid JSON")


def test_not_an_object():
    assert validate(["a"]) == ["reply must be a JSON object"]


def test_missing_and_extra_fields():
    errors = validate({"summary": "x", "severity": "low", "verdict": "bad"})
    assert "missing fields: risks, recommendations" in errors
    assert "unexpected fields: verdict" in errors


@pytest.mark.parametrize("sev", ["severe", "High", "", None, 3])
def test_severity_must_be_exact_enum(sev):
    errors = validate({**GOOD, "severity": sev})
    assert any(e.startswith("severity must be one of") for e in errors)


@pytest.mark.parametrize("risks", [[], "a string", [""], [1], ["x"] * 5, ["y" * 201]])
def test_bad_lists_rejected(risks):
    assert validate({**GOOD, "risks": risks})


def test_summary_rules():
    assert validate({**GOOD, "summary": "  "}) == ["summary must be a non-empty string"]
    assert "max 400" in validate({**GOOD, "summary": "z" * 401})[0]


def test_whitespace_is_trimmed():
    a, _ = parse_analysis(json.dumps({**GOOD, "summary": "  hi  "}))
    assert a.summary == "hi"


def test_schema_matches_contract_fields():
    assert ANALYSIS_SCHEMA["required"] == list(FIELDS)
    assert ANALYSIS_SCHEMA["properties"]["severity"]["enum"] == ["low", "medium", "high", "critical"]
