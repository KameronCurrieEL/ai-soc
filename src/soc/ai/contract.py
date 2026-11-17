"""The analyst's output contract (see CLAUDE.md "AI output contract").

{ "summary": str, "severity": "low|medium|high|critical", "risks": [str], "recommendations": [str] }

ANALYSIS_SCHEMA is sent to Ollama to steer generation; parse_analysis() is the real gate.
We never trust the model's output just because we asked nicely.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass

SEVERITIES = ("low", "medium", "high", "critical")
MAX_SUMMARY = 400
MAX_ITEMS = 4
MAX_ITEM_LEN = 200
FIELDS = ("summary", "severity", "risks", "recommendations")

_STR_LIST = {"type": "array", "minItems": 1, "maxItems": MAX_ITEMS,
             "items": {"type": "string", "maxLength": MAX_ITEM_LEN}}

ANALYSIS_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "summary": {"type": "string", "maxLength": MAX_SUMMARY},
        "severity": {"type": "string", "enum": list(SEVERITIES)},
        "risks": _STR_LIST,
        "recommendations": _STR_LIST,
    },
    "required": list(FIELDS),
    "additionalProperties": False,
}


@dataclass(frozen=True)
class Analysis:
    summary: str
    severity: str
    risks: tuple[str, ...]
    recommendations: tuple[str, ...]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["risks"], d["recommendations"] = list(self.risks), list(self.recommendations)
        return d


def _check_str_list(name: str, value: object, errors: list[str]) -> None:
    if not isinstance(value, list) or not value:
        errors.append(f"{name} must be a non-empty list of strings")
        return
    if len(value) > MAX_ITEMS:
        errors.append(f"{name} has {len(value)} items, max {MAX_ITEMS}")
    for i, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            errors.append(f"{name}[{i}] must be a non-empty string")
        elif len(item) > MAX_ITEM_LEN:
            errors.append(f"{name}[{i}] is {len(item)} chars, max {MAX_ITEM_LEN}")


def validate(data: object) -> list[str]:
    """Return a list of human-readable problems; empty list = valid."""
    if not isinstance(data, dict):
        return ["reply must be a JSON object"]
    errors: list[str] = []
    missing = [f for f in FIELDS if f not in data]
    if missing:
        errors.append(f"missing fields: {', '.join(missing)}")
    extra = sorted(set(data) - set(FIELDS))
    if extra:
        errors.append(f"unexpected fields: {', '.join(extra)}")
    summary = data.get("summary")
    if "summary" in data:
        if not isinstance(summary, str) or not summary.strip():
            errors.append("summary must be a non-empty string")
        elif len(summary) > MAX_SUMMARY:
            errors.append(f"summary is {len(summary)} chars, max {MAX_SUMMARY}")
    if "severity" in data and data["severity"] not in SEVERITIES:
        errors.append(f"severity must be one of {list(SEVERITIES)}, got {data['severity']!r}")
    for name in ("risks", "recommendations"):
        if name in data:
            _check_str_list(name, data[name], errors)
    return errors


def parse_analysis(text: str) -> tuple[Analysis | None, list[str]]:
    """Raw model text -> (Analysis, []) if valid, else (None, [errors])."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return None, [f"invalid JSON: {exc.msg} at position {exc.pos}"]
    errors = validate(data)
    if errors:
        return None, errors
    return Analysis(
        summary=data["summary"].strip(),
        severity=data["severity"],
        risks=tuple(r.strip() for r in data["risks"]),
        recommendations=tuple(r.strip() for r in data["recommendations"]),
    ), []
