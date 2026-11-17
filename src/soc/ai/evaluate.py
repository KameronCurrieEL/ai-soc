"""Score the AI analyst against hand-labeled cases (data/eval/cases.json).

Metrics:
  valid       reply passed the output contract (after at most one retry)
  exact       AI severity == expected
  acceptable  AI severity within the labeled acceptable range
  under-call  AI severity BELOW the acceptable range (a missed attack: worst outcome in a SOC)
  over-call   AI severity ABOVE the acceptable range (alert fatigue)

Run with:  python -m soc.ai.evaluate   (or `make eval`)
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from soc.ai.analyst import OUTPUT_DIR, analyze
from soc.ai.contract import SEVERITIES
from soc.ai.llm import LLM, llm_from_env
from soc.ai.prompt import PROMPT_VERSION
from soc.checks import load_env
from soc.parsing.schema import Alert

CASES = Path("data/eval/cases.json")
RANK = {s: i for i, s in enumerate(SEVERITIES)}


def alert_from_dict(d: dict) -> Alert:
    d = dict(d)
    d["mitre_ids"], d["mitre_tactics"] = tuple(d.get("mitre_ids", [])), tuple(d.get("mitre_tactics", []))
    return Alert(**d)


def grade(got: str | None, expected: str, acceptable: list[str]) -> str:
    """invalid | exact | acceptable | under | over"""
    if got is None:
        return "invalid"
    if got == expected:
        return "exact"
    if got in acceptable:
        return "acceptable"
    return "under" if RANK[got] < min(RANK[a] for a in acceptable) else "over"


def summarize(grades: list[str]) -> dict:
    n = len(grades) or 1
    count = {g: grades.count(g) for g in ("exact", "acceptable", "under", "over", "invalid")}
    return {
        "cases": len(grades),
        "valid_rate": round(1 - count["invalid"] / n, 2),
        "exact_rate": round(count["exact"] / n, 2),
        "acceptable_rate": round((count["exact"] + count["acceptable"]) / n, 2),
        "under_calls": count["under"],
        "over_calls": count["over"],
        "invalid": count["invalid"],
    }


def run(cases: list[dict], llm: LLM) -> dict:
    rows = []
    for c in cases:
        r = analyze(alert_from_dict(c["alert"]), llm)
        got = r.analysis.severity if r.analysis else None
        g = grade(got, c["expected"], c["acceptable"])
        rows.append({"id": c["id"], "expected": c["expected"], "got": got, "grade": g,
                     "attempts": r.attempts, "duration_s": round(r.duration_s, 1),
                     "summary": r.analysis.summary if r.analysis else "; ".join(r.errors)})
        print(f"{c['id']:<34} expect {c['expected']:<8} got {str(got):<8} {g.upper():<10} "
              f"{r.duration_s:>4.0f}s try {r.attempts}", flush=True)
    return {"model": llm.name, "prompt_version": PROMPT_VERSION,
            "run_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "score": summarize([r["grade"] for r in rows]), "rows": rows}


def main() -> int:
    cases = json.loads(CASES.read_text())
    report = run(cases, llm_from_env(load_env()))
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUTPUT_DIR / f"eval-{report['run_at'].replace(':', '')}.json"
    path.write_text(json.dumps(report, indent=1) + "\n")
    print(json.dumps(report["score"], indent=1))
    print(f"-- report: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
