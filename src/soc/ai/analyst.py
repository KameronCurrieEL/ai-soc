"""AI analyst: normalized Alert -> validated Analysis (or a logged failure).

Flow: prompt -> model -> validate -> (one retry with the errors) -> result.
The model only proposes; nothing here executes anything.

Run with:
  python -m soc.ai.analyst --file data/samples/win_60204_multiple_logon_failures.json
  python -m soc.ai.analyst --last 1h --rule 60204 --limit 3
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from soc.ai.contract import ANALYSIS_SCHEMA, Analysis, parse_analysis
from soc.ai.llm import LLM, llm_from_env
from soc.ai.prompt import PROMPT_VERSION, SYSTEM_PROMPT, build_retry_prompt, build_user_prompt
from soc.checks import load_env
from soc.parsing.normalize import normalize
from soc.parsing.schema import Alert

log = logging.getLogger("soc.ai")
MAX_ATTEMPTS = 2  # first try + one retry (CLAUDE.md contract)
OUTPUT_DIR = Path("data/outputs")  # gitignored


@dataclass
class AnalysisResult:
    alert_id: str
    model: str
    prompt_version: str
    analysis: Analysis | None
    attempts: int
    errors: list[str] = field(default_factory=list)  # errors from the LAST attempt
    duration_s: float = 0.0
    analyzed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    @property
    def ok(self) -> bool:
        return self.analysis is not None

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id, "model": self.model, "prompt_version": self.prompt_version,
            "ok": self.ok, "attempts": self.attempts, "errors": self.errors,
            "duration_s": round(self.duration_s, 1), "analyzed_at": self.analyzed_at,
            "analysis": self.analysis.to_dict() if self.analysis else None,
        }


def analyze(alert: Alert, llm: LLM) -> AnalysisResult:
    result = AnalysisResult(alert.id, llm.name, PROMPT_VERSION, None, 0)
    user_prompt = build_user_prompt(alert)
    for attempt in range(1, MAX_ATTEMPTS + 1):
        result.attempts = attempt
        try:
            text = llm.complete(SYSTEM_PROMPT, user_prompt, ANALYSIS_SCHEMA)
            result.duration_s += getattr(llm, "last_duration_s", 0.0)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            result.errors = [f"model call failed: {exc}"]
            continue  # same prompt again; the model never saw anything
        analysis, errors = parse_analysis(text)
        if analysis:
            result.analysis, result.errors = analysis, []
            return result
        result.errors = errors
        log.info("alert %s attempt %d rejected: %s", alert.id, attempt, "; ".join(errors))
        user_prompt = build_retry_prompt(alert, errors)
    log.warning("alert %s: analysis FAILED after %d attempts: %s", alert.id, result.attempts, "; ".join(result.errors))
    return result


def load_raw_alerts(path: Path) -> list[dict]:
    """A file may hold one raw alert or a list of them (e.g. data/raw/alerts-*.json)."""
    data = json.loads(path.read_text())
    return data if isinstance(data, list) else [data]


def save_results(results: list[AnalysisResult], directory: Path = OUTPUT_DIR) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "analyses.jsonl"
    with path.open("a") as f:
        for r in results:
            f.write(json.dumps(r.to_dict()) + "\n")
    return path


def format_result(alert: Alert, r: AnalysisResult) -> str:
    head = f"== {alert.rule_id} lvl {alert.rule_level} ({alert.wazuh_severity}) {alert.description}"
    if not r.ok:
        return f"{head}\n   FAILED after {r.attempts} attempt(s): {'; '.join(r.errors)}"
    a = r.analysis
    lines = [head, f"   AI severity: {a.severity.upper()}   ({r.duration_s:.0f}s, attempts {r.attempts})",
             f"   {a.summary}"]
    lines += [f"   risk: {x}" for x in a.risks] + [f"   rec:  {x}" for x in a.recommendations]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Triage alerts with the local AI analyst.")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--file", type=Path, help="raw Wazuh alert JSON (one alert or a list)")
    src.add_argument("--last", help="fetch from the indexer, e.g. 1h")
    p.add_argument("--rule", action="append", help="with --last: rule id filter (repeatable)")
    p.add_argument("--min-level", type=int, default=0)
    p.add_argument("--limit", type=int, default=3, help="max alerts to analyze (CPU model is slow)")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    env = load_env()
    if args.file:
        raws = load_raw_alerts(args.file)[: args.limit]
    else:
        from soc.wazuh.alerts import alerts_from_response, build_alerts_query, parse_window
        from soc.wazuh.indexer import indexer_settings, search
        query = build_alerts_query(parse_window(args.last), args.min_level, None, args.rule, args.limit)
        raws = alerts_from_response(search(indexer_settings(env), query))

    llm = llm_from_env(env)
    results = []
    for raw in raws:
        alert = normalize(raw)
        r = analyze(alert, llm)
        results.append(r)
        print(format_result(alert, r), flush=True)
    if results:
        print(f"-- {sum(r.ok for r in results)}/{len(results)} valid; appended to {save_results(results)}")
    return 0 if all(r.ok for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
