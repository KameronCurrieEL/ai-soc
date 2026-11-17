"""Decision engine: alerts (+ optional AI analysis) -> prioritized, guarded proposals.

    final priority = max(rule priority, AI severity)   # AI may raise, never lower
    proposals      = rules only, then safety guards    # the AI never creates actions

Nothing here executes; Phase 7 adds human approval.

Run with:
  python -m soc.decision.engine --last 24h          # rules only (fast)
  python -m soc.decision.engine --last 2h --ai      # + AI analyst for alerts that pass the pre-filter
  python -m soc.decision.engine --eval              # eval set, using AI severities from the latest eval report
"""

from __future__ import annotations

import argparse
import glob
import json
import sys
from pathlib import Path

from soc.decision.correlate import Burst, find_bursts
from soc.decision.guards import apply_guards
from soc.decision.models import PRIORITIES, Decision, max_priority
from soc.decision.rules import run_rules
from soc.parsing.schema import Alert

OUTPUT_DIR = Path("data/outputs")
AI_MIN_PRIORITY = "medium"  # pre-filter: only alerts at/above this reach the slow local model


def decide(alert: Alert, ai_severity: str | None = None) -> Decision:
    hits = run_rules(alert)
    if hits:
        rule_priority = max_priority(*(h.priority for h in hits))
        reasons = [f"[{h.rule}] {h.reason}" for h in hits]
    else:
        rule_priority = alert.wazuh_severity
        reasons = [f"no rule matched; Wazuh level {alert.rule_level} -> {alert.wazuh_severity}"]

    priority = max_priority(rule_priority, ai_severity)
    if ai_severity in PRIORITIES and ai_severity != rule_priority:
        if priority == ai_severity:
            reasons.append(f"AI raised priority {rule_priority} -> {ai_severity}")
        else:
            reasons.append(f"AI rated {ai_severity}; ignored because rules say {rule_priority} (AI can't lower)")

    proposals, vetoed = apply_guards([p for h in hits for p in h.proposals])
    proposals = list(dict.fromkeys(proposals))  # de-duplicate, keep order
    return Decision(alert.id, priority, rule_priority, ai_severity, proposals, vetoed, reasons)


def needs_ai(alert: Alert, decision: Decision) -> bool:
    """Pre-filter for the slow model. Config benchmarks never need it."""
    if alert.source == "sca":
        return False
    return PRIORITIES.index(decision.rule_priority) >= PRIORITIES.index(AI_MIN_PRIORITY)


def burst_to_alert(b: Burst) -> Alert:
    """Express our own correlation as an Alert so the same brute_force rule judges it."""
    return Alert(
        id=f"burst:{b.source}:{b.first}", timestamp=b.last, source="soc_correlation", rule_id="soc-burst",
        rule_level=10, wazuh_severity="medium",
        description=f"{b.count} failed logons from one source within 5 minutes (own correlation)",
        agent_id="", agent_name=b.agent_name, mitre_ids=("T1110",), mitre_tactics=("Credential Access",),
        user=", ".join(b.users) or None, src_ip=b.src_ip, src_ip_scope=b.src_ip_scope, event_id="4625",
        related_count=b.count,
    )


def decide_batch(alerts: list[Alert], analyst=None) -> list[tuple[Alert, Decision]]:
    """Decide every alert plus our own bursts. `analyst(alert) -> severity|None` is optional."""
    items = alerts + [burst_to_alert(b) for b in find_bursts(alerts)]
    out = []
    for a in items:
        d = decide(a)
        if analyst and needs_ai(a, d):
            d = decide(a, analyst(a))
        out.append((a, d))
    return out


def hardening_backlog(alerts: list[Alert]) -> dict[str, list[str]]:
    """Failed configuration checks, grouped by policy (deduplicated): a to-do list, not alerts."""
    backlog: dict[str, set[str]] = {}
    for a in alerts:
        if a.source == "sca" and a.details.get("result") == "failed":
            label = f"{a.details.get('policy', 'unknown policy')} on {a.agent_name or a.agent_id}"
            backlog.setdefault(label, set()).add(a.details.get("check") or a.description)
    return {k: sorted(v) for k, v in sorted(backlog.items())}


def format_decision(a: Alert, d: Decision) -> str:
    lines = [f"[{d.priority.upper():>8}] {a.timestamp[:19]} rule {a.rule_id} {a.description}"]
    lines += [f"           why: {r}" for r in d.reasons]
    lines += [f"           -> PROPOSE {p.action}({p.target}) [{p.priority}]" + (" *changes system*" if p.changes_system else "")
              for p in d.proposals]
    lines += [f"           VETOED: {v}" for v in d.vetoed]
    return "\n".join(lines)


def run_eval() -> int:
    """Engine on the labeled eval set, with the AI severities from the most recent `make eval`."""
    from soc.ai.evaluate import alert_from_dict, grade, summarize
    cases = json.loads(Path("data/eval/cases.json").read_text())
    reports = sorted(glob.glob(str(OUTPUT_DIR / "eval-*.json")))
    ai = {r["id"]: r["got"] for r in json.loads(Path(reports[-1]).read_text())["rows"]} if reports else {}
    grades = {"ai": [], "engine": []}
    for c in cases:
        alert = alert_from_dict(c["alert"])
        d = decide(alert)
        if needs_ai(alert, d):  # same pre-filter as the live pipeline
            d = decide(alert, ai.get(c["id"]))
        g_ai, g_eng = grade(ai.get(c["id"]), c["expected"], c["acceptable"]), grade(d.priority, c["expected"], c["acceptable"])
        grades["ai"].append(g_ai)
        grades["engine"].append(g_eng)
        actions = ", ".join(f"{p.action}({p.target})" for p in d.proposals) or "-"
        print(f"{c['id']:<34} expect {c['expected']:<8} AI {str(ai.get(c['id'])):<8} {g_ai:<10} "
              f"engine {d.priority:<8} {g_eng:<10} {actions}")
    for who, g in grades.items():
        print(f"{who:>6}: {summarize(g)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Turn alerts into prioritized action proposals (nothing executes).")
    p.add_argument("--last", default="24h")
    p.add_argument("--ai", action="store_true", help="ask the AI analyst about alerts that pass the pre-filter")
    p.add_argument("--eval", action="store_true", help="score the engine on data/eval/cases.json")
    p.add_argument("--all", action="store_true", help="also print low-priority alerts without proposals")
    args = p.parse_args(argv)
    if args.eval:
        return run_eval()

    from soc.checks import load_env
    from soc.parsing.normalize import normalize
    from soc.wazuh.alerts import alerts_from_response, build_alerts_query, parse_window
    from soc.wazuh.indexer import indexer_settings, search

    env = load_env()
    resp = search(indexer_settings(env), build_alerts_query(parse_window(args.last), size=1000))
    alerts = [normalize(r) for r in alerts_from_response(resp)]

    analyst = None
    if args.ai:
        from soc.ai.analyst import analyze
        from soc.ai.llm import llm_from_env
        llm = llm_from_env(env)
        analyst = lambda a: (r.analysis.severity if (r := analyze(a, llm)).analysis else None)  # noqa: E731

    results = decide_batch(alerts, analyst)
    shown = [(a, d) for a, d in results if args.all or d.proposals or d.priority != "low"]
    for a, d in sorted(shown, key=lambda x: (-PRIORITIES.index(x[1].priority), x[0].timestamp)):
        print(format_decision(a, d))
    counts = {pr: sum(d.priority == pr for _, d in results) for pr in PRIORITIES}
    n_props = sum(len(d.proposals) for _, d in results)
    print(f"-- {len(results)} alerts/bursts: {counts}; {n_props} proposals; "
          f"{sum(needs_ai(a, d) for a, d in results)} would go to the AI")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    backlog = hardening_backlog(alerts)
    if backlog:
        path = OUTPUT_DIR / "hardening-backlog.txt"
        path.write_text("".join(f"## {policy} ({len(checks)} failed)\n" + "".join(f"- {c}\n" for c in checks) + "\n"
                                for policy, checks in backlog.items()))
        print("-- hardening backlog: " + "; ".join(f"{p}: {len(c)} failed" for p, c in backlog.items()) + f" -> {path}")
    with (OUTPUT_DIR / "decisions.jsonl").open("a") as f:
        for _, d in results:
            if d.proposals:
                f.write(json.dumps(d.to_dict()) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
