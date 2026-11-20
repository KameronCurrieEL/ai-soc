"""Analyst console for the approval queue.

  python -m soc.agent run [--last 24h] [--ai]      fetch, decide, queue incidents
  python -m soc.agent queue [--all]                list incidents
  python -m soc.agent show INC-xxxx                incident details + proposals + audit trail
  python -m soc.agent approve ID --by NAME [--note TEXT]
  python -m soc.agent reject  ID --by NAME --reason TEXT
  python -m soc.agent execute ID --by NAME         run an APPROVED proposal (dry-run only)
  python -m soc.agent close INC-xxxx --by NAME --verdict true_positive|benign|false_positive --note TEXT
  python -m soc.agent audit [INC-xxxx]

--by defaults to $SOC_ANALYST. The approver's name goes into the audit log.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import unicodedata

from soc.agent import approval, store

PRIORITY_MARK = {"critical": "!!!", "high": "!! ", "medium": "!  ", "low": "   "}


def untrusted(text: object) -> str:
    """Show log-derived text safely: drop control chars (terminal escape injection) and quote it."""
    s = "".join(ch for ch in str(text) if unicodedata.category(ch)[0] != "C")
    return repr(s[:200] + ("..." if len(s) > 200 else ""))


def cmd_run(args: argparse.Namespace) -> int:
    from soc.agent.pipeline import RunStats, fetch_alerts, make_ai_analyst, run_pipeline
    from soc.checks import load_env
    env = load_env()
    stats, notes = RunStats(), {}
    analyst = make_ai_analyst(env, notes, stats) if args.ai else None
    alerts = fetch_alerts(env, args.last)
    with store.connect() as conn:
        stats = run_pipeline(conn, alerts, analyst, notes, stats)
    s = stats.saved
    print(f"{stats.alerts} alerts -> {stats.decisions_with_proposals} decisions with proposals -> "
          f"{stats.incidents} incidents ({s.get('new', 0)} new, {s.get('updated', 0)} updated, "
          f"{s.get('new_proposals', 0)} new proposals); AI calls: {stats.ai_calls}; "
          f"hardening backlog: {stats.backlog_checks} failed checks")
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    """Feed alerts from another source (a JSON file of raw alerts) through the same pipeline."""
    from soc.agent.pipeline import RunStats, alerts_from_file, run_pipeline
    alerts = alerts_from_file(args.file, args.sensor)
    with store.connect_tenant(store.DB_PATH, args.tenant) as conn:
        stats = run_pipeline(conn, alerts, None, {}, RunStats())
    s = stats.saved
    print(f"ingested {stats.alerts} alerts from sensor '{args.sensor}' into tenant '{args.tenant}' -> "
          f"{stats.incidents} incidents "
          f"({s.get('new', 0)} new, {s.get('updated', 0)} updated, {s.get('new_proposals', 0)} new proposals)")
    return 0


def cmd_queue(args: argparse.Namespace) -> int:
    conn = store.connect()
    rows = store.list_incidents(conn, None if args.all else "open")
    if not rows:
        print("queue empty")
    for r in rows:
        props = store.get_proposals(conn, r["id"])
        pending = sum(p["status"] == "proposed" for p in props)
        print(f"{PRIORITY_MARK[r['priority']]} {r['id']}  [{r['priority']:<8}] {r['status']:<6} "
              f"{r['title']}  ({len(json.loads(r['alert_ids']))} alerts, {pending}/{len(props)} pending)  "
              f"last {r['last_seen'][:19]}")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    conn = store.connect()
    r = store.get_incident(conn, args.incident)
    if r is None:
        print(f"no incident {args.incident}", file=sys.stderr)
        return 1
    print(f"{r['id']}  [{r['priority'].upper()}]  {r['title']}  ({r['status']})")
    print(f"  seen {r['first_seen'][:19]} -> {r['last_seen'][:19]}, {len(json.loads(r['alert_ids']))} alerts")
    print("  WHY (rules):")
    for reason in json.loads(r["reasons"]):
        print(f"    - {untrusted(reason)}")
    notes = json.loads(r["ai_notes"])
    if notes:
        print("  AI ANALYST (advisory, may be wrong):")
        for n in notes:
            print(f"    - {untrusted(n)}")
    for v in json.loads(r["vetoed"]):
        print(f"  VETOED by safety guard: {untrusted(v)}")
    print("  PROPOSALS (targets come from logs = untrusted):")
    for p in store.get_proposals(conn, r["id"]):
        print(f"    #{p['id']:<4} {p['status']:<9} {p['action']:<16} target={untrusted(p['target'])} [{p['priority']}]")
    print("  AUDIT TRAIL:")
    for e in reversed(store.audit_entries(conn, r["id"])):
        print(f"    {e['at']}  {e['actor']:<10} {e['event']:<20} {e['detail']}")
    return 0


def _actor(args: argparse.Namespace) -> str:
    return args.by or os.environ.get("SOC_ANALYST", "")


def _guarded(fn) -> int:
    try:
        out = fn()
    except approval.ApprovalError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    if out:
        print(out)
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    conn = store.connect()
    return _guarded(lambda: approval.approve(conn, args.id, _actor(args), args.note) or f"proposal #{args.id} approved")


def cmd_reject(args: argparse.Namespace) -> int:
    conn = store.connect()
    return _guarded(lambda: approval.reject(conn, args.id, _actor(args), args.reason) or f"proposal #{args.id} rejected")


def cmd_execute(args: argparse.Namespace) -> int:
    conn = store.connect()
    return _guarded(lambda: approval.run_approved(conn, args.id, _actor(args)))


def cmd_close(args: argparse.Namespace) -> int:
    conn = store.connect()
    return _guarded(lambda: approval.close_incident(conn, args.incident, _actor(args), args.note, args.verdict)
                    or f"{args.incident} closed")


def cmd_audit(args: argparse.Namespace) -> int:
    for e in reversed(store.audit_entries(store.connect(), args.incident, limit=args.limit)):
        print(f"{e['at']}  {e['actor']:<10} {e['event']:<20} {e['incident_id'] or '':<12} "
              f"#{e['proposal_id'] or '':<4} {e['detail']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="soc", description="AI-assisted SOC: approval queue console")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="fetch alerts, decide, queue incidents")
    r.add_argument("--last", default="24h")
    r.add_argument("--ai", action="store_true", help="AI analyst for pre-filtered alerts (slow on CPU)")
    r.set_defaults(fn=cmd_run)
    g = sub.add_parser("ingest", help="ingest alerts from another source (JSON file)")
    g.add_argument("--file", required=True, help="JSON list of raw alerts")
    g.add_argument("--sensor", required=True, help="name of the source/collector (e.g. wazuh-branch2)")
    g.add_argument("--tenant", default="default", help="tenant to ingest into (default: default)")
    g.set_defaults(fn=cmd_ingest)
    q = sub.add_parser("queue", help="list incidents")
    q.add_argument("--all", action="store_true", help="include closed incidents")
    q.set_defaults(fn=cmd_queue)
    s = sub.add_parser("show", help="incident details")
    s.add_argument("incident")
    s.set_defaults(fn=cmd_show)
    for name, fn in (("approve", cmd_approve), ("reject", cmd_reject), ("execute", cmd_execute)):
        c = sub.add_parser(name)
        c.add_argument("id", type=int, help="proposal id (see `show`)")
        c.add_argument("--by", help="approver name (default $SOC_ANALYST)")
        if name == "approve":
            c.add_argument("--note", default="")
        if name == "reject":
            c.add_argument("--reason", required=True)
        c.set_defaults(fn=fn)
    c = sub.add_parser("close")
    c.add_argument("incident")
    c.add_argument("--by")
    c.add_argument("--note", required=True)
    c.add_argument("--verdict", required=True, choices=list(approval.VERDICTS))
    c.set_defaults(fn=cmd_close)
    a = sub.add_parser("audit", help="show the audit log")
    a.add_argument("incident", nargs="?")
    a.add_argument("--limit", type=int, default=30)
    a.set_defaults(fn=cmd_audit)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
