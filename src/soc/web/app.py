"""Local web dashboard over the approval queue (Phase 7b).

A second front end over soc.agent.store / approval / pipeline: no decision logic lives here,
so the browser and the CLI can never disagree about what is allowed.

Security controls (an approval page that can trigger firewall changes is a juicy target):
  - binds 127.0.0.1 only, and rejects requests whose Host isn't localhost (DNS rebinding)
  - CSRF token on every POST (a malicious site can't submit "approve" via your browser)
  - Jinja2 autoescaping for all log-derived text (XSS)
  - CSP + X-Frame-Options DENY (no scripts from elsewhere, no clickjacking via frames)
  - a named human approver on every action; the audit log records it

Run with:  python -m soc.web   (or `make web`) -> http://localhost:8765
"""

from __future__ import annotations

import argparse
import hmac
import json
import secrets
import sqlite3
import sys
from pathlib import Path

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for

from soc.agent import approval, insights, store
from soc.enrich import geoip
from soc.parsing.schema import ip_scope
from soc.response.actions import InvalidTarget, plan

ALLOWED_HOSTS = {"127.0.0.1", "localhost"}
DEFAULT_PORT = 8765
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def create_app(db_path: Path | str = store.DB_PATH, pipeline_runner=None) -> Flask:
    """pipeline_runner(conn) -> RunStats; injectable so tests don't need Wazuh."""
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=secrets.token_hex(32),       # new key per start: old sessions/tokens become invalid
        SESSION_COOKIE_HTTPONLY=True,           # JavaScript can't read the session cookie
        SESSION_COOKIE_SAMESITE="Strict",       # browser won't send it on cross-site requests
    )
    app.jinja_env.filters["fromjson"] = json.loads

    # ---------- per-request plumbing ----------

    def db() -> sqlite3.Connection:
        if "conn" not in g:
            g.conn = store.connect(db_path)
        return g.conn

    @app.teardown_appcontext
    def close_db(_exc: BaseException | None) -> None:
        conn = g.pop("conn", None)
        if conn is not None:
            conn.close()

    def csrf_token() -> str:
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return session["csrf"]

    @app.context_processor
    def inject() -> dict:
        return {"csrf_token": csrf_token(), "analyst": session.get("analyst", "")}

    @app.before_request
    def security_checks() -> None:
        host = (request.host or "").rsplit(":", 1)[0].strip("[]")
        if host not in ALLOWED_HOSTS:
            abort(400, "unexpected Host header")      # DNS rebinding protection
        if request.method == "POST":
            sent = request.form.get("csrf_token", "")
            expected = session.get("csrf", "")
            if not sent or not expected or not hmac.compare_digest(sent, expected):
                abort(400, "CSRF token missing or invalid: reload the page and try again")

    @app.after_request
    def add_headers(resp):
        resp.headers.update(SECURITY_HEADERS)
        return resp

    # ---------- pages ----------

    @app.get("/")
    def index():
        show_all = request.args.get("all") == "1"
        conn = db()
        incidents = []
        for r in store.list_incidents(conn, None if show_all else "open"):
            props = store.get_proposals(conn, r["id"])
            incidents.append({"row": r, "pending": sum(p["status"] == "proposed" for p in props),
                              "approved": sum(p["status"] == "approved" for p in props), "total": len(props)})
        last_run = conn.execute("SELECT * FROM audit_log WHERE event = 'pipeline_run' ORDER BY id DESC LIMIT 1").fetchone()
        counts = {p: sum(1 for i in incidents if i["row"]["priority"] == p and i["row"]["status"] == "open")
                  for p in ("critical", "high", "medium", "low")}
        return render_template("index.html", incidents=incidents, show_all=show_all, last_run=last_run, counts=counts)

    @app.get("/incident/<inc_id>")
    def incident(inc_id: str):
        conn = db()
        r = store.get_incident(conn, inc_id)
        if r is None:
            abort(404)
        proposals = []
        for p in store.get_proposals(conn, inc_id):
            try:
                preview, error = plan(p["action"], p["target"]), None
            except InvalidTarget as exc:
                preview, error = None, str(exc)
            proposals.append({"row": p, "plan": preview, "error": error})
        alert_rows = store.get_alerts(conn, json.loads(r["alert_ids"]))
        audit_rows = list(reversed(store.audit_entries(conn, inc_id, limit=200)))
        hosts, ips = insights.hosts_and_ips(r, alert_rows)
        # Loading the GeoIP database takes seconds: only do it when there is a public IP to look up.
        geo_db = geoip.default_db() if any(ip_scope(ip) == "public" for ip in ips) else None
        locations = [geoip.locate(ip, hosts[0] if hosts else None, geo_db) for ip in ips]
        involved = {k: v for k, v in insights.entities(alert_rows).items() if k not in ("host", "ip")}
        return render_template(
            "incident.html", inc=r, proposals=proposals, verdicts=approval.VERDICTS, audit=audit_rows,
            summary=insights.plain_summary(r, alert_rows) if alert_rows else None,
            hosts=hosts, locations=locations, involved=involved, geo_attribution=geoip.ATTRIBUTION,
            timeline=insights.timeline(alert_rows, audit_rows))

    @app.get("/entity")
    def entity():
        """Pivot page. Query string (not path) because values contain ':' '\\' and spaces."""
        etype = request.args.get("type", "")
        value = request.args.get("value", "")[:300]
        if etype not in insights.ENTITY_TYPES or not value:
            abort(404)
        conn = db()
        p = insights.pivot(etype, value, store.recent_alerts(conn, hours=store.ALERT_RETENTION_DAYS * 24),
                           store.list_incidents(conn, None))
        location = None
        if etype == "ip":
            hosts = [e.value for e in p.related.get("host", [])]
            if not hosts and p.incidents:
                hosts = insights.hosts_and_ips(p.incidents[0], [])[0]
            geo_db = geoip.default_db() if ip_scope(value) == "public" else None
            location = geoip.locate(value, hosts[0] if hosts else None, geo_db)
        counts = {prio: n for prio in reversed(insights.PRIORITY_ORDER)
                  if (n := sum(r["priority"] == prio for r in p.alerts))}
        return render_template("entity.html", p=p, label=insights.ENTITY_TYPES[etype][0], location=location,
                               counts=counts, timeline=insights.timeline(p.alerts, []),
                               retention_days=store.ALERT_RETENTION_DAYS, geo_attribution=geoip.ATTRIBUTION)

    @app.get("/audit")
    def audit_view():
        return render_template("audit.html", entries=store.audit_entries(db(), limit=300))

    # ---------- actions (POST only, CSRF-checked above) ----------

    def remember_analyst() -> str:
        name = request.form.get("by", "").strip()[:40]
        if name:
            session["analyst"] = name
        return name

    def do(fn, success: str):
        try:
            out = fn()
        except approval.ApprovalError as exc:
            flash(f"Refused: {exc}", "error")
            return
        flash(out if isinstance(out, str) and out else success, "ok")

    @app.post("/proposal/<int:pid>/<verb>")
    def proposal_action(pid: int, verb: str):
        conn = db()
        p = store.get_proposal(conn, pid)
        if p is None:
            abort(404)
        by = remember_analyst()
        if verb == "approve":
            do(lambda: approval.approve(conn, pid, by, request.form.get("note", "")), f"Proposal #{pid} approved")
        elif verb == "reject":
            do(lambda: approval.reject(conn, pid, by, request.form.get("reason", "")), f"Proposal #{pid} rejected")
        elif verb == "execute":
            do(lambda: approval.run_approved(conn, pid, by, dry_run=True), f"Proposal #{pid} executed (dry-run)")
        else:
            abort(404)
        return redirect(url_for("incident", inc_id=p["incident_id"]))

    @app.post("/incident/<inc_id>/close")
    def close(inc_id: str):
        by = remember_analyst()
        do(lambda: approval.close_incident(db(), inc_id, by, request.form.get("note", ""),
                                           request.form.get("verdict", "")), f"{inc_id} closed")
        return redirect(url_for("incident", inc_id=inc_id))

    @app.post("/run")
    def run():
        runner = pipeline_runner or _default_runner
        try:
            stats = runner(db())
        except Exception as exc:  # Wazuh down, bad credentials, ...: show it, don't crash the page
            flash(f"Pipeline run failed: {exc}", "error")
            return redirect(url_for("index"))
        s = stats.saved
        flash(f"Pipeline: {stats.alerts} alerts -> {stats.incidents} incidents "
              f"({s.get('new', 0)} new, {s.get('updated', 0)} updated, {s.get('new_proposals', 0)} new proposals)", "ok")
        return redirect(url_for("index"))

    return app


def _default_runner(conn: sqlite3.Connection):
    """Rules-only refresh from the web (the AI takes minutes on CPU; use the CLI `run --ai` for that)."""
    from soc.agent.pipeline import fetch_alerts, run_pipeline
    from soc.checks import load_env
    return run_pipeline(conn, fetch_alerts(load_env(), "24h"))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Local SOC dashboard (127.0.0.1 only)")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = p.parse_args(argv)
    print(f"SOC dashboard on http://localhost:{args.port}  (localhost only; Ctrl+C to stop)")
    create_app().run(host="127.0.0.1", port=args.port, debug=False)  # never debug=True: it allows code execution
    return 0


if __name__ == "__main__":
    sys.exit(main())
