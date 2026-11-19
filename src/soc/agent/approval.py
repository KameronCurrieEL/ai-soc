"""Human approval gate: the only way a proposal moves forward.

    proposed --approve--> approved --execute--> executed (dry-run)
    proposed --reject---> rejected

Each transition is one conditional UPDATE (WHERE status = <expected>) plus its audit entry,
in the same transaction. Two people approving at once can't both succeed.
"""

from __future__ import annotations

import sqlite3

from soc.agent.store import audit, get_proposal, now
from soc.decision.models import CHANGES_SYSTEM
from soc.response.actions import InvalidTarget, execute, plan

PIPELINE_ACTOR = "pipeline"
AUTOPILOT_ACTOR = "autopilot"

# Standard SOC dispositions. Recorded at close; they measure how good the detections are.
VERDICTS = {
    "true_positive": "True positive: real malicious or unauthorized activity",
    "benign": "Benign: real activity, but expected or authorized (e.g. an admin or a test)",
    "false_positive": "False positive: the detection was wrong",
}


class ApprovalError(Exception):
    pass


def _check_actor(actor: str) -> str:
    actor = (actor or "").strip()
    if not actor or actor.lower() == PIPELINE_ACTOR:
        raise ApprovalError("a named human approver is required")
    return actor


def _transition(conn: sqlite3.Connection, proposal_id: int, expected: str, new: str) -> sqlite3.Row:
    row = get_proposal(conn, proposal_id)
    if row is None:
        raise ApprovalError(f"proposal {proposal_id} not found")
    cur = conn.execute("UPDATE proposals SET status = ? WHERE id = ? AND status = ?", (new, proposal_id, expected))
    if cur.rowcount != 1:
        raise ApprovalError(f"proposal {proposal_id} is {row['status']!r}, expected {expected!r}")
    return row


def approve(conn: sqlite3.Connection, proposal_id: int, actor: str, note: str = "") -> None:
    actor = _check_actor(actor)
    row = get_proposal(conn, proposal_id)
    if row is None:
        raise ApprovalError(f"proposal {proposal_id} not found")
    try:
        plan(row["action"], row["target"])  # refuse approval of something that could never run safely
    except InvalidTarget as exc:
        with conn:
            audit(conn, actor, "approval_refused", row["incident_id"], proposal_id, error=str(exc))
        raise ApprovalError(f"cannot approve: {exc}") from None
    with conn:
        _transition(conn, proposal_id, "proposed", "approved")
        audit(conn, actor, "proposal_approved", row["incident_id"], proposal_id,
              action=row["action"], target=row["target"], note=note)


def reject(conn: sqlite3.Connection, proposal_id: int, actor: str, reason: str) -> None:
    actor = _check_actor(actor)
    if not reason.strip():
        raise ApprovalError("a reason is required to reject")
    with conn:
        row = _transition(conn, proposal_id, "proposed", "rejected")
        audit(conn, actor, "proposal_rejected", row["incident_id"], proposal_id,
              action=row["action"], target=row["target"], reason=reason)


def run_approved(conn: sqlite3.Connection, proposal_id: int, actor: str, dry_run: bool = True) -> str:
    """Execute an APPROVED proposal (dry-run). Unapproved proposals can't get here."""
    actor = _check_actor(actor)
    row = get_proposal(conn, proposal_id)
    if row is None:
        raise ApprovalError(f"proposal {proposal_id} not found")
    if row["status"] != "approved":
        raise ApprovalError(f"proposal {proposal_id} is {row['status']!r}; only approved proposals can run")
    p = plan(row["action"], row["target"])
    output = execute(p, dry_run=dry_run)
    with conn:
        _transition(conn, proposal_id, "approved", "executed")
        audit(conn, actor, "proposal_executed", row["incident_id"], proposal_id, dry_run=dry_run,
              command=p.command, rollback=p.rollback, output=output)
    return output


def close_incident(conn: sqlite3.Connection, incident_id: str, actor: str, note: str, verdict: str) -> None:
    actor = _check_actor(actor)
    if verdict not in VERDICTS:
        raise ApprovalError(f"a verdict is required: one of {', '.join(VERDICTS)}")
    if not note.strip():
        raise ApprovalError("a closing note is required")
    with conn:
        open_props = conn.execute("SELECT COUNT(*) FROM proposals WHERE incident_id = ? AND status IN "
                                  "('proposed', 'approved')", (incident_id,)).fetchone()[0]
        if open_props:
            raise ApprovalError(f"{open_props} proposal(s) still pending: approve/run or reject them first")
        cur = conn.execute("UPDATE incidents SET status = 'closed', verdict = ?, verdict_by = ?, verdict_at = ?,"
                           " updated_at = ? WHERE id = ? AND status = 'open'",
                           (verdict, actor, now(), now(), incident_id))
        if cur.rowcount != 1:
            raise ApprovalError(f"incident {incident_id} not found or already closed")
        audit(conn, actor, "incident_closed", incident_id, verdict=verdict, note=note)


def run_autopilot(conn: sqlite3.Connection, dry_run: bool = True) -> list[dict]:
    """Act without a human on RULE-critical containment only (CLAUDE.md D6).

    Scope, deliberately narrow so a hijacked AI can never trigger this:
      - source = 'rule'  (AI-suggested proposals never qualify, even if the AI rated them critical)
      - priority = 'critical'  (set by the deterministic rule, e.g. success_after_brute_force)
      - action changes the system (block_ip / disable_account / isolate_host); 'investigate' is left for a human
      - status still 'proposed', and the target still passes validation
    Each action is approved + executed (dry-run) as actor 'autopilot', every step audited, and the
    incident is flagged 'autopilot_engaged' so the human reviews it. Returns the acted proposals.
    """
    rows = conn.execute(
        "SELECT p.* FROM proposals p JOIN incidents i ON i.id = p.incident_id "
        "WHERE p.status = 'proposed' AND p.source = 'rule' AND p.priority = 'critical' AND i.status = 'open'"
    ).fetchall()
    acted, flagged = [], set()
    for row in rows:
        if row["action"] not in CHANGES_SYSTEM:
            continue
        try:
            p = plan(row["action"], row["target"])
        except InvalidTarget as exc:
            with conn:
                audit(conn, AUTOPILOT_ACTOR, "approval_refused", row["incident_id"], row["id"], error=str(exc))
            continue
        output = execute(p, dry_run=dry_run)
        with conn:
            if row["incident_id"] not in flagged:
                audit(conn, AUTOPILOT_ACTOR, "autopilot_engaged", row["incident_id"],
                      note="rule-critical incident handled automatically; review required")
                flagged.add(row["incident_id"])
            _transition(conn, row["id"], "proposed", "approved")
            audit(conn, AUTOPILOT_ACTOR, "proposal_approved", row["incident_id"], row["id"],
                  action=row["action"], target=row["target"], note="autopilot (rule-critical)")
            _transition(conn, row["id"], "approved", "executed")
            audit(conn, AUTOPILOT_ACTOR, "proposal_executed", row["incident_id"], row["id"], dry_run=dry_run,
                  command=p.command, rollback=p.rollback, output=output)
        acted.append({"proposal_id": row["id"], "incident_id": row["incident_id"],
                      "action": row["action"], "target": row["target"], "output": output})
    return acted
