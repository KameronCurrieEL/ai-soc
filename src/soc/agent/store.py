"""Persistent queue (incidents + proposals) and an append-only audit log, in SQLite.

SQLite is a file-based SQL database built into Python: no server, no dependency.
The audit log is protected by triggers inside the database, so not even a bug in our
code can UPDATE or DELETE history.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from datetime import timedelta

from soc.agent.incidents import WINDOW_S, Incident
from soc.decision.correlate import parse_time
from soc.decision.models import max_priority

DB_PATH = Path("data/outputs/soc.db")  # gitignored: contains real alert data
DEFAULT_TENANT = "default"


def valid_tenant(name: str) -> bool:
    name = (name or "").strip()
    return bool(name) and len(name) <= 40 and all(c.isalnum() or c in "._-" for c in name)


def tenant_db_path(base: Path | str, tenant: str) -> Path:
    """Per-tenant data file. The default tenant keeps the base DB (existing data); others are siloed.

    Complete isolation: a user in tenant X only ever opens tenant X's database, so a query
    cannot reach another tenant's rows. `base` is also the shared control DB (users/auth).
    """
    base = Path(base)
    if tenant == DEFAULT_TENANT or not valid_tenant(tenant):
        return base
    return base.parent / "tenants" / f"{tenant}.db"


def connect_tenant(base: Path | str, tenant: str) -> sqlite3.Connection:
    return connect(tenant_db_path(base, tenant))

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id          TEXT PRIMARY KEY,
    key         TEXT NOT NULL,
    title       TEXT NOT NULL,
    priority    TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'open',      -- open | closed
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    alert_ids   TEXT NOT NULL,                     -- JSON list
    reasons     TEXT NOT NULL,                     -- JSON list
    vetoed      TEXT NOT NULL,                     -- JSON list
    ai_notes    TEXT NOT NULL DEFAULT '[]',        -- JSON list, advisory AI summaries
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS proposals (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(id),
    action      TEXT NOT NULL,
    target      TEXT NOT NULL,
    priority    TEXT NOT NULL,
    rule        TEXT NOT NULL,
    reason      TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'proposed',  -- proposed | approved | rejected | executed
    source      TEXT NOT NULL DEFAULT 'rule',       -- rule | agent  (who proposed it)
    UNIQUE (incident_id, action, target)
);
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    at          TEXT NOT NULL,
    actor       TEXT NOT NULL,                     -- 'pipeline' or the human approver
    event       TEXT NOT NULL,
    incident_id TEXT,
    proposal_id INTEGER,
    detail      TEXT NOT NULL                      -- JSON
);
CREATE TABLE IF NOT EXISTS alerts (
    id          TEXT PRIMARY KEY,                  -- Wazuh alert id (or burst:... for our own correlation)
    timestamp   TEXT NOT NULL,                     -- Wazuh format, UTC (+0000): sorts as text
    source      TEXT NOT NULL,
    rule_id     TEXT NOT NULL,
    priority    TEXT NOT NULL,                     -- decision engine's final priority
    description TEXT NOT NULL,
    agent_name  TEXT NOT NULL,
    user        TEXT,
    src_ip      TEXT,
    sensor      TEXT NOT NULL DEFAULT 'wazuh-lab',  -- which collector/SIEM sent it (multi-source)
    data        TEXT NOT NULL,                     -- JSON: normalized Alert
    decision    TEXT NOT NULL                      -- JSON: priority, reasons, proposals
);
CREATE INDEX IF NOT EXISTS alerts_ts ON alerts (timestamp);
CREATE TABLE IF NOT EXISTS chat_messages (             -- assistant conversations: advice, not decisions
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scope       TEXT NOT NULL,                     -- incident id, or 'overview' for the queue
    role        TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
    actor       TEXT NOT NULL,                     -- analyst name, or the model name
    content     TEXT NOT NULL,
    at          TEXT NOT NULL,
    duration_s  REAL
);
CREATE INDEX IF NOT EXISTS chat_scope ON chat_messages (scope, id);
CREATE TABLE IF NOT EXISTS agent_assessments (          -- responder agent output per incident (advisory)
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    model       TEXT NOT NULL,
    assessment  TEXT NOT NULL,
    confidence  TEXT NOT NULL,
    next_steps  TEXT NOT NULL,                      -- JSON list of {technique, step, watch_for}
    skills_used TEXT NOT NULL,                      -- JSON list of red-team skill names
    at          TEXT NOT NULL,
    duration_s  REAL
);
CREATE INDEX IF NOT EXISTS assess_inc ON agent_assessments (incident_id, id);
CREATE TABLE IF NOT EXISTS settings (                   -- small key/value (e.g. autopilot on/off)
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (                      -- console accounts (auth + RBAC)
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT NOT NULL UNIQUE COLLATE NOCASE,
    pw_hash     TEXT NOT NULL,                      -- pbkdf2$<iters>$<salt_hex>$<hash_hex>
    role        TEXT NOT NULL DEFAULT 'viewer',     -- viewer | analyst | admin
    tenant      TEXT NOT NULL DEFAULT 'default',    -- groundwork for per-tenant isolation (C2)
    created_at  TEXT NOT NULL,
    last_login  TEXT
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
    BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
    BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect(path: Path | str = DB_PATH) -> sqlite3.Connection:
    if str(path) != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    _migrate(conn)
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    """Add columns introduced after the first release, so existing databases keep working."""
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(incidents)")}
    with conn:
        for name in ("verdict", "verdict_by", "verdict_at"):
            if name not in cols:
                conn.execute(f"ALTER TABLE incidents ADD COLUMN {name} TEXT")
        pcols = {r["name"] for r in conn.execute("PRAGMA table_info(proposals)")}
        if "source" not in pcols:
            conn.execute("ALTER TABLE proposals ADD COLUMN source TEXT NOT NULL DEFAULT 'rule'")
        acols = {r["name"] for r in conn.execute("PRAGMA table_info(alerts)")}
        if acols and "sensor" not in acols:
            conn.execute("ALTER TABLE alerts ADD COLUMN sensor TEXT NOT NULL DEFAULT 'wazuh-lab'")


ALERT_RETENTION_DAYS = 7


def wazuh_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+0000")


def save_alerts(conn: sqlite3.Connection, results: list) -> int:
    """Store normalized alerts + their decisions so the dashboard never waits on Wazuh.

    results: list of (Alert, Decision). Alerts are replaced, not audited: they are data,
    not decisions. Old alerts are pruned to keep the database small.
    """
    rows = []
    for a, d in results:
        decision = {"priority": d.priority, "rule_priority": d.rule_priority, "ai_severity": d.ai_severity,
                    "reasons": d.reasons, "proposals": [p.to_dict() for p in d.proposals], "vetoed": d.vetoed}
        rows.append((a.id, a.timestamp, a.source, a.rule_id, d.priority, a.description, a.agent_name,
                     a.user, a.src_ip, getattr(a, "sensor", "wazuh-lab"),
                     json.dumps(a.to_dict(), ensure_ascii=False), json.dumps(decision)))
    cutoff = wazuh_ts(datetime.now(timezone.utc) - timedelta(days=ALERT_RETENTION_DAYS))
    with conn:
        conn.executemany("INSERT OR REPLACE INTO alerts (id, timestamp, source, rule_id, priority, description, "
                         "agent_name, user, src_ip, sensor, data, decision) "
                         "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)
        conn.execute("DELETE FROM alerts WHERE timestamp < ?", (cutoff,))
    return len(rows)


def get_alerts(conn: sqlite3.Connection, ids: list[str]) -> list[sqlite3.Row]:
    if not ids:
        return []
    marks = ",".join("?" * len(ids))
    return conn.execute(f"SELECT * FROM alerts WHERE id IN ({marks}) ORDER BY timestamp", ids).fetchall()


def recent_alerts(conn: sqlite3.Connection, hours: int = 24) -> list[sqlite3.Row]:
    cutoff = wazuh_ts(datetime.now(timezone.utc) - timedelta(hours=hours))
    return conn.execute("SELECT * FROM alerts WHERE timestamp >= ? ORDER BY timestamp", (cutoff,)).fetchall()


def latest_alerts(conn: sqlite3.Connection, limit: int = 100, priority: str | None = None,
                  sensor: str | None = None, q: str | None = None) -> list[sqlite3.Row]:
    """Newest alerts first, for the live feed. Optional filters: priority, sensor (source), free text.

    Parameterized LIKE: `q` is only ever a bound value, never concatenated into SQL (injection-safe).
    """
    where, params = ["1=1"], []
    if priority in ("low", "medium", "high", "critical"):
        where.append("priority = ?"); params.append(priority)
    if sensor:
        where.append("sensor = ?"); params.append(sensor)
    if q and q.strip():
        where.append("(description LIKE ? OR user LIKE ? OR src_ip LIKE ? OR agent_name LIKE ? OR rule_id LIKE ?)")
        params += [f"%{q.strip()}%"] * 5
    params.append(max(1, min(limit, 500)))
    return conn.execute(f"SELECT * FROM alerts WHERE {' AND '.join(where)} "
                        f"ORDER BY timestamp DESC, rowid DESC LIMIT ?", params).fetchall()


def sensors(conn: sqlite3.Connection) -> list[str]:
    """Distinct sensors (collectors/SIEMs) seen, for the feed's filter dropdown."""
    return [r["sensor"] for r in conn.execute("SELECT DISTINCT sensor FROM alerts ORDER BY sensor")]


def sensor_stats(conn: sqlite3.Connection, hours: int = 24) -> list[dict]:
    """Per-sensor alert count (last `hours`) and most recent alert time, for the overview's Sources card."""
    cutoff = wazuh_ts(datetime.now(timezone.utc) - timedelta(hours=hours))
    rows = conn.execute(
        "SELECT sensor, COUNT(*) n, MAX(timestamp) last FROM alerts WHERE timestamp >= ? "
        "GROUP BY sensor ORDER BY n DESC", (cutoff,)).fetchall()
    return [{"sensor": r["sensor"], "count": r["n"], "last": r["last"][:19].replace("T", " ")} for r in rows]


def save_chat(conn: sqlite3.Connection, scope: str, role: str, actor: str, content: str,
              duration_s: float | None = None) -> None:
    with conn:
        conn.execute("INSERT INTO chat_messages (scope, role, actor, content, at, duration_s) VALUES (?, ?, ?, ?, ?, ?)",
                     (scope, role, actor, content, now(), duration_s))


def chat_history(conn: sqlite3.Connection, scope: str, limit: int = 30) -> list[sqlite3.Row]:
    """Most recent messages of one conversation, oldest first."""
    rows = conn.execute("SELECT * FROM chat_messages WHERE scope = ? ORDER BY id DESC LIMIT ?", (scope, limit)).fetchall()
    return list(reversed(rows))


def add_agent_proposals(conn: sqlite3.Connection, incident_id: str, proposals: list) -> int:
    """Insert responder-suggested proposals (source='agent'). Deduped by UNIQUE(incident, action, target)."""
    added = 0
    with conn:
        for p in proposals:
            cur = conn.execute(
                "INSERT OR IGNORE INTO proposals (incident_id, action, target, priority, rule, reason, source)"
                " VALUES (?, ?, ?, ?, ?, ?, 'agent')", (incident_id, p.action, p.target, p.priority, p.rule, p.reason))
            if cur.rowcount:
                audit(conn, "ai_responder", "proposal_created", incident_id, cur.lastrowid,
                      action=p.action, target=p.target, priority=p.priority, source="agent")
                added += 1
    return added


def save_assessment(conn: sqlite3.Connection, incident_id: str, model: str, assessment: str, confidence: str,
                    next_steps: list, skills_used: list, duration_s: float | None = None) -> None:
    with conn:
        conn.execute("INSERT INTO agent_assessments (incident_id, model, assessment, confidence, next_steps,"
                     " skills_used, at, duration_s) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                     (incident_id, model, assessment, confidence, json.dumps(next_steps),
                      json.dumps(skills_used), now(), duration_s))
        audit(conn, "ai_responder", "agent_assessed", incident_id, confidence=confidence, model=model)


def latest_assessment(conn: sqlite3.Connection, incident_id: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM agent_assessments WHERE incident_id = ? ORDER BY id DESC LIMIT 1",
                        (incident_id,)).fetchone()


def get_setting(conn: sqlite3.Connection, key: str, default: str = "") -> str:
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    with conn:
        conn.execute("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) "
                     "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                     (key, value, now()))


def audit(conn: sqlite3.Connection, actor: str, event: str, incident_id: str | None = None,
          proposal_id: int | None = None, **detail: object) -> None:
    """Append one audit entry. Callers commit together with the change it describes."""
    conn.execute(
        "INSERT INTO audit_log (at, actor, event, incident_id, proposal_id, detail) VALUES (?, ?, ?, ?, ?, ?)",
        (now(), actor, event, incident_id, proposal_id, json.dumps(detail, ensure_ascii=False)),
    )


def _find_open_match(conn: sqlite3.Connection, inc: Incident) -> sqlite3.Row | None:
    """Same incident seen by an earlier run (maybe with a shifted time window)?"""
    row = conn.execute("SELECT * FROM incidents WHERE id = ?", (inc.id,)).fetchone()
    if row:
        return row
    for row in conn.execute("SELECT * FROM incidents WHERE key = ? AND status = 'open'", (inc.key,)):
        gap = (parse_time(inc.first_seen) - parse_time(row["last_seen"])).total_seconds()
        if gap <= WINDOW_S and parse_time(inc.last_seen) >= parse_time(row["first_seen"]):
            return row
    return None


def save_incidents(conn: sqlite3.Connection, incidents: list[Incident]) -> dict[str, int]:
    """Insert new incidents, merge ones we already have. Idempotent: re-running changes nothing."""
    stats = {"new": 0, "updated": 0, "new_proposals": 0}
    with conn:  # one transaction: all or nothing
        for inc in incidents:
            row = _find_open_match(conn, inc)
            if row is None:
                inc_id = inc.id
                conn.execute(
                    "INSERT INTO incidents (id, key, title, priority, first_seen, last_seen, alert_ids, reasons,"
                    " vetoed, ai_notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (inc_id, inc.key, inc.title, inc.priority, inc.first_seen, inc.last_seen,
                     json.dumps(inc.alert_ids), json.dumps(inc.reasons), json.dumps(inc.vetoed),
                     json.dumps(inc.ai_notes), now(), now()),
                )
                audit(conn, "pipeline", "incident_created", inc_id, title=inc.title, priority=inc.priority)
                stats["new"] += 1
            else:
                inc_id = row["id"]
                alert_ids = list(dict.fromkeys(json.loads(row["alert_ids"]) + inc.alert_ids))
                reasons = list(dict.fromkeys(json.loads(row["reasons"]) + inc.reasons))
                vetoed = list(dict.fromkeys(json.loads(row["vetoed"]) + inc.vetoed))
                ai_notes = list(dict.fromkeys(json.loads(row["ai_notes"]) + inc.ai_notes))
                priority = max_priority(row["priority"], inc.priority)
                last_seen = max(row["last_seen"], inc.last_seen, key=parse_time)
                old = (json.loads(row["alert_ids"]), row["priority"], row["last_seen"], json.loads(row["ai_notes"]))
                if (alert_ids, priority, last_seen, ai_notes) != old:
                    conn.execute(
                        "UPDATE incidents SET priority=?, last_seen=?, alert_ids=?, reasons=?, vetoed=?, ai_notes=?,"
                        " updated_at=? WHERE id=?", (priority, last_seen, json.dumps(alert_ids), json.dumps(reasons),
                                                     json.dumps(vetoed), json.dumps(ai_notes), now(), inc_id))
                    if priority != row["priority"]:
                        audit(conn, "pipeline", "incident_escalated", inc_id, old=row["priority"], new=priority)
                    stats["updated"] += 1
            for p in inc.proposals:
                cur = conn.execute(
                    "INSERT OR IGNORE INTO proposals (incident_id, action, target, priority, rule, reason)"
                    " VALUES (?, ?, ?, ?, ?, ?)", (inc_id, p.action, p.target, p.priority, p.rule, p.reason))
                if cur.rowcount:
                    audit(conn, "pipeline", "proposal_created", inc_id, cur.lastrowid,
                          action=p.action, target=p.target, priority=p.priority, rule=p.rule)
                    stats["new_proposals"] += 1
    return stats


def list_incidents(conn: sqlite3.Connection, status: str | None = "open") -> list[sqlite3.Row]:
    order = "CASE priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, last_seen DESC"
    if status:
        return conn.execute(f"SELECT * FROM incidents WHERE status = ? ORDER BY {order}", (status,)).fetchall()
    return conn.execute(f"SELECT * FROM incidents ORDER BY {order}").fetchall()


def get_incident(conn: sqlite3.Connection, incident_id: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()


def get_proposals(conn: sqlite3.Connection, incident_id: str) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM proposals WHERE incident_id = ? ORDER BY id", (incident_id,)).fetchall()


def get_proposal(conn: sqlite3.Connection, proposal_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM proposals WHERE id = ?", (proposal_id,)).fetchone()


def audit_entries(conn: sqlite3.Connection, incident_id: str | None = None, limit: int = 50) -> list[sqlite3.Row]:
    if incident_id:
        return conn.execute("SELECT * FROM audit_log WHERE incident_id = ? ORDER BY id DESC LIMIT ?",
                            (incident_id, limit)).fetchall()
    return conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()


# ---------- users (auth / RBAC) ----------

def create_user(conn: sqlite3.Connection, username: str, pw_hash: str, role: str, tenant: str = "default") -> int:
    with conn:
        cur = conn.execute("INSERT INTO users (username, pw_hash, role, tenant, created_at) VALUES (?, ?, ?, ?, ?)",
                           (username, pw_hash, role, tenant, now()))
    return cur.lastrowid


def get_user(conn: sqlite3.Connection, username: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)).fetchone()


def list_users(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM users ORDER BY username").fetchall()


def count_users(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) n FROM users").fetchone()["n"]


def set_user_password(conn: sqlite3.Connection, username: str, pw_hash: str) -> None:
    with conn:
        conn.execute("UPDATE users SET pw_hash = ? WHERE username = ? COLLATE NOCASE", (pw_hash, username))


def set_user_role(conn: sqlite3.Connection, username: str, role: str) -> None:
    with conn:
        conn.execute("UPDATE users SET role = ? WHERE username = ? COLLATE NOCASE", (role, username))


def touch_login(conn: sqlite3.Connection, username: str) -> None:
    with conn:
        conn.execute("UPDATE users SET last_login = ? WHERE username = ? COLLATE NOCASE", (now(), username))
