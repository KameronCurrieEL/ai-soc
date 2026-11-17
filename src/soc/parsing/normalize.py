"""Normalize raw Wazuh alerts (indexer documents) into our Alert schema.

normalize(raw) never raises on missing fields: an alert we can't fully read still
becomes a valid Alert with the common fields, so one odd log can't stop the pipeline.
"""

from __future__ import annotations

from soc.parsing.schema import Alert, ip_scope, wazuh_severity
from soc.parsing.windows import clean, failure_reason, logon_type


def _get(d: dict, *path: str) -> dict:
    """Safe nested *object* lookup: _get(raw, "data", "win", "eventdata") -> {} if any level
    is missing or isn't an object, so callers can always use .get() on the result."""
    for key in path:
        d = d.get(key) if isinstance(d, dict) else None
        if d is None:
            return {}
    return d if isinstance(d, dict) else {}


def detect_source(raw: dict) -> str:
    decoder = str(_get(raw, "decoder").get("name") or "")
    if decoder == "windows_eventchannel":
        return "windows_event"
    if decoder.startswith("syscheck") or raw.get("location") == "syscheck":
        return "fim"
    if decoder == "sca" or _get(raw, "data", "sca"):
        return "sca"
    if decoder == "ossec":
        return "wazuh"
    return "other"


def _fix_path(p: str | None) -> str | None:
    """Wazuh double-escapes backslashes in Windows paths (C:\\\\Windows)."""
    return p.replace("\\\\", "\\") if p else p


def _windows(raw: dict) -> dict:
    ev = _get(raw, "data", "win", "eventdata")
    sysinfo = _get(raw, "data", "win", "system")
    details = {
        "host": clean(sysinfo.get("computer")),
        "logon_type": logon_type(ev.get("logonType")),
        "failure_reason": failure_reason(ev.get("status"), ev.get("subStatus")),
        "requested_by": clean(ev.get("subjectUserName")),
        "process": _fix_path(clean(ev.get("processName"))),
        "workstation": clean(ev.get("workstationName")),
    }
    return {
        "user": clean(ev.get("targetUserName")),
        "src_ip": clean(ev.get("ipAddress")),
        "event_id": clean(sysinfo.get("eventID")),
        "details": details,
    }


def _fim(raw: dict) -> dict:
    sc = _get(raw, "syscheck")
    path = sc.get("path")
    if sc.get("value_name"):
        path = f"{path}\\{sc['value_name']}"
    details = {
        "path": path,
        "change": sc.get("event"),  # added | modified | deleted
        "changed_attributes": ",".join(sc.get("changed_attributes", [])) or None,
        "value_type": sc.get("value_type"),
    }
    return {"user": sc.get("uname_after"), "details": details}


def _sca(raw: dict) -> dict:
    sca = _get(raw, "data", "sca")
    check = sca.get("check") or {}
    details = {
        "policy": sca.get("policy"),
        "check": check.get("title"),
        "result": check.get("result"),   # passed | failed | not applicable
        "score": str(sca["score"]) if "score" in sca else None,  # summary alerts only
    }
    return {"details": details}


def _generic(raw: dict) -> dict:
    """Common Wazuh decoder fields for other logs (e.g. Linux sshd)."""
    data = _get(raw, "data")
    return {"user": data.get("dstuser") or data.get("srcuser"), "src_ip": data.get("srcip")}


EXTRACTORS = {"windows_event": _windows, "fim": _fim, "sca": _sca, "other": _generic}


def normalize(raw: dict) -> Alert:
    rule = _get(raw, "rule")
    agent = _get(raw, "agent")
    mitre = rule.get("mitre") or {}
    source = detect_source(raw)
    extra = EXTRACTORS.get(source, lambda _r: {})(raw)
    try:
        level = int(rule.get("level", 0))
    except (TypeError, ValueError):
        level = 0
    previous = raw.get("previous_output") or ""
    src_ip = extra.get("src_ip")
    return Alert(
        id=str(raw.get("id", "")),
        timestamp=str(raw.get("timestamp", "")),
        source=source,
        rule_id=str(rule.get("id", "")),
        rule_level=level,
        wazuh_severity=wazuh_severity(level),
        description=str(rule.get("description", "")).strip().rstrip("."),
        agent_id=str(agent.get("id", "")),
        agent_name=str(agent.get("name", "")),
        mitre_ids=tuple(mitre.get("id", [])),
        mitre_tactics=tuple(mitre.get("tactic", [])),
        user=extra.get("user"),
        src_ip=src_ip,
        src_ip_scope=ip_scope(src_ip),
        event_id=extra.get("event_id"),
        related_count=len(previous.splitlines()),
        details={k: v for k, v in extra.get("details", {}).items() if v},
    )
