"""SOC responder agent: reads an incident, thinks with red-team knowledge, SUGGESTS defensive actions.

It only proposes. Its suggested actions pass the SAME guards + target validation as rule proposals
(soc.decision.guards, soc.response.actions), so a hijacked model can't produce a dangerous proposal.
Its attacker knowledge feeds "attacker_next_steps" (what to watch for), never executable attack steps.

Model output is validated against RESPONSE_SCHEMA; invalid JSON gets one retry, then a logged failure
(same contract as the analyst). See CLAUDE.md (D6) and docs/decisions.md.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.error
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from soc.decision.guards import apply_guards
from soc.decision.models import ACTIONS, Proposal
from soc.response.actions import InvalidTarget, validate_target

log = logging.getLogger("soc.ai")

PROMPT_PATH = Path(__file__).with_name("prompts") / "responder.md"
SKILLS_INDEX = Path(__file__).with_name("redteam") / "skills_index.json"
MAX_ATTEMPTS = 2
MAX_SKILLS = 5
URGENCIES = ("routine", "soon", "immediate")

# ---------- output contract ----------

RESPONSE_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "assessment": {"type": "string", "maxLength": 600},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        "attacker_next_steps": {
            "type": "array", "maxItems": 3,
            "items": {"type": "object", "properties": {
                "technique": {"type": "string", "maxLength": 80},
                "step": {"type": "string", "maxLength": 200},
                "watch_for": {"type": "string", "maxLength": 200},
            }, "required": ["step", "watch_for"], "additionalProperties": False},
        },
        "actions": {
            "type": "array", "maxItems": 4,
            "items": {"type": "object", "properties": {
                "action": {"type": "string", "enum": list(ACTIONS)},
                "target": {"type": "string", "maxLength": 120},
                "urgency": {"type": "string", "enum": list(URGENCIES)},
                "reason": {"type": "string", "maxLength": 200},
            }, "required": ["action", "target", "reason"], "additionalProperties": False},
        },
    },
    "required": ["assessment", "confidence", "attacker_next_steps", "actions"],
    "additionalProperties": False,
}


@dataclass(frozen=True)
class Assessment:
    assessment: str
    confidence: str
    attacker_next_steps: list[dict]
    actions: list[dict]            # raw, as the model gave them (pre-guard)

    def to_dict(self) -> dict:
        return {"assessment": self.assessment, "confidence": self.confidence,
                "attacker_next_steps": self.attacker_next_steps, "actions": self.actions}


def validate(data: object) -> list[str]:
    if not isinstance(data, dict):
        return ["reply must be a JSON object"]
    errors: list[str] = []
    for f in ("assessment", "confidence", "attacker_next_steps", "actions"):
        if f not in data:
            errors.append(f"missing field: {f}")
    if "confidence" in data and data["confidence"] not in ("low", "medium", "high"):
        errors.append("confidence must be low|medium|high")
    if "assessment" in data and (not isinstance(data["assessment"], str) or not data["assessment"].strip()):
        errors.append("assessment must be a non-empty string")
    for i, a in enumerate(data.get("actions", []) if isinstance(data.get("actions"), list) else []):
        if not isinstance(a, dict) or a.get("action") not in ACTIONS or not str(a.get("target", "")).strip():
            errors.append(f"actions[{i}] needs a known action and a target")
    if not isinstance(data.get("attacker_next_steps"), list):
        errors.append("attacker_next_steps must be a list")
    return errors


def parse(text: str) -> tuple[Assessment | None, list[str]]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError) as exc:
        return None, [f"not valid JSON: {exc}"]
    errors = validate(data)
    if errors:
        return None, errors
    return Assessment(data["assessment"].strip(), data["confidence"],
                      data["attacker_next_steps"], data["actions"]), []


# ---------- red-team skill selection ----------

@lru_cache(maxsize=1)
def load_skills() -> list[dict]:
    try:
        return json.loads(SKILLS_INDEX.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []


# which skill categories matter for a given kind of incident (rule family / entities present)
FAMILY_CATEGORIES = {
    "brute_force": ("active-directory", "privesc", "network", "infrastructure"),
    "success_after_brute_force": ("active-directory", "post-exploitation", "privesc", "infrastructure"),
    "security_agent_stopped": ("infrastructure", "forensics", "post-exploitation"),
    "new_service": ("infrastructure", "post-exploitation", "privesc"),
    "config_benchmark": ("infrastructure", "privesc"),
}


def _tokens(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", text.lower()))


def select_skills(family: str, context: str, limit: int = MAX_SKILLS) -> list[dict]:
    """Pick the attacker skills most relevant to this incident: category match first, then word overlap.

    Pure text ranking over the vendored index. 'wireless'/'iot' skills surface when the incident
    mentions Wi-Fi, BLE, sub-GHz, Zigbee etc. (useful once the ESP32 attacks the honeypot).
    """
    skills = load_skills()
    if not skills:
        return []
    wanted = set(FAMILY_CATEGORIES.get(family, ()))
    ctx = _tokens(context)
    for kw, cat in (("wifi", "wireless"), ("wi-fi", "wireless"), ("wireless", "wireless"), ("bluetooth", "wireless"),
                    ("ble", "wireless"), ("zigbee", "wireless"), ("ghz", "wireless"), ("rf", "wireless"),
                    ("iot", "iot"), ("mqtt", "iot"), ("firmware", "iot")):
        if kw in ctx:
            wanted.add(cat)

    def score(s: dict) -> tuple[int, int]:
        cat_hit = 2 if s["category"] in wanted else 0
        overlap = len(ctx & _tokens(s["name"] + " " + s["description"]))
        return (cat_hit, overlap)

    ranked = sorted(skills, key=score, reverse=True)
    top = [s for s in ranked if score(s) != (0, 0)][:limit]
    return top or ranked[:2]   # always give the model at least a little context


SKILL_DESC_CHARS = 220   # trim long descriptions: keeps the prompt small so CPU inference stays fast


def format_skills(skills: list[dict]) -> str:
    if not skills:
        return "(no red-team skill index found)"
    lines = []
    for s in skills:
        desc = s["description"]
        if len(desc) > SKILL_DESC_CHARS:
            desc = desc[:SKILL_DESC_CHARS].rsplit(" ", 1)[0] + "…"
        lines.append(f"- [{s['category']}] {s['name']}: {desc}")
    return "\n".join(lines)


# ---------- prompt ----------

def load_prompt_template() -> str:
    text = PROMPT_PATH.read_text(encoding="utf-8")
    marker = "# SYSTEM PROMPT"
    return text.split(marker, 1)[1].lstrip("\n") if marker in text else text


def build_prompt(context: str, skills: list[dict]) -> str:
    return (load_prompt_template()
            .replace("{relevant_skills}", format_skills(skills))
            .replace("{incident_context}", context))


# ---------- run ----------

@dataclass
class ResponderResult:
    model: str
    assessment: Assessment | None
    attempts: int
    errors: list[str] = field(default_factory=list)
    duration_s: float = 0.0
    skills_used: list[str] = field(default_factory=list)


def stream_messages(family: str, context: str) -> tuple[list[dict], list[dict]]:
    """Build the chat messages + the selected skills for a STREAMING responder run.

    Returns (messages, skills). The caller streams with RESPONSE_SCHEMA, accumulates the text,
    then uses parse() + actions_to_proposals() on the full reply (same gates as the blocking path).
    """
    skills = select_skills(family, context)
    return [{"role": "user", "content": build_prompt(context, skills)}], skills


def respond(llm, family: str, context: str) -> ResponderResult:
    """Ask the agent about one incident. The caller turns result.assessment.actions into proposals."""
    skills = select_skills(family, context)
    prompt = build_prompt(context, skills)
    res = ResponderResult(getattr(llm, "name", "?"), None, 0, skills_used=[s["name"] for s in skills])
    user = prompt
    for attempt in range(1, MAX_ATTEMPTS + 1):
        res.attempts = attempt
        try:
            text = llm.complete("", user, RESPONSE_SCHEMA)
            res.duration_s += getattr(llm, "last_duration_s", 0.0)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            res.errors = [f"model call failed: {exc}"]
            continue
        assessment, errors = parse(text)
        if assessment:
            res.assessment, res.errors = assessment, []
            return res
        res.errors = errors
        log.info("responder attempt %d rejected: %s", attempt, "; ".join(errors))
        user = f"{prompt}\n\nYour previous reply was rejected:\n- " + "\n- ".join(errors) + "\nReturn only the JSON object."
    log.warning("responder FAILED after %d attempts: %s", res.attempts, "; ".join(res.errors))
    return res


def actions_to_proposals(assessment: Assessment, allowed_targets: set[str]) -> tuple[list[Proposal], list[str]]:
    """Turn the model's suggested actions into vetted Proposals.

    Three gates, in order: (1) target must be an entity actually in the incident (no invented targets),
    (2) soc.response validate_target (format / injection), (3) soc.decision guards (never block ourselves,
    never disable protected accounts). Urgency maps to proposal priority. Returns (proposals, rejected_reasons).
    """
    urgency_priority = {"routine": "medium", "soon": "high", "immediate": "critical"}
    candidates, rejected = [], []
    for a in assessment.actions:
        action, target = a["action"], str(a["target"]).strip()
        reason = f"AI responder ({assessment.confidence} confidence): {str(a.get('reason', '')).strip()[:180]}"
        if action != "investigate" and target not in allowed_targets:
            rejected.append(f"{action} {target!r}: target is not an entity in this incident")
            continue
        try:
            validate_target(action, target)
        except InvalidTarget as exc:
            rejected.append(f"{action} {target!r}: {exc}")
            continue
        priority = urgency_priority.get(a.get("urgency", ""), "medium")
        candidates.append(Proposal(action, target, priority, "ai_responder", reason))
    allowed, vetoed = apply_guards(candidates)
    return allowed, rejected + vetoed
