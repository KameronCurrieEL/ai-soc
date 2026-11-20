# Decisions

Short records of choices that shape the project: context, decision, why, consequences.

---

## D1 (2026-11-17): Local LLM via Ollama, behind a swappable interface

**Context.** Phase 5 needs a model to triage alerts. Options: local model via Ollama (qwen2.5:3b), a cloud API (e.g. Claude), or a larger local model.

**Decision.** Ollama with qwen2.5:3b, accessed only through a small `LLM` protocol in `src/soc/ai/llm.py` (`complete(system, user, schema) -> str`). Cloud backends are allowed later as an *add-on* class, not a rewrite.

**Why.**
- Free-only rule (CLAUDE.md): a cloud API is billed per call; the lab produces ~1000 alerts/day.
- Privacy: normalized alerts contain real hostnames, usernames and paths. A local model keeps them on the machine.
- Works offline, no API keys to protect.
- The interface keeps the pipeline vendor-neutral: the analyst, prompt, contract and eval set don't change if the backend does.

**Consequences.**
- Quality is limited: in the first tests the 3B model hallucinated (called 4625 a *successful* logon; invented "persistence via svchost"). Mitigations: translate codes in the parser, strict output validation + one retry, a labeled eval set, and a human approval gate before any action.
- Speed: CPU-only (no VRAM used), ~4-8 tokens/s, ~30-40 s per alert. Mitigations: 400-token cap, length limits in the schema, short-answer instructions. Not suitable for every alert in real time; Phase 6 should pre-filter what reaches the model.
- Open: compare qwen2.5:7b (or similar) on the same eval set before deciding to switch.

### D1 update (2026-11-17): eval results
Eval set of 16 owner-reviewed cases. qwen2.5:3b: 100% valid JSON, 62% exact severity, 69% acceptable, 4 under-calls (all real threats), and a successful prompt injection via the username field. Prompt v2 (rubric edits) produced identical scores. Conclusion: the model is useful for summaries and routine noise, not as the decision-maker. Phase 6 rules decide; AI severity may raise but never lower priority.

---

## D2 (2026-11-17): Plain Python for the decision engine; no agent framework

**Context.** CLAUDE.md: no agent framework (LangGraph/CrewAI/AutoGen) until Phase 6, and only if plain Python is clearly insufficient.

**Decision.** Plain Python. Rules are pure functions `Alert -> RuleHit | None`; safety guards are pure functions `Proposal -> veto reason | None`; the engine is a short loop. Revisit only if Phase 7 orchestration needs durable multi-step state that a queue + audit log can't handle.

**Why.**
- The Phase 5 eval showed the LLM can't be the decision-maker (4 under-calls, successful prompt injection). An agent framework's value is letting a model plan and call tools; that is exactly the autonomy this project must NOT give the model.
- Deterministic rules are testable (each eval case is a unit test), explainable to an approver (every proposal has a rule name and reason), and immune to text an attacker controls.
- Zero dependencies: every line can be explained in an interview.

**Consequences.**
- Final priority = max(rule priority, AI severity): the AI can raise, never lower. Proposals come only from rules; guards re-check targets themselves (they vetoed a block on a documentation IP that the data mislabeled "public").
- Rules must be written and maintained by hand. The engine scores 16/16 on the eval set, but the rules were written after seeing those cases (overfitting risk): a held-out set of new cases is needed for an honest score.
- Failed configuration checks go to a hardening backlog report, not the approval queue (they produced 262 of 267 proposals on day one).

---

## D3 (2026-11-17): Flask for the local web dashboard (Phase 7b)

**Context.** The approval queue needs a browser UI. Options: Python's stdlib `http.server`, Flask, or a heavier framework (Django, FastAPI + frontend).

**Decision.** Flask 3.1 (pinned in requirements.txt), server-rendered Jinja2 templates, no JavaScript. The UI is a thin layer over `soc.agent.store` / `approval` / `pipeline`; it contains no decision logic.

**Why.**
- Jinja2 autoescaping makes HTML-escaping the default, which is the main XSS defense when every page shows attacker-controlled log text. With `http.server` every value would need manual escaping: one miss = XSS.
- Small, free, open source, well known; still explainable line by line.
- Server-rendered forms with no JS allow a strict Content-Security-Policy (`default-src 'self'`).

**Security controls (and why).**
- Bind 127.0.0.1 only; reject any Host header other than localhost/127.0.0.1 (DNS rebinding).
- Per-session CSRF token on every POST, compared with `hmac.compare_digest`; session cookie HttpOnly + SameSite=Strict.
- CSP with `frame-ancestors 'none'` + `X-Frame-Options: DENY` (clickjacking on the Approve button).
- Flask debug mode never enabled (its debugger allows code execution).
- Same named-approver rule and audit log as the CLI.

**Consequences.** Adds one runtime dependency (+ its 6 sub-dependencies). The Flask dev server is fine for a single local user but not for a shared deployment; that would need a production WSGI server, HTTPS and real authentication (out of scope for the lab).

---

## D4 (2026-11-19): Offline GeoIP (DB-IP Country Lite), not a geolocation web API

**Context.** The incident page should say roughly where an attack came from.

**Decision.** Classify the address first (loopback / private / reserved / public, recomputed with `ip_scope`). Only public addresses get a country, looked up locally in DB-IP's free "IP to Country Lite" CSV (CC BY 4.0, ~4.5 MB, downloaded by `make geoip`, gitignored). Lookup is a binary search (`bisect`) over ~730k sorted ranges. Stdlib only.

**Why.**
- A web API (ipinfo, ip-api, ...) would be a cloud call (project rule) and would send attacker IPs to a third party, which can tip off an attacker who watches lookups of their own infrastructure.
- Non-public addresses have no meaningful location; showing "This computer" for `::1` is more useful than a country, and a database can't override that (tested with a deliberately wrong database).
- Country-level, not city: city data is ~25x larger and gives false precision.

**Consequences.** Location is approximate and says so on the page (VPN/Tor/cloud/anycast: e.g. 1.1.1.1 shows Australia). The database needs a monthly re-download to stay current. Loading takes ~6 s, so the page only loads it when an incident has a public IP. Attribution is shown whenever a country is displayed (license requirement).

---

## D5 (2026-11-19): AI assistant in the console, with one same-origin script

**Context.** The analyst wants to ask the local model questions about an incident (or the whole queue) while deciding. On CPU an answer takes ~10-40 s, so it has to stream. D3 said "no JavaScript".

**Decision.**
- **Chat panel:** an assistant panel on the queue and incident pages, backed by Ollama's streaming `/api/chat`.
- **Same-origin script:** one script, `static/assistant.js`, served from the console itself. The CSP is unchanged (`default-src 'self'`): there's still no inline script or style, and nothing loads from elsewhere.
- **Works without JavaScript:** the form also works with JavaScript off, by posting and then reloading.
- **Chat storage:** conversations are stored in their own `chat_messages` table. They are advice, not decisions, so they don't go in the audit log.

**Guardrails (why this doesn't weaken the approval gate).**
- No route the assistant uses changes incidents, proposals or the audit log (tested). It has no tools; it returns text.
- Its context is built by the same code as the incident page, so it sees exactly what the analyst sees. Log-derived values are stripped of control characters, length-capped, and placed inside `<soc_data>`. The system prompt marks that block as untrusted and says to flag instruction-like text. Phase 5 showed that delimiters alone fail, which is why the model still can't act.
- Answers are inserted with `textContent` (JS) or Jinja autoescaping (no JS): model output can never become HTML.
- The model has no memory: the last 6 turns are sent back each time, the incident context only with the newest question.

**Consequences.**
- The console is no longer 100% JS-free. The script is small, reviewed, and optional.
- Answers are only as good as a 3B model: useful for explaining and checklists, not for verdicts, which stay with the rules and the human.
- Ollama status is checked at most every 30 s for the header pill.

---

## D6 (2026-11-19): Responder agent with red-team knowledge + bounded autopilot

**Context.** The owner wants an agent that reads an incident, suggests response actions to approve, and — for a "red"-level situation while they're away from the dashboard — can act on its own. This changes the original hard rule "nothing runs without explicit human approval." The owner authorized the change (CLAUDE.md updated; rules may change as the project evolves and are recorded here).

**Decision.**
1. **Responder agent** (`src/soc/ai/responder.py`): on demand per incident, a local model reads the incident facts, predicts the attacker's likely next moves, and SUGGESTS actions. Suggestions become proposals (`source='agent'`) that the human approves like any other. The agent has no tools and cannot approve, execute or close.
2. **Red-team knowledge** (`src/soc/ai/redteam/`): 79 offensive-security skills vendored from snailsploit/claude-red (MIT). Only the ones relevant to an incident are injected (category + keyword match). They inform `attacker_next_steps` (what to watch for), never executable attack steps. The agent's actions stay the four defensive ones.
3. **Autopilot** (`approval.run_autopilot`, off by default, toggle in the UI): when ON, proposals that are `source='rule'` AND `priority='critical'` AND system-changing are approved+executed automatically as actor `autopilot`, and the incident is flagged for review.

**Why these bounds.**
- **Autopilot triggers on RULES only, never the AI.** The Phase 5 eval showed this model can be talked into a wrong severity by attacker-controlled log text. If the AI could trigger autopilot, a crafted username could cause an autonomous action. Rule-critical only (e.g. `success_after_brute_force`) keeps the trigger deterministic and testable.
- **Still dry-run.** Autopilot records the command + rollback in the audit log; it changes nothing on the host. This matches "simulate if something happened while I was away."
- **Agent suggestions pass the same gates as rules.** Target must be an entity in the incident (no invented targets), then `validate_target` (injection/format), then the safety guards (never block ourselves, never disable protected accounts). A hijacked model cannot produce a dangerous proposal.
- **Output is validated JSON** (`RESPONSE_SCHEMA`), one retry then a logged failure — same contract as the analyst.

**Model.** A bake-off (`make eval` across candidates) compares qwen2.5:3b, qwen2.5:7b and Cisco Foundation-Sec-8B-Instruct; `OLLAMA_AGENT_MODEL` selects the agent's model independently of the triage model.

**Consequences.** The console now runs autonomous actions in one narrow, audited, dry-run path. The red-team skills are offensive content (vendored, MIT, attributed) living in a defensive repo; the README explains the defensive-only use. If live execution is ever enabled, autopilot would need a hard allowlist and rate limit first.

---

## D7 (2026-11-19): Console authentication + RBAC (SIEM step C1)

**Context.** Moving toward a SaaS-style SIEM, the console needs real accounts instead of a typed-in approver name. The owner authorized changing the free/local-only rule as the project evolves.

**Decision.** Session-based login with three roles — viewer (read only), analyst (+ approve/reject/execute/close, run responder, toggle autopilot, run pipeline), admin (+ manage users). Passwords hashed with PBKDF2-HMAC-SHA256 (stdlib, 240k iterations, per-user salt), verified in constant time. No new dependencies.

**Why it also strengthens the audit trail.** The audit actor is now the authenticated username, taken from the server-side session — not a value the browser can set. A form that spoofs `by=someone-else` is ignored (tested). This closes the old gap where accountability depended on someone typing their real name.

**Controls.** All routes require login except the login page and static files; `/api/*` returns 401 when unauthenticated. State-changing routes require the analyst role; user management requires admin. CSRF, Host-header and CSP protections are unchanged. First run seeds an admin (SOC_ADMIN_USER/PASSWORD, or a generated one-time password printed to the log). Users managed via the admin UI or `python -m soc.web.auth`.

**Consequences.** `tenant` columns exist on users (default 'default') as groundwork, but data is not yet isolated per tenant — that is step C2. The Flask dev server + signed-cookie sessions are fine for the local lab; a real deployment needs a WSGI server, HTTPS and secure cookie flags.

---

## D8 (2026-11-19): Multi-tenancy by database-per-tenant (SIEM step C2)

**Context.** For a SaaS SIEM, one customer must never see another's alerts, incidents or audit log.

**Decision.** Database-per-tenant (the "silo" model): each tenant's data lives in its own SQLite file
(`data/outputs/tenants/<tenant>.db`; the `default` tenant keeps the existing `soc.db`, so current data
is untouched). Users/auth live in a shared control DB. On each request the console opens the logged-in
user's tenant DB for data and the control DB for auth. Admins assign a tenant when creating a user.

**Why this model over a tenant_id column.**
- **Provable isolation**: a query physically cannot reach another tenant's rows — there is no shared table
  to forget a `WHERE tenant = ?` on. For a security product that is the strongest, most explainable story.
- **Minimal blast radius**: the ~25 existing store queries were unchanged; only connection routing changed.
- **Easy per-tenant backup/export/delete** (one file), and a clean path to per-tenant encryption later.

**Trade-offs / consequences.** Cross-tenant analytics would need to fan out across files (not needed here).
SQLite-per-tenant suits a lab and modest SaaS; a large deployment would map the same pattern onto a
schema/database per tenant in Postgres. Autopilot and settings are naturally per-tenant (separate files).
Tests prove: incidents/alerts don't leak across tenants, cross-tenant incident IDs 404, and a tenant name
can't escape its directory (path traversal falls back to the default DB).

---

## D9 (2026-11-19): Real-execution engine behind a fail-closed switch

**Context.** Moving toward real response (and Phase 9), the console needs to actually run containment —
without ever doing so by accident. Owner chose: build the plumbing, keep it dry-run until deliberately enabled.

**Decision.** `soc.response.execution` runs an approved plan for real only when ALL hold (else dry-run or refuse):
1. process master switch `SOC_ALLOW_LIVE=1` (an operator/host decision, not a web toggle),
2. the tenant's `execution_mode` setting == "live",
3. the exact target is on the tenant's `live_allowlist`,
4. a transport backend is registered for the plan's platform.
No backend ships by default, so even fully enabled it refuses until an operator wires one (SSH for the
Phase 9 Linux honeypot, WinRM/PowerShell for Windows). Approval + autopilot both go through this engine;
live executions are audited with `live=true`. Everything is fail-closed and unit-tested (missing env,
missing allowlist entry, missing backend, bad allowlist JSON all refuse or stay dry-run).

**Why.** A security tool that can block/isolate/disable is dangerous if it fires wrongly. Four independent
preconditions mean a single mistake (one toggle, one env var, one stray target) cannot cause a real action.
`investigate` is never a live command. The human-approval gate and the rule-only autopilot trigger (D6) are
unchanged; this only governs whether the executed step is simulated or real.

**Consequences.** Going live is an explicit, auditable operator action with a per-target allowlist. The
transport backends and a settings UI for the allowlist are the remaining work before Phase 9 real actions.
