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
