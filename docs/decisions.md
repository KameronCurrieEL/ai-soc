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
