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
