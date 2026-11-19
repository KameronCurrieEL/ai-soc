# Red-team skills (vendored)

Offensive-security methodology skills from **snailsploit/claude-red**
(https://github.com/snailsploit/claude-red), MIT License, (c) 2024-2025 SnailSploit / Kai Aizen.
See `skills/LICENSE`.

**How we use them (defensive only).** These describe *attacker* tradecraft. The SOC responder
agent reads the relevant ones to predict what an attacker would do next and what to watch for,
so the analyst gets ahead of the attack. The agent's *actions* are always defensive
(block / isolate / disable / investigate), guard-checked, dry-run, and human-approved.
Nothing here is executed; the agent never emits offensive commands.

- `skills/<category>/<name>/SKILL.md` — the vendored skill bodies (reference).
- `skills_index.json` — {category, name, description, path} per skill; the agent selects from this.
- Regenerate the index: `python -I <scratch>/mkindex.py src/soc/ai/redteam/skills src/soc/ai/redteam/skills_index.json`
