# AI-Assisted SOC (portfolio project)

Goal: Wazuh -> Python -> local LLM analyst -> decision engine -> SOC agent -> human approval -> response.
Purpose: demonstrate AI + cybersecurity + networking fundamentals on a resume. The owner must be able to explain every part in an interview.

## Hard rules
- FREE ONLY: Wazuh, Docker, Ollama (local models), Python stdlib/open-source libs. No paid APIs, no cloud LLM calls inside the project.
- No agent framework (LangGraph/CrewAI/AutoGen) until Phase 6, and only if plain Python is clearly insufficient. Record the decision in docs/decisions.md.
- Secrets live in `.env` (gitignored). Never commit credentials, tokens or IPs of real systems.
- Response actions (block IP, isolate host, disable account) NEVER run without explicit human approval. Default mode is dry-run.
- Lab only: only act on the owner's own Windows host/VMs.

## Environment
- Windows 11 host, WSL2 Ubuntu 24.04, Docker Desktop
- Wazuh 4.9.2 single-node Docker Compose (manager, indexer, dashboard)
- Ollama on Windows (qwen2.5:3b); reach from WSL via the Windows host IP (it can change after reboot; use `OLLAMA_URL` in `.env` or auto-detect the WSL default gateway from `/proc/net/route`. NOT `/etc/resolv.conf`: with DNS tunneling it shows 10.255.255.254, a DNS proxy)

## Working style (teaching mode)
- The owner is learning. Before writing code for a phase: explain the concept in 3-5 lines and what we will build.
- Build in small steps. After each step: run it, show the output, explain what it proved.
- After each phase, add 3-5 "interview questions I can now answer" to PROJECT_STATE.md and ask the owner to answer one in their own words.
- Prefer plain Python + tests over cleverness. Small functions, type hints, one responsibility per module.

## Session protocol
1. Start: read PROJECT_STATE.md and docs/ROADMAP.md, state the current phase and next step.
2. End: update PROJECT_STATE.md (status, decisions, gotchas, next step) and commit.
3. Commit per working step with a clear message.

## Repo layout (target)
```
infra/            docker-compose, wazuh config, setup notes
src/soc/
  wazuh/          API auth, alert/agent retrieval
  parsing/        normalize alerts to our own schema
  ai/             prompts, ollama client, analyst
  decision/       rules + thresholds -> action proposals
  agent/          orchestration + approval gate
  response/       actions (dry-run by default)
tests/
data/             sample alerts (sanitized), outputs (gitignored if sensitive)
docs/             ROADMAP.md, decisions.md, architecture, writeups
```

## AI output contract
Analyst returns JSON validated against a schema:
`{ "summary": str, "severity": "low|medium|high|critical", "risks": [str], "recommendations": [str] }`
Invalid JSON gets one retry, then a logged failure. The model never executes anything; it only proposes.
