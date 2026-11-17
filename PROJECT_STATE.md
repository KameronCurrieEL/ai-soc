# PROJECT_STATE.md
Last updated: 2026-11-17 (RESTART: rebuilding from scratch with Claude Code)

## Goal
AI-assisted SOC: Wazuh -> Python -> AI Analyst -> Decision Engine -> SOC Agent -> Human Approval -> Response
Free/local only. See CLAUDE.md for rules, docs/ROADMAP.md for phases.

## Environment
- Lenovo Yoga 6, Windows 11, WSL2 Ubuntu 24.04, Docker Desktop
- Wazuh 4.9.2 single-node Docker Compose (to be rebuilt)
- Ollama on Windows (qwen2.5:3b), reached from WSL via Windows host IP (changes after reboot)

## Phase status
- Phase 0 Workspace: IN PROGRESS. Code done (checks.py, tests, Makefile, .env pattern); waiting on make/Docker/Ollama fixes on the host
- Phases 1-8: not started
- Prior attempt (archived): Phases 1-4 worked, Phase 5 partial. Reuse lessons, not code.

## Lessons from the first attempt
- WSL -> Windows Ollama IP may change after reboot; check if connection fails
- [add: anything that was painful the first time]

## Decisions made (and why)
- Health checks use stdlib only (urllib, subprocess) + own .env parser: zero deps, every line explainable
- Local LLM via Ollama: free, private, no API keys
- Plain Python first: easier to explain in interviews; framework only if needed (decide at Phase 6)

## Open questions
- Agent framework at Phase 6: plain Python vs LangGraph/CrewAI/AutoGen
- Keep qwen2.5:3b or test a larger local model for better triage quality?

## Known issues / gotchas
- /etc/resolv.conf nameserver (10.255.255.254) is WSL's DNS-tunneling proxy, NOT the Windows host. Windows host = WSL default gateway (`ip route`, or /proc/net/route). checks.py auto-detects it.
- Ollama on Windows binds to 127.0.0.1 by default -> unreachable from WSL. Needs OLLAMA_HOST=0.0.0.0 + Windows Firewall allow on TCP 11434.
- `docker` CLI present doesn't mean the daemon is up: check with `docker info`, not `docker --version`.
- `make` isn't preinstalled on Ubuntu WSL: `sudo apt install make`.

## Next step
Phase 0: fix host-side issues until `make check` is all OK: install make, start Docker Desktop, expose Ollama to WSL (OLLAMA_HOST=0.0.0.0, firewall rule, `ollama pull qwen2.5:3b`). Then write Phase 0 interview questions and close the phase.

## Concepts I can explain (interview check)
- [ ] Wazuh architecture: manager, indexer, dashboard, agent
- [ ] Wazuh rule hierarchy / rule 60122
- [ ] 4624 vs 4625
- [ ] Why AI output is structured, validated JSON
- [ ] Why a human approval gate exists
- [ ] MITRE ATT&CK mapping
