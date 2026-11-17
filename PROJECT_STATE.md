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
- Phase 0 Workspace: DONE 2026-11-17. Health check all OK (Python 3.12, Docker 29.9.3, Ollama qwen2.5:3b at WSL gateway). 8 tests pass.
- Phase 1 Wazuh lab: DONE 2026-11-17. `make wazuh-up` starts stack (project ai-soc-wazuh); dashboard login OK; `make wazuh-check` gets a JWT. 13 tests pass.
- Phases 2-8: not started
- Prior attempt (archived): Phases 1-4 worked, Phase 5 partial. Reuse lessons, not code.

## Lessons from the first attempt
- WSL -> Windows Ollama IP may change after reboot; check if connection fails
- Attempt 1 Wazuh failed: certs missing at `up` -> Docker created empty dirs at the bind-mount paths ("not a directory"). Generate certs FIRST. Old stack removed 2026-11-17.
- [add: anything that was painful the first time]

## Decisions made (and why)
- Wazuh compose repo cloned at pinned tag v4.9.2 by script, gitignored (not vendored; contains private keys)
- Separate compose project name `ai-soc-wazuh` so it can't collide with other stacks' volumes
- Lab uses Wazuh default credentials, localhost only; creds live in .env
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
- `make` isn't preinstalled on Ubuntu WSL: `sudo apt install make` (needs a real terminal for the sudo password, not the `!` prompt).
- Wazuh API returns HTTP 500 for ~30s after start (users/RBAC not ready). Wait and retry.
- Wazuh cert dir is root-owned 0500; setup script uses a `.certs_generated` marker file instead of looking inside.
- Lab TLS verification is OFF (self-signed CA). Phase 3: verify against root-ca.pem.

## Next step
Phase 2: Telemetry. Install the Wazuh agent on the Windows host, enroll it to the manager (port 1515), confirm it shows Active, then generate 4625 (failed logon) and 4624 (success) events and find them as alerts in the dashboard.
Session start: `make check && make wazuh-up && make wazuh-check`.

## Concepts I can explain (interview check)
- [~] Wazuh architecture: manager, indexer, dashboard, agent (Phase 1 covered manager/indexer/dashboard; agent in Phase 2)
- [ ] Wazuh rule hierarchy / rule 60122
- [ ] 4624 vs 4625
- [ ] Why AI output is structured, validated JSON
- [ ] Why a human approval gate exists
- [ ] MITRE ATT&CK mapping

## Interview questions I can now answer (Phase 0)
(Model answers + my practice attempts: docs/interview-answers.md)
- How does a WSL2 Linux VM reach a service running on the Windows host, and why can't you hardcode that IP?
- Why does Ollama need OLLAMA_HOST=0.0.0.0 to be reachable from WSL? (loopback 127.0.0.1 vs all interfaces, plus firewall)
- What's the difference between the docker CLI being installed and the Docker daemon running? How do you test the daemon?
- How do you keep secrets out of a git repo? (.env + .gitignore + committed .env.example)
- Why write health checks that return structured results and exit codes instead of just printing?

## Interview questions I can now answer (Phase 1)
(Model answers: docs/interview-answers.md)
- Walk me through Wazuh's architecture and what each port is for.
- How does the Wazuh API authenticate you, and why use a token instead of sending the password every time?
- Why do the Wazuh components use TLS, what is the root CA for, and what's the risk of disabling verification?
- Tell me about a deployment problem you debugged. (cert bind-mount "not a directory"; API 500 startup race)
- Why pin the version and make the setup script idempotent?
