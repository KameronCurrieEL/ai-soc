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
- Phase 2 Telemetry: DONE 2026-11-17.
  - Agent 001 "windows-host" active, manager address now 127.0.0.1 (survives reboots).
  - 4624 -> rule 60106 (so far only SYSTEM service logons, logonType 5). 4625 -> rule 60122 (lvl 5).
  - Brute-force correlation 60204 (lvl 10, T1110) fired 3x on a 20-attempt run.
  - Sanitized samples in data/samples/ (4624, 4625, 60204).
- Phase 3 Retrieval: DONE 2026-11-17. 49 tests pass.
  - `make agents` (manager API, Bearer token) and `make alerts ARGS="--last 1h --min-level 5 --rule 60204 --save"` (indexer _search).
  - TLS verification ON: indexer verified against Wazuh root CA with expected name wazuh.indexer; API cert (self-signed) pinned. `make wazuh-certs` copies both into infra/certs/ (gitignored).
- Phase 4 Parsing: DONE 2026-11-17. 83 tests pass.
  - src/soc/parsing/: schema.py (Alert dataclass, wazuh_severity bands, ip_scope), windows.py (logon types + NTSTATUS -> words), normalize.py (dispatch by decoder: windows_event | fim | sca | wazuh | other).
  - `make alerts ARGS="--last 24h --limit 1000 --json"` -> JSONL of normalized alerts (status lines on stderr). Stress test: 1000 real alerts, 0 crashes.
- Phases 5-8: not started
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
- TLS: indexer cert is issued to "wazuh.indexer" (not localhost) -> client checks that name while connecting to localhost (WAZUH_INDEXER_TLS_NAME). API cert is self-signed and separate from the root CA -> pinned (WAZUH_API_CA_FILE). If Wazuh certs are regenerated, re-run `make wazuh-certs`.
- Alerts are NOT in the manager API in 4.x; they're in the indexer (9200, index pattern wazuh-alerts-*). Agents come from the manager API (55000).
- 4624 rule 60106 so far only matches SYSTEM service logons; interactive user logons didn't produce 60106 alerts.
- Windows agent ossec.conf had <address> hardcoded to the WSL eth0 IP (172.24.228.45), which changes on reboot. Fix: 127.0.0.1 (Docker Desktop publishes 1514/1515 on Windows localhost; verified port 1515 reachable).
- Agent re-enrollment is automatic: when the manager rejects an old key, a 4.x agent requests a new one on 1515.
- Generate 4625 with a NON-EXISTENT user: wrong passwords on your real account can trigger lockout (Win11 default ~10 attempts).
- Rule 60204 did NOT fire on a 10-failure burst sent in the same millisecond (firedtimes out of order -> parallel processing). Fired fine with 1 s spacing. Phase 6: count failures ourselves, don't rely only on Wazuh correlation.
- Wazuh maps single 4625 (60122) to T1531 "Account Access Removal" (questionable); only 60204 gets T1110. Parser: keep Wazuh MITRE tags but don't trust blindly.
- Python's ipaddress.is_private also covers documentation/reserved ranges (e.g. 203.0.113.0/24). ip_scope checks RFC1918/CGNAT/ULA explicitly and returns "reserved" for the rest.
- SCA (config benchmark) alerts are ~40% of volume and many are level 7 ("medium") even when the check PASSED. Phase 6: don't treat SCA like attacks; filter result=passed.
- Normalized output still contains real host/user names (only committed samples are sanitized). Fine for the local LLM; never commit data/outputs.
- In alerts, decoded Windows fields live under data.win.eventdata.* (rules refer to them as win.eventdata.*).
- Indexer uses the admin user (lab). Real deployment: a read-only role limited to wazuh-alerts-*.

## Next step
Phase 5 (AI analyst): src/soc/ai/: Ollama client (stdlib HTTP, reuse OLLAMA_URL auto-detect from soc.checks), prompt built from a normalized Alert, JSON schema validation of the reply ({summary, severity, risks, recommendations}), one retry then logged failure. Eval set of ~10 normalized sample alerts with expected severity; owner reviews results.
Session start: `make check && make wazuh-up && make wazuh-check`.
Interview practice DEFERRED (owner's choice) until most phases are done: then answer questions from docs/interview-answers.md (incl. own STAR story for Phase 1 Q4). Keep adding Q + model answers each phase.

## Concepts I can explain (interview check)
- [~] Wazuh architecture: manager, indexer, dashboard, agent (Phase 1 covered manager/indexer/dashboard; agent in Phase 2)
- [~] Wazuh rule hierarchy / rule 60122 / correlation 60204
- [~] 4624 vs 4625 (incl. subStatus codes)
- [ ] Why AI output is structured, validated JSON
- [ ] Why a human approval gate exists
- [~] MITRE ATT&CK mapping (kept from Wazuh; 60122->T1531 questionable, 60204->T1110)

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

## Interview questions I can now answer (Phase 2)
(Model answers: docs/interview-answers.md)
- What's the difference between 4624 and 4625, and which 4625 fields matter for triage?
- How does a Wazuh correlation rule like 60204 work?
- Tell me about a detection that didn't fire when you expected it to.
- Why point the agent at 127.0.0.1 instead of the WSL IP?
- Why sanitize sample alerts before committing them?

## Interview questions I can now answer (Phase 3)
(Model answers: docs/interview-answers.md)
- In Wazuh 4.x, where do agents and alerts live, and how do you query each?
- How did you build a safe search query from user input?
- What does TLS certificate verification check, and what's the risk of turning it off?
- The indexer cert says "wazuh.indexer" but you connect to localhost. How did you verify it properly?
- What is certificate pinning and when is it appropriate?

## Interview questions I can now answer (Phase 4)
(Model answers: docs/interview-answers.md)
- Why normalize alerts into your own schema instead of passing raw SIEM JSON along?
- How do you handle alerts from different sources (Windows events, FIM, SCA) in one schema?
- Why translate codes like 0xc0000064 before sending alerts to the LLM?
- How did you make the parser robust against malformed or unexpected alerts?
- Why does your schema classify source IPs as loopback/private/public/reserved?
