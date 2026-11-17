# Roadmap (free, local, open-source)

Each phase ends with: working demo, tests where sensible, a short writeup in docs/, interview questions answered.

| # | Phase | Build | Done when |
|---|-------|-------|-----------|
| 0 | Workspace | Repo, CLAUDE.md, .env pattern, WSL/Docker/Ollama checks | `make check` confirms Docker, Ollama and Python all respond |
| 1 | Wazuh lab | Single-node Wazuh 4.9.2 via Docker Compose, dashboard reachable | Dashboard login works; manager API returns a token |
| 2 | Telemetry | Install Windows agent, enable event log collection, generate known events (4624/4625) | Failed and successful logons show up as alerts |
| 3 | Retrieval | Python Wazuh API client: auth, list agents, fetch alerts; save sanitized samples | `python -m soc.wazuh.alerts --last 1h` prints normalized alerts |
| 4 | Parsing | Normalize alerts to our schema (rule id, level, agent, user, src ip, time, MITRE) | Unit tests pass on sample alerts |
| 5 | AI analyst | Ollama client, prompt, JSON schema validation, retry, eval set of ~10 sample alerts | Analyst returns valid JSON for all samples; results reviewed by you |
| 6 | Decision engine | Rules + thresholds map analysis to proposed actions (e.g. brute force -> propose block) | Proposals generated with reasons; nothing executes |
| 7 | Agent + approval | Orchestrate pipeline, queue proposals, CLI approve/reject, audit log; dry-run response | Approve in CLI -> action logged (and optionally run on lab host) |
| 8 | Portfolio | README with architecture diagram, demo GIF, writeups, resume bullets | A stranger can read the repo and understand it in 5 minutes |

## Attack simulations to generate data (own lab only)
Failed logons (4625) via wrong password attempts, new local user creation, service install, PowerShell encoded command, file integrity changes. Use Atomic Red Team (free) only on your own machine.

## Resume framing (fill in with real results)
- Built a local, zero-cost AI-assisted SOC pipeline: Wazuh SIEM -> Python -> LLM triage -> human-approved response
- Mapped detections to MITRE ATT&CK; validated LLM output with schema checks and a hand-labeled eval set
- Designed a human-in-the-loop approval gate so no automated action runs unreviewed
