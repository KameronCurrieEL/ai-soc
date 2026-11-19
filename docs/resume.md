# Resume bullets

Pick 3-4. Every number below comes from this repo and can be shown live.

**Project line:** AI-Assisted SOC (home lab): Wazuh SIEM, Python, local LLM (Ollama), Flask, SQLite, Docker, WSL2

- Built a zero-cost, fully local SOC pipeline: Wazuh SIEM → Python normalization → LLM triage → deterministic decision engine → human-approved response, processing 1,000 alerts into 2 actionable incidents with 5 LLM calls.
- Designed a human-in-the-loop approval gate: an atomic state machine, a named-approver requirement, and an append-only audit log enforced by database triggers; response actions validated against command injection and limited to dry-run.
- Evaluated a local LLM analyst on 16 hand-labelled alerts: it reached only 69% acceptable severity and fell to a prompt injection hidden in a username. Redesigned so rules decide and AI can only raise priority, reaching 16/16 with zero under-calls.
- Found a gap in Wazuh's brute-force correlation (missed a dense burst due to parallel processing) and wrote a sliding-window correlator that caught 27 failed logons in 2.5 minutes.
- Cut alert fatigue from 267 proposals to 5 by routing 262 configuration-benchmark findings to a hardening backlog instead of the approval queue.
- Built a hardened analyst web console:
  - localhost-only, with a Host-header check (DNS rebinding) and CSRF tokens
  - strict CSP, no JavaScript, autoescaped log data (XSS)
  - entity pivoting, offline IP geolocation, incident timelines and false-positive metrics per detection
- Secured SIEM API access with TLS verification against the Wazuh root CA plus certificate pinning, and wrote 246 automated tests.

**Short version (one line):**
Built a local AI-assisted SOC (Wazuh, Python, Ollama LLM) with a human approval gate, append-only audit log and hardened web console; showed with an eval set and a prompt-injection test why the LLM advises and rules decide.

**Skills line:** Wazuh · Windows event logs (4624/4625) · MITRE ATT&CK · Python · SQLite · Flask/Jinja2 · Docker · WSL2 networking · TLS/PKI · LLM evaluation · prompt injection · web security (CSRF, XSS, CSP, DNS rebinding)
