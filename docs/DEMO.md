# Demo guide

A hands-on walkthrough to test the full pipeline and console before a live demo.

- **Time:** ~30 minutes (+10 if you include the AI step).
- **Layout:** each scenario says what to do, what you should see, and what it proves.
- **Where commands run:**
  - **WSL** = Ubuntu terminal in `~/ai-soc`
  - **PS** = normal Windows PowerShell
  - **Admin PS** = PowerShell "Run as administrator"

Everything here happens on your own lab machine only. Response actions are dry-run: nothing is ever blocked or disabled.

---

## 0. Start the lab (every session)

```bash
# WSL
make check            # python / docker / ollama all [OK]
make wazuh-up         # starts manager, indexer, dashboard
make wazuh-check      # wait ~1 min after start; HTTP 500 at first is normal (see Troubleshooting)
make agents           # 001 windows-host ... active
make test             # 262 passed: proves the code before you touch live data
make web              # leave this terminal open
```

Open **http://localhost:8765** in your Windows browser. The top bar says **DRY-RUN**.

**Proves:**
- The SIEM is up and reachable over verified TLS.
- The Windows agent is reporting.
- The console only listens on localhost.

---

## 1. Brute force from this machine (the main scenario)

**Do (PS, normal, not admin):** 20 failed logons for a user that doesn't exist, 1 second apart. Never use your real account: Windows locks it after ~10 failures.

```powershell
$pw   = ConvertTo-SecureString 'Wrong-Password-1' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('soc-test-user', $pw)
1..20 | ForEach-Object {
  try { Start-Process cmd.exe -ArgumentList '/c exit' -Credential $cred -WindowStyle Hidden -ErrorAction Stop } catch {}
  Start-Sleep -Seconds 1
}
```

**Then:** wait ~1 minute and click **Refresh from Wazuh (rules only)** on the queue page.

**You should see:**
- **Queue:**
  - A new **medium** incident, "Brute force from ::1", with 1 pending proposal.
  - A spike in the 24h chart. Hover the bar for counts.
- **Incident page:**
  - **What happened:** "Someone tried and failed to sign in to the account 'soc-test-user' about 20 times … started by '<your Windows user>'".
  - **Where:** "This computer", `::1`, loopback, with the reason nothing gets blocked.
  - **Involved:** account `soc-test-user`, the process, MITRE `T1110`, rules 60122/60204 and `soc-burst` (my own correlation).
  - **Timeline:** "20× Logon Failure" collapsed into one line, then "Incident opened by the pipeline".
  - **Proposal:** `investigate`, not `block_ip`.

**Proves:**
- End-to-end detection: Windows event 4625 → Wazuh → normalize → rules → incident.
- My own correlator works alongside Wazuh's.
- Safety guards never propose blocking your own machine.

**Talking point:** "The source is loopback, so the right action is to find the process, not to firewall myself."

---

## 2. Pivot like an analyst

On the incident page:
1. Click **`soc-test-user`**. The entity page shows every stored alert for that account, its incidents, and "Seen together with" (the source IP, the process, who started it).
2. From there, click **`::1`**. The location reads "This computer", and you see all incidents from that address, including the Nov 17 one.
3. Click the host name. You see every incident on the machine.

**Proves:** you can move from one indicator to everything related to it (pivoting), and it works for older incidents too.

---

## 3. The approval gate

On the brute-force incident's proposal:
1. Clear the name field and click **Approve**. The browser refuses: a name is required.
2. Type `pipeline` as the name → **Approve**. You get **Refused: … named human**. The pipeline can never approve its own proposals.
3. Type your name, note "my own test" → **Approve**. Status becomes `approved`.
4. Click **Execute (dry-run)**. You see `[dry-run]` and the exact PowerShell command plus its rollback. Nothing ran.
5. **Close incident:** submit without a verdict first, and you're refused. Then choose **benign** (real activity, but it was you) with a note → **Close**.
6. Open **Audit log** (top bar). Every step is there with your name, the time and your reason. The refused approval is logged too.

**Proves:**
- Nothing runs without a named human.
- Every decision is accountable.
- Close verdicts feed the metrics.

---

## 4. Security agent stopped (high priority, reject path)

**Do (Admin PS):**
```powershell
Restart-Service WazuhSvc
```

**Then:** wait ~1 minute → **Refresh**.

**You should see:**
- A **high** incident, "Security monitoring stopped on windows-host".
- MITRE `T1562.001` ("Impair Defenses").
- The summary says nothing on the machine is watched while the agent is off.

**Do:** reject the proposal with reason "planned restart", then close with verdict **benign**.

**Proves:**
- Attackers disable security tools first, so this detection is rated high even though the AI rates it low.
- The reject path is audited.

---

## 5. Detection quality metrics

Open **Metrics** (top bar).

**You should see:**
- `brute_force` and `security_agent_stopped` with your verdicts counted.
- FP rate (0% if everything was benign).
- Median minutes to close.
- The two Nov 17 incidents counted as "No verdict", because they were closed before verdicts existed.

**Talking point:** "Benign isn't a false positive. The rule was right, it was me. That calls for an exception, not a rule fix."

---

## 6. Web security checks (WSL)

```bash
# DNS-rebinding protection: a request with a foreign Host header is refused
curl -s -o /dev/null -w "%{http_code}\n" -H "Host: evil.example" http://127.0.0.1:8765/      # 400
# Forged POST without a CSRF token is refused
curl -s -o /dev/null -w "%{http_code}\n" -X POST -d "by=me" http://127.0.0.1:8765/proposal/1/approve   # 400
# Security headers
curl -sI http://127.0.0.1:8765/ | grep -iE "content-security-policy|x-frame-options"
```

**Proves:** CSRF protection, the Host-header check against DNS rebinding, and CSP plus anti-framing are actually active.

---

## 7. The audit log can't be edited (WSL)

```bash
.venv/bin/python -c "
import sqlite3; c = sqlite3.connect('data/outputs/soc.db')
try: c.execute(\"UPDATE audit_log SET actor='someone-else'\")
except Exception as e: print('blocked:', e)"
```

**You should see:** `blocked: audit_log is append-only`.

**Proves:** tamper resistance is enforced by the database itself, not only by my code.

---

## 8. Optional: the AI analyst (~5-10 min on CPU)

```bash
# WSL, while Ollama runs on Windows
make soc ARGS="run --last 1h --ai"
```

Refresh the incident page. The **AI analyst** box (dashed border, "advisory") now has a summary.

**Talking point:** "The AI can raise priority, never lower it. In my eval it fell for a prompt injection in a username, so it advises and the rules decide." (see `docs/writeups/01-prompt-injection.md`)

---

## 8b. The AI assistant (in the console)

Needs Ollama running: the header pill must say **qwen2.5:3b online**.

1. On the brute-force incident, click the suggestion **"Is this likely malicious? Why?"**. The answer streams in word by word (~10-40 s on CPU).
2. Type your own question, e.g. "What should I check before approving the investigate action?", and press Enter.
3. On the queue page, ask **"What should I look at first?"**. This version sees all open incidents.
4. Reload the page: the conversation is kept, separately for each incident.
5. Open the **Audit log**: asking the AI added nothing there. Advice isn't a decision; only your clicks are.

**Proves:** the model helps you think, and the decision path doesn't change. It has no tools, it reads the same facts you see, and log text reaches it inside an untrusted-data block.

**Talking point:** "In my eval, a 3B model fell for a prompt injection, so the assistant can explain and suggest checks, but it can't act. Its answers are shown as plain text, never as HTML."

---

## 9. Screenshots for the README

Save these as PNG files in `docs/screenshots/`, then ask Claude to add them to the README:

| File | What to capture |
|---|---|
| `queue.png` | Queue page with the 24h chart showing your brute-force spike |
| `incident.png` | Brute-force incident: summary, Where, Involved, timeline |
| `entity.png` | Entity page for `soc-test-user` |
| `approval.png` | A proposal after Execute (dry-run): command + rollback |
| `metrics.png` | Metrics page with verdicts |
| `audit.png` | Audit log showing your approvals and the refused `pipeline` approval |
| `assistant.png` | Incident page with an AI assistant answer in the side panel |

Tip: Win+Shift+S (Snipping Tool). Check before committing that no real Windows user names or hostnames are visible in the screenshots, or crop them out: the repo is public.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `make wazuh-check` → HTTP 500 | Normal for ~30 s after start (users/RBAC not ready). Wait and retry. |
| `make check` → ollama FAIL | Windows host IP changed after reboot: auto-detected from the WSL default gateway. Check that Ollama runs with `OLLAMA_HOST=0.0.0.0` and the firewall allows TCP 11434. |
| Refresh finds no new incident | Wait 1-2 min (agent → manager → indexer). Check `make agents` shows *active*. Then `make alerts ARGS="--last 15m --min-level 5"`. |
| Brute force produced no 60204 alert | Expected for very dense bursts (see writeup 02). My `soc-burst` correlation still creates the incident. |
| Port 8765 in use | A previous `make web` is still running: stop it, or `.venv/bin/python -m soc.web --port 8766`. |
| Page shows "Alert details weren't stored" | The incident predates alert storage: run the pipeline once (`Refresh`). |

## Reset to a clean demo (optional)

`data/outputs/soc.db` holds the queue and audit log. To start fresh, rename it first rather than deleting it: `mv data/outputs/soc.db data/outputs/soc-backup.db`. The next pipeline run creates a new one. The audit history stays in the backup.
