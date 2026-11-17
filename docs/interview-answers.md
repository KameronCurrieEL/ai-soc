# Interview Answers

Model answers for the interview questions in PROJECT_STATE.md, one section per phase.
Practice: read the model answer, close the file, then say it in your own words.
Add your own version under "My answer" each time you practise.

---

## Phase 0: Workspace

### 1. How does WSL2 reach a service on the Windows host, and why not hardcode the IP?
**Model answer:**
"WSL2 runs Linux in a lightweight VM with its own virtual network (NAT by default). From inside WSL, the Windows host is the default gateway, so I read the gateway from the routing table (`/proc/net/route`) instead of hardcoding it. The IP is assigned when WSL starts and can change after a reboot, so a hardcoded value would break. I also don't use `/etc/resolv.conf`, because with DNS tunneling it points at a DNS proxy (10.255.255.254), not the host."

**My answer:**

### 2. Why does Ollama need `OLLAMA_HOST=0.0.0.0` to be reachable from WSL?
**Model answer:**
"By default Ollama binds to 127.0.0.1, which is loopback, so only processes on the Windows host itself can reach it. WSL2 runs in a VM with its own virtual network, so its traffic reaches Windows through a virtual adapter, not loopback. Setting OLLAMA_HOST to 0.0.0.0 makes Ollama listen on all interfaces, and I also added a firewall rule for port 11434. Binding to all interfaces does widen exposure, so in a real environment I'd restrict that firewall rule to the WSL subnet."

**My answer (first attempt, 2026-11-17):**
"Ollama needs to be OLLAMA_HOST=0.0.0.0 to be reachable from WSL due to it being a local IP address so it can connect in a local environment."
*Feedback: right topic (which address it listens on), but 0.0.0.0 means "all interfaces", not "local". Mention loopback, all interfaces, and the firewall.*

### 3. What's the difference between the Docker CLI being installed and the daemon running?
**Model answer:**
"Docker is client-server. The `docker` command is just a client that sends API requests to the Docker daemon (dockerd), which actually runs containers. `docker --version` only proves the client is installed. `docker info` has to talk to the daemon, so that's what my health check uses. On day one the CLI was present but Docker Desktop wasn't running, and `docker info` caught it."

**My answer:**

### 4. How do you keep secrets out of a git repo?
**Model answer:**
"Secrets go in a `.env` file that's listed in `.gitignore`, so git never tracks it. I commit a `.env.example` with the same keys but no real values, so anyone cloning the repo knows what to configure. I verified it by checking `git status`: `.env.example` showed up as a new file, `.env` didn't. If a secret ever did get committed, deleting it isn't enough because it's in history; you rotate the secret."

**My answer:**

### 5. Why write health checks that return structured results and exit codes?
**Model answer:**
"Each check returns a small result object (name, ok, detail), so the logic is testable without Docker or Ollama running, and the output tells you how to fix the problem instead of dumping a stack trace. The script exits 0 if everything passes and 1 if anything fails, so other tools (make, CI, a startup script) can act on the result automatically. It's the same idea as monitoring in a SOC: a check is only useful if a machine can read its result."

**My answer:**
