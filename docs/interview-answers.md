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

---

## Phase 1: Wazuh lab

### 1. Walk me through Wazuh's architecture and what each port is for.
**Model answer:**
"Wazuh has four parts. Agents on endpoints collect logs, like Windows event logs, and send them to the manager on port 1514; new agents enroll on 1515. The manager decodes each event and runs it through rules; anything that matches becomes an alert written to alerts.json. Filebeat ships those alerts to the indexer, which is OpenSearch, on 9200, where they're stored and searchable. The dashboard is the web UI on 443. The manager also exposes a REST API on 55000, which is what my Python code uses. I ran manager, indexer and dashboard as a single-node Docker Compose stack."

**My answer:**

### 2. How does the Wazuh API authenticate you, and why use a token instead of sending the password every time?
**Model answer:**
"You POST to /security/user/authenticate with HTTP Basic auth, which is just base64 of user:password, so it has to go over TLS because base64 is encoding, not encryption. The API returns a JWT: three base64 parts, header, payload with the user and expiry, and a signature. Every later request sends it as a Bearer token. That means the password crosses the wire once, the token expires after 15 minutes so a leaked one has limited value, and the server can check the signature without a password lookup each time. My code also never logs the full token, only the first few characters."

**My answer:**

### 3. Why do the components use TLS, what is the root CA for, and what's the risk of disabling verification?
**Model answer:**
"Alerts and credentials move between agent, manager, indexer and dashboard, so TLS encrypts that traffic and lets each side prove its identity. Before the first start I generated a private root CA and used it to sign a certificate for each component; each one trusts anything signed by that CA. Because the CA is self-signed, my Python client currently skips verification, which means it would accept an impostor's certificate: a man-in-the-middle risk. It's acceptable on localhost for a lab, and the fix, which I've noted for Phase 3, is to verify against root-ca.pem instead of turning checks off."

**My answer:**

### 4. Tell me about a deployment problem you debugged.
**Model answer:**
"My first Wazuh attempt failed with 'error mounting filebeat.key: not a directory'. The compose file bind-mounts certificate files into the containers, but the certs hadn't been generated. When a bind-mount source doesn't exist, Docker creates an empty directory there, and you can't mount a directory onto a file. The fix was ordering: generate certs first. I put that in an idempotent setup script so it can't be skipped. A second one: the API returned HTTP 500 right after startup, not 401. I read the manager logs, saw it was still initializing, and changed my error message so a 500 says 'still starting' instead of wrongly blaming credentials."

**My answer:**

### 5. Why pin the version and make the setup script idempotent?
**Model answer:**
"Pinning to v4.9.2 means the lab builds the same way every time; pulling 'latest' could silently change config formats or break the API my code depends on. Idempotent means running the script again is safe: it only clones if the folder is missing and only generates certs if a marker file says it hasn't happened. That matters here because regenerating certs on a running stack would break TLS between the components. I tested it by running the script twice; the second run changed nothing."

**My answer:**
