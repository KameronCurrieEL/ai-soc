# Phase 9 — Honeypot + ESP32 attacks (setup guide)

Goal: a decoy Linux host on the lab network, watched by Wazuh, attacked from your own
LilyGO T-Embed CC1101. A hardware attack should become a Wazuh alert → an incident in the
VARDR console → you approve → the device gets blocked.

**Lab only.** Everything here targets your own honeypot on your own LAN. IP-layer attacks
against the honeypot only. No Wi-Fi deauth, no CC1101 sub-GHz transmitting (illegal / affects
neighbours, and neither produces a host log Wazuh could see anyway).

## Architecture

```
  ai-soc repo (this repo)                 bruce-vardr repo (separate, AGPL fork)
┌────────────────────────────┐   serial  ┌───────────────────────────┐
│ Python red-team recon agent │◄────────►│ Bruce on T-Embed CC1101   │
│  brain: scan analysis +     │   USB     │  hands: scan, run 1 attack│
│  ranked attack menu (you    │           └───────────────────────────┘
│  pick); Ollama + red-team   │                        │ IP-layer attack (honeypot only)
│  skills                     │                        ▼
└────────────────────────────┘             Rocky VM: Cowrie + Wazuh agent
                                                        │ alert
                                                        ▼
                     defensive responder agent → you approve → firewall block (rhel playbook)
```

Offensive agent (suggests attacks, you pick) mirrors the defensive responder (suggests
containment, you approve). Both human-gated — the AI never acts on its own (CLAUDE.md hard rule).

**Licensing:** Bruce is AGPL-3.0. Keep the Bruce fork in its **own repository**; do not paste its
C++ into `ai-soc`. The Python side merely talks to Bruce over the serial cable (a separate program,
not a derivative), so this repo keeps its own licence.

## Build order

1. **Honeypot VM** — Rocky + Cowrie + Wazuh agent (this guide). ← we are here
2. **Bruce fork** — confirm/add serial commands: `scan <target>` → ports/services; `attack <type> <target>` → one scripted IP-layer sim.
3. **Python recon agent** (`src/soc/ai/recon.py`) — drives Bruce over pyserial, analyses the scan with the local model + red-team skills, returns analysis + ranked attack menu. Built TDD against mock scan data first (no hardware needed to test).
4. **Close the loop** — pick attack → Bruce fires → Wazuh alert → incident → defensive responder suggests block → you approve. The live-radar-blip demo.

---

## Prerequisite — RAM headroom (done 2026-11-19)

Laptop has 13.8 GB; WSL2 defaults to ~50% and is slow to release it, leaving too little for a VM.
Fix written to `C:\Users\Kameron\.wslconfig`:

```ini
[wsl2]
memory=5GB                 # cap the WSL VM (Wazuh stack ~2.4GB + Python, with headroom)
autoMemoryReclaim=gradual  # return unused page cache to Windows over time
swap=2GB
```

**Apply:** run `wsl --shutdown` from a **Windows** PowerShell/CMD (stops this WSL session + Wazuh +
web server; WSL restarts on next open). Must be applied before running the VM and Wazuh together.

Memory budget with the VM running: Windows + apps ~4.5 GB · WSL ≤5 GB · Ollama ~2.5 GB when loaded ·
honeypot VM ~2 GB. Tight — close Discord/Spotify/extra browser tabs during attack sessions.

---

## Step 1b — Create the Rocky VM (VirtualBox, on Windows)

VirtualBox is already installed. Windows 11 Home, so no Hyper-V — VirtualBox is the right choice.

1. **ISO:** Rocky Linux 9 (latest 9.x), **minimal** ISO — https://rockylinux.org/download
2. **New VM:** name `vardr-honeypot`, Type Linux, Version Red Hat (64-bit); **2048 MB RAM**, **2 CPUs**; 20 GB disk, dynamically allocated.
3. **Network (the setting that matters):** Settings → Network → Adapter 1 → **Bridged Adapter**, Name = your **Wi-Fi** interface. (NAT would hide the VM from the T-Embed — don't use it.)
4. **Install:** boot the ISO → **Minimal Install**; set a root password **and** a sudo user; network toggled **ON** during install (so it gets a DHCP lease).

**Verify:** in the VM, `ip addr` (note the LAN IP, e.g. 192.168.x.x) and `ip route | grep default`.
The IP should be on the same subnet as your other home devices.

> Next session: give me the VM's IP. We confirm it from WSL, then do step 1c.

---

## Step 1c — Install Cowrie (next session)

Outline (exact commands next session, one block at a time):
- Real `sshd` stays reachable for admin but moves off port 22 (e.g. 2022) so Cowrie can own 22.
- Install Cowrie (Python venv) as a non-root user; it listens on 2222.
- Redirect TCP 22 → 2222 (firewalld or authbind) so attackers hitting "ssh" land in the honeypot.
- Cowrie logs JSON to `var/log/cowrie/cowrie.json` — that's what Wazuh will read.
- Verify: from WSL, `ssh root@<vm-ip>` with any password → it "accepts" into a fake shell; the
  attempt appears in `cowrie.json`.

## Step 1d — Wazuh agent on the VM (next session)

- Install the Wazuh agent (4.9.2, matching the manager).
- **Manager address:** the Windows host's **LAN IP** (not 127.0.0.1 — the VM is bridged on the LAN).
  Docker Desktop publishes 1514/1515; we publish them on the host LAN IP and allow TCP 1514/1515
  through Windows Firewall.
- Add a `localfile` entry so the agent tails `cowrie.json` (JSON decoder).
- Enroll on 1515, confirm the agent shows `active` via `make agents`.
- Verify: an SSH attempt on the VM → a Wazuh alert in the indexer (`make alerts`).

## Step 9.3+ (later) — Detections, then attacks

Custom Wazuh decoders/rules for Cowrie (login attempt / fake success / command / download),
map to our schema as a `honeypot` source, decision rules (any contact ≥ medium, fake success high,
command/download critical). Then steps 2–4 above.

---

## Gotchas to watch (add as we hit them)

- Bridged adapter must bind the active **Wi-Fi** NIC; a sleeping/disconnected NIC gives no DHCP lease.
- VirtualBox over WSL2's hypervisor runs in slower paravirt mode (green turtle icon) — fine for a
  small headless VM.
- Manager returns HTTP 500 for ~30 s after start; the agent may need a retry on first enroll.
