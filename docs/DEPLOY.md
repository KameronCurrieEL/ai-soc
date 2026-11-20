# Deploying the console (home-hosted, exposed via a tunnel)

The chosen model (**option B**): everything — Wazuh, Ollama, the pipeline, the console — runs on your
home lab. Nothing moves to a cloud box. You expose only the web console through an outbound **tunnel**,
so there are no inbound firewall holes and your alert data never leaves home.

```
  browser ──HTTPS──► Cloudflare Tunnel ──► cloudflared (home) ──► 127.0.0.1:8765 (console, waitress)
                                                                      │
                                   home lab:  Wazuh · Ollama · SQLite ┘   (never exposed)
```

## 1. Run it as a production service

The console now serves with **waitress** (a real WSGI server), not the Flask dev server.

```bash
make serve                      # = SOC_PROD=1 python -m soc.web  (binds 127.0.0.1:8765)
```

Keep the bind on `127.0.0.1` — the tunnel connects to it locally; it is never reached directly.

**Environment** (set before starting; see `.env`):

| Var | Purpose |
|---|---|
| `SOC_PROD=1` | use waitress |
| `SOC_SECRET_KEY` | stable session key. If unset, a key is generated and persisted to `data/outputs/secret.key` (0600). Set it explicitly for a real deployment. |
| `SOC_HTTPS=1` | **required when exposed via the tunnel** — marks cookies Secure (sent only over HTTPS) |
| `SOC_ALLOWED_HOSTS` | your tunnel hostname(s), comma-separated, e.g. `soc.example.com`. Without this the Host-header check rejects the tunnel. |
| `SOC_ADMIN_USER` / `SOC_ADMIN_PASSWORD` | the first admin (else a one-time password is printed on first run) |

Example:
```bash
SOC_PROD=1 SOC_HTTPS=1 SOC_ALLOWED_HOSTS=soc.example.com \
SOC_SECRET_KEY="$(openssl rand -hex 32)" make serve
```

## 2. Keep it running (systemd, WSL/Linux)

`/etc/systemd/system/ai-soc.service`:
```ini
[Unit]
Description=AI-SOC console
After=network.target docker.service

[Service]
WorkingDirectory=/home/kameron/ai-soc
EnvironmentFile=/home/kameron/ai-soc/.env
Environment=SOC_PROD=1 PYTHONPATH=src
ExecStart=/home/kameron/ai-soc/.venv/bin/python -m soc.web
Restart=on-failure
User=kameron

[Install]
WantedBy=multi-user.target
```
```bash
sudo systemctl enable --now ai-soc
```
(On WSL, enable systemd in `/etc/wsl.conf` → `[boot] systemd=true`, or run `make serve` under `tmux`.)

## 3. The tunnel (Cloudflare Tunnel — free, no inbound ports)

```bash
# one-time
cloudflared tunnel login
cloudflared tunnel create ai-soc
cloudflared tunnel route dns ai-soc soc.example.com
# run (point the hostname at the local console)
cloudflared tunnel --url http://127.0.0.1:8765 run ai-soc
```
Cloudflare terminates HTTPS and forwards to the local console. Set `SOC_HTTPS=1` and
`SOC_ALLOWED_HOSTS=soc.example.com` so cookies are Secure and the Host check passes.

(ngrok works for a quick test: `ngrok http 8765`, then put the ngrok host in `SOC_ALLOWED_HOSTS`.)

## 4. Hardening checklist before you expose it

- [ ] Strong, unique **admin password** (not the demo creds); create per-person accounts with least-privilege roles.
- [ ] `SOC_SECRET_KEY` set to a long random value and kept secret.
- [ ] `SOC_HTTPS=1` so session cookies are Secure; the tunnel provides TLS.
- [ ] `SOC_ALLOWED_HOSTS` limited to exactly your tunnel hostname.
- [ ] Put **Cloudflare Access** (or the tunnel's auth) in front for a second factor — the app login is the only gate otherwise.
- [ ] Response execution stays **dry-run** (D9) unless you deliberately enable `SOC_ALLOW_LIVE=1` + a per-tenant allowlist + a backend.
- [ ] Back up `data/outputs/` (the tenant DBs + audit log) regularly.
- [ ] Watch `make` logs / the audit page; the login page has no rate-limit yet (add one or rely on Cloudflare Access).

## What's deliberately NOT done

- No public cloud VPS and no inbound ports (that was the alternative; option B avoids both).
- Live response backends (SSH/WinRM) are not wired — that lands with Phase 9.
