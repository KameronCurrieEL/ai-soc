# Infra: Wazuh 4.9.2 single-node lab

```
make wazuh-up      # clone (pinned v4.9.2), generate certs once, docker compose up
make wazuh-check   # log in to the manager API, confirm a JWT is issued
```

## Components
| Container | Role | Port(s) |
|---|---|---|
| wazuh.manager | Receives agent events, runs decoders + rules, writes alerts, REST API | 1514 (agent events), 1515 (enrollment), 514/udp (syslog), 55000 (API) |
| wazuh.indexer | OpenSearch: stores and searches alerts | 9200 |
| wazuh.dashboard | Web UI (OpenSearch Dashboards + Wazuh plugin) | 443 -> 5601 |

Flow: agent -> manager (rules) -> alerts.json -> Filebeat -> indexer -> dashboard.
All inter-component traffic is TLS, signed by a root CA generated locally.

## Design choices
- **Not vendored**: `infra/wazuh-docker/` is cloned by the script at a pinned tag and gitignored (it also holds private keys).
- **Own compose project name** (`ai-soc-wazuh`) so this stack never reuses volumes from the archived first attempt.
- **Certs before `up`**: if a bind-mounted file doesn't exist, Docker creates an empty *directory* there and the container fails with "not a directory". This is what broke attempt #1.

## Lab credentials
Wazuh's public defaults (dashboard `admin` / `SecretPassword`; API `wazuh-wui`). Fine for a localhost-only lab; change them before anything is reachable from another network. Our code reads them from `.env`, never from source.

## Gotchas
- API returns **HTTP 500** for ~30s after start (web server up before users/RBAC are initialised). Wait, then retry.
- Indexer needs `vm.max_map_count >= 262144` and ~1 GB heap; WSL has ~6.7 GB total here.
- Cert dir is root-owned `0500` after generation; inspect it via a container, not `ls`.
- Ports are published on all interfaces of the host (0.0.0.0). Lab only.
