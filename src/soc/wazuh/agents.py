"""List Wazuh agents (the monitored machines) from the manager API.

Run with:  python -m soc.wazuh.agents
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

from soc.checks import load_env
from soc.wazuh.auth import get_token
from soc.wazuh.client import request_json

AGENT_FIELDS = "id,name,ip,status,version,os.name,lastKeepAlive"
MANAGER_AGENT_ID = "000"  # the manager monitoring itself


@dataclass(frozen=True)
class Agent:
    id: str
    name: str
    ip: str
    status: str  # active | disconnected | pending | never_connected
    os: str
    version: str
    last_keepalive: str


def agents_from_response(payload: dict, include_manager: bool = False) -> list[Agent]:
    """Turn the API's {"data": {"affected_items": [...]}} envelope into Agent objects."""
    items = (payload.get("data") or {}).get("affected_items", [])
    agents = [
        Agent(
            id=i.get("id", ""),
            name=i.get("name", ""),
            ip=i.get("ip", ""),
            status=i.get("status", "unknown"),
            os=(i.get("os") or {}).get("name", ""),
            version=i.get("version", ""),
            last_keepalive=i.get("lastKeepAlive", ""),
        )
        for i in items
    ]
    return [a for a in agents if include_manager or a.id != MANAGER_AGENT_ID]


def fetch_agents(env: dict[str, str]) -> list[Agent]:
    url = env.get("WAZUH_API_URL", "https://localhost:55000").rstrip("/")
    verify = env.get("WAZUH_VERIFY_TLS") == "true"
    token = get_token(url, env["WAZUH_API_USER"], env["WAZUH_API_PASSWORD"], verify)
    payload = request_json(
        f"{url}/agents?select={AGENT_FIELDS}",
        headers={"Authorization": f"Bearer {token}"},
        verify_tls=verify,
    )
    return agents_from_response(payload)


def format_agent(a: Agent) -> str:
    return f"{a.id:>4}  {a.name:<16} {a.status:<13} {a.ip:<15} {a.os} ({a.version}) last seen {a.last_keepalive}"


def main() -> int:
    agents = fetch_agents(load_env())
    for a in agents:
        print(format_agent(a))
    print(f"{len(agents)} agent(s), {sum(a.status == 'active' for a in agents)} active")
    return 0


if __name__ == "__main__":
    sys.exit(main())
