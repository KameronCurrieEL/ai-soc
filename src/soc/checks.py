"""Environment health checks: Python, Docker, Ollama.

Run with:  python -m soc.checks   (or `make check`)
Exit code 0 = everything responds, 1 = at least one check failed.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

MIN_PYTHON = (3, 10)
TIMEOUT_S = 5


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str


# ---------- config ----------

def parse_env_lines(lines: list[str]) -> dict[str, str]:
    """Parse KEY=VALUE lines from a .env file. Ignores blanks and # comments."""
    env: dict[str, str] = {}
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def load_env(path: Path = Path(".env")) -> dict[str, str]:
    """Load .env, then let real environment variables override it."""
    env = parse_env_lines(path.read_text().splitlines()) if path.exists() else {}
    env.update({k: v for k, v in os.environ.items() if k in env or k.startswith("OLLAMA_")})
    return env


# ---------- networking: find the Windows host from WSL ----------

def parse_default_gateway(route_table: str) -> str | None:
    """Return the default gateway IP from /proc/net/route content.

    Each row is: Iface Destination Gateway Flags ... with addresses in
    little-endian hex. The default route has Destination 00000000.
    Example: gateway '01E018AC' -> bytes AC.18.E0.01 -> 172.24.224.1
    """
    for row in route_table.splitlines()[1:]:
        fields = row.split()
        if len(fields) >= 3 and fields[1] == "00000000":
            gateway = bytes.fromhex(fields[2])[::-1]  # little-endian -> network order
            return socket.inet_ntoa(gateway)
    return None


def windows_host_ip() -> str | None:
    """In WSL2 (NAT mode) the Windows host is the default gateway."""
    try:
        return parse_default_gateway(Path("/proc/net/route").read_text())
    except OSError:
        return None


def resolve_ollama_url(env: dict[str, str]) -> str | None:
    if env.get("OLLAMA_URL"):
        return env["OLLAMA_URL"].rstrip("/")
    host = windows_host_ip()
    port = env.get("OLLAMA_PORT") or "11434"
    return f"http://{host}:{port}" if host else None


# ---------- checks ----------

def check_python(version: tuple[int, int] = sys.version_info[:2]) -> CheckResult:
    ok = version >= MIN_PYTHON
    want = ".".join(map(str, MIN_PYTHON))
    return CheckResult("python", ok, f"{version[0]}.{version[1]} (need >= {want})")


def check_docker() -> CheckResult:
    """Ask the Docker daemon (not just the CLI) for its version."""
    try:
        proc = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, text=True, timeout=TIMEOUT_S * 2,
        )
    except FileNotFoundError:
        return CheckResult("docker", False, "docker CLI not found")
    except subprocess.TimeoutExpired:
        return CheckResult("docker", False, "daemon did not answer in time")
    if proc.returncode != 0 or not proc.stdout.strip():
        return CheckResult("docker", False, "daemon not running (start Docker Desktop)")
    return CheckResult("docker", True, f"server {proc.stdout.strip()}")


def models_from_tags(payload: dict) -> list[str]:
    """Extract model names from Ollama's GET /api/tags response."""
    return [m.get("name", "") for m in payload.get("models", [])]


def check_ollama(url: str | None, model: str) -> CheckResult:
    if not url:
        return CheckResult("ollama", False, "no OLLAMA_URL and could not detect Windows host IP")
    try:
        with urllib.request.urlopen(f"{url}/api/tags", timeout=TIMEOUT_S) as resp:
            payload = json.load(resp)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return CheckResult("ollama", False, f"{url} unreachable ({exc})")
    models = models_from_tags(payload)
    if model not in models:
        return CheckResult("ollama", False, f"{url} up, but model {model!r} missing (have: {models})")
    return CheckResult("ollama", True, f"{url} model {model}")


def run_all(env: dict[str, str]) -> list[CheckResult]:
    return [
        check_python(),
        check_docker(),
        check_ollama(resolve_ollama_url(env), env.get("OLLAMA_MODEL", "qwen2.5:3b")),
    ]


def main() -> int:
    results = run_all(load_env())
    for r in results:
        print(f"[{'OK' if r.ok else 'FAIL':4}] {r.name:7} {r.detail}")
    return 0 if all(r.ok for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
