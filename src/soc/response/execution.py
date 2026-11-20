"""Execution engine: turns an approved ResponsePlan into a real change — behind a locked switch.

Design principle: FAIL CLOSED. Live execution runs only when ALL of these are true:
  1. the process allows it at all:   env SOC_ALLOW_LIVE=1   (an operator decision, not a UI toggle)
  2. this tenant has it enabled:     setting execution_mode == "live"
  3. the target is explicitly listed: setting live_allowlist contains the target
  4. a transport backend is wired:   a Backend is registered for the plan's platform
If any is missing, the action stays a dry-run (or raises) — it never runs by accident.

Nothing here reaches a real host yet: no backend is registered by default, so even with the switch
on and an allowlist, live execution refuses until an operator wires a transport (SSH for the Phase 9
honeypot, WinRM/PowerShell for Windows). Tests inject a fake backend to exercise the path.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Callable

from soc.response.actions import ResponsePlan

ENV_FLAG = "SOC_ALLOW_LIVE"           # process-level master switch (must equal "1")


class ExecutionRefused(RuntimeError):
    """A live action was requested but a safety precondition was not met."""


@dataclass(frozen=True)
class ExecutionPolicy:
    live: bool                        # is live execution permitted in this context at all?
    allow: frozenset[str]             # exact targets a live action may touch (IPs / hosts / accounts)

    def permits(self, target: str) -> bool:
        return self.live and target in self.allow


# platform -> backend callable: run(plan) -> output string (raises on failure)
Backend = Callable[[ResponsePlan], str]
_BACKENDS: dict[str, Backend] = {}


def register_backend(platform: str, backend: Backend) -> None:
    _BACKENDS[platform] = backend


def resolve_policy(conn, tenant_setting_get, env: dict | None = None) -> ExecutionPolicy:
    """Build the policy from the process env + this tenant's stored settings. Fails closed.

    `tenant_setting_get(key, default)` reads a setting for the current tenant (store.get_setting bound
    to the tenant conn). Live is OFF unless the operator set SOC_ALLOW_LIVE=1 *and* the tenant enabled it.
    """
    env = os.environ if env is None else env
    process_allows = env.get(ENV_FLAG) == "1"
    tenant_live = tenant_setting_get("execution_mode", "dry_run") == "live"
    try:
        allow = frozenset(json.loads(tenant_setting_get("live_allowlist", "[]")))
    except (ValueError, TypeError):
        allow = frozenset()
    return ExecutionPolicy(live=process_allows and tenant_live, allow=allow)


def run(plan: ResponsePlan, policy: ExecutionPolicy, platform: str = "windows") -> tuple[str, bool]:
    """Execute (or simulate) a plan. Returns (output, was_live).

    Dry-run unless the policy permits this exact target AND a backend is registered for the platform.
    A permitted-but-unbacked target refuses loudly rather than silently simulating, so an operator
    who turned the switch on knows the transport is still missing.
    """
    if plan.command is None:                       # investigate / human task: nothing to run
        return (f"[dry-run] no command: {plan.description}", False)
    if not policy.live:
        return (f"[dry-run] would run ({platform}): {plan.command}", False)
    if plan.target not in policy.allow:
        raise ExecutionRefused(f"target {plan.target!r} is not on the live allowlist")
    backend = _BACKENDS.get(platform)
    if backend is None:
        raise ExecutionRefused(f"live is enabled but no execution backend is wired for {platform!r}")
    return (backend(plan), True)
