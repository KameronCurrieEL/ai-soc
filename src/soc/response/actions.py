"""Response actions: turn an approved proposal into the exact command (dry-run by default).

Targets can come from attacker-controlled log data (a username is whatever the attacker
typed), so every target must pass strict validation BEFORE it goes near a command.
Live execution is deliberately disabled in this build: CLAUDE.md requires dry-run by default.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from soc.decision.guards import PROTECTED_ACCOUNTS
from soc.parsing.schema import ip_scope

# Windows local account names: max 20 chars, no spaces or special characters for our purposes.
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,20}$")
HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,62}$")


class InvalidTarget(ValueError):
    pass


class ExecutionDisabled(RuntimeError):
    pass


@dataclass(frozen=True)
class ResponsePlan:
    action: str
    target: str
    command: str | None      # what would run (PowerShell on the Windows host); None = human task
    rollback: str | None     # how to undo it
    description: str


def validate_target(action: str, target: str) -> str:
    """Return the cleaned target or raise InvalidTarget. Defense in depth on top of the guards."""
    if action == "block_ip":
        try:
            ip = str(ipaddress.ip_address(target.strip()))
        except ValueError:
            raise InvalidTarget(f"not an IP address: {target!r}") from None
        if ip_scope(ip) != "public":
            raise InvalidTarget(f"only public IPs can be blocked, {ip} is {ip_scope(ip)}")
        return ip
    if action == "disable_account":
        name = target.strip()
        if not USERNAME_RE.match(name):
            raise InvalidTarget(f"unsafe or invalid account name: {target!r}")
        if name.lower() in PROTECTED_ACCOUNTS:
            raise InvalidTarget(f"protected account: {name}")
        return name
    if action == "isolate_host":
        if not HOSTNAME_RE.match(target.strip()):
            raise InvalidTarget(f"unsafe or invalid host name: {target!r}")
        return target.strip()
    if action == "investigate":
        return target  # never placed in a command
    raise InvalidTarget(f"unknown action {action!r}")


PLATFORMS = ("windows", "rhel")


def plan(action: str, target: str, platform: str = "windows") -> ResponsePlan:
    """The exact command + rollback for a validated target, per host platform.

    windows: PowerShell on the Windows lab host. rhel: Red Hat Enterprise Linux / Rocky / Alma
    (firewalld + shadow-utils), for Linux hosts such as the Phase 9 honeypot.
    """
    if platform not in PLATFORMS:
        raise InvalidTarget(f"unknown platform {platform!r}")
    t = validate_target(action, target)
    if platform == "rhel":
        return _plan_rhel(action, t)
    if action == "block_ip":
        rule = f"SOC-block-{t}"
        return ResponsePlan(action, t,
            f"New-NetFirewallRule -DisplayName '{rule}' -Direction Inbound -RemoteAddress {t} -Action Block",
            f"Remove-NetFirewallRule -DisplayName '{rule}'",
            f"block inbound traffic from {t} on the Windows firewall")
    if action == "disable_account":
        return ResponsePlan(action, t, f"Disable-LocalUser -Name '{t}'", f"Enable-LocalUser -Name '{t}'",
                            f"disable local account {t}")
    if action == "isolate_host":
        return ResponsePlan(action, t,
            "Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Block; "
            "New-NetFirewallRule -DisplayName 'SOC-isolation-allow-wazuh' -Direction Outbound "
            "-RemoteAddress 127.0.0.1 -RemotePort 1514,1515 -Protocol TCP -Action Allow",
            "Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Allow; "
            "Remove-NetFirewallRule -DisplayName 'SOC-isolation-allow-wazuh'",
            f"isolate {t}: block all traffic except the Wazuh agent channel")
    return ResponsePlan(action, t, None, None, "human investigation task: no system change")


def _plan_rhel(action: str, t: str) -> ResponsePlan:
    if action == "block_ip":
        family = "ipv6" if ":" in t else "ipv4"
        rich = f"rule family=\"{family}\" source address=\"{t}\" drop"
        return ResponsePlan(action, t,
            f"firewall-cmd --permanent --add-rich-rule='{rich}' && firewall-cmd --reload",
            f"firewall-cmd --permanent --remove-rich-rule='{rich}' && firewall-cmd --reload",
            f"drop all traffic from {t} with firewalld")
    if action == "disable_account":
        return ResponsePlan(action, t, f"usermod --lock --expiredate 1 '{t}'", f"usermod --unlock --expiredate '' '{t}'",
                            f"lock the password and expire Linux account {t}")
    if action == "isolate_host":
        return ResponsePlan(action, t,
            "firewall-cmd --set-default-zone=drop && firewall-cmd --zone=drop --add-port=1514-1515/tcp",
            "firewall-cmd --set-default-zone=public && firewall-cmd --zone=drop --remove-port=1514-1515/tcp",
            f"isolate {t}: drop inbound traffic except the Wazuh agent ports (outbound needs a firewalld policy)")
    return ResponsePlan(action, t, None, None, "human investigation task: no system change")


def execute(p: ResponsePlan, dry_run: bool = True) -> str:
    """Dry-run: describe what would run. Live execution is intentionally not implemented."""
    if not dry_run:
        raise ExecutionDisabled("live execution is disabled in this build (dry-run only)")
    if p.command is None:
        return f"[dry-run] no command: {p.description}"
    return f"[dry-run] would run on the Windows host: {p.command}"
