"""Translate Windows Security event codes into words.

A small local model reasons far better over "user does not exist" than over "0xc0000064".
Sources: Microsoft docs for events 4624/4625 (logon types, NTSTATUS codes).
"""

from __future__ import annotations

LOGON_TYPES = {
    "2": "interactive (keyboard/console)",
    "3": "network (e.g. SMB share)",
    "4": "batch (scheduled task)",
    "5": "service",
    "7": "unlock",
    "8": "network cleartext",
    "9": "new credentials (runas /netonly)",
    "10": "remote interactive (RDP)",
    "11": "cached interactive",
}

# NTSTATUS codes seen in 4625 Status / SubStatus
LOGON_FAILURE_REASONS = {
    "0xc0000064": "user does not exist",
    "0xc000006a": "wrong password for an existing user",
    "0xc000006d": "bad username or password",
    "0xc000006f": "logon outside allowed hours",
    "0xc0000070": "logon from unauthorized workstation",
    "0xc0000071": "password expired",
    "0xc0000072": "account disabled",
    "0xc000015b": "logon type not granted to this user",
    "0xc0000193": "account expired",
    "0xc0000224": "user must change password at next logon",
    "0xc0000234": "account locked out",
}

EMPTY = {"", "-", "0", "0x0"}


def clean(value: str | None) -> str | None:
    """Windows uses '-' (or zeros) for 'not applicable'. Treat those as missing."""
    if value is None:
        return None
    value = value.strip()
    return None if value in EMPTY else value


def logon_type(code: str | None) -> str | None:
    code = clean(code)
    return f"{code} {LOGON_TYPES.get(code, 'unknown')}" if code else None


def failure_reason(status: str | None, sub_status: str | None) -> str | None:
    """SubStatus is more specific than Status, so prefer it when it's set."""
    for code in (clean(sub_status), clean(status)):
        if code:
            code = code.lower()
            return f"{code} {LOGON_FAILURE_REASONS.get(code, 'unknown failure code')}"
    return None
