"""Authentication + role-based access control for the console.

Passwords: PBKDF2-HMAC-SHA256 (stdlib hashlib), per-user random salt, stored as
`pbkdf2$<iters>$<salt_hex>$<hash_hex>`. Verify in constant time (hmac.compare_digest).
No new dependencies.

Roles (least privilege):
  viewer   - read only
  analyst  - viewer + approve/reject/execute/close, run the responder, toggle autopilot
  admin    - analyst + manage users

The logged-in username is the actor written to the audit log, so accountability no longer
depends on someone typing their name honestly.
"""

from __future__ import annotations

import functools
import hashlib
import hmac
import os
import secrets

from flask import g, redirect, request, session, url_for

ROLES = ("viewer", "analyst", "admin")
RANK = {r: i for i, r in enumerate(ROLES)}
PBKDF2_ITERS = 240_000
USERNAME_MAX = 40


def hash_password(password: str, *, iters: int = PBKDF2_ITERS, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iters)
    return f"pbkdf2${iters}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iters, salt_hex, hash_hex = stored.split("$")
        if scheme != "pbkdf2":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iters))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk.hex(), hash_hex)


def valid_username(name: str) -> bool:
    name = (name or "").strip()
    return bool(name) and len(name) <= USERNAME_MAX and all(c.isalnum() or c in "._-" for c in name)


def authenticate(conn, username: str, password: str):
    """Return the user row on success, else None. Runs a dummy hash on unknown users (timing)."""
    user = __import__("soc.agent.store", fromlist=["get_user"]).get_user(conn, username)
    if user is None:
        hash_password(password)  # avoid revealing whether the username exists via response time
        return None
    return user if verify_password(password, user["pw_hash"]) else None


# ---------- request-time helpers ----------

def current_user():
    return session.get("user")  # {"name":..., "role":..., "tenant":...} or None


def login_user(user_row) -> None:
    session["user"] = {"name": user_row["username"], "role": user_row["role"], "tenant": user_row["tenant"]}


def logout_user() -> None:
    session.pop("user", None)


def has_role(minimum: str) -> bool:
    u = current_user()
    return bool(u) and RANK.get(u["role"], -1) >= RANK[minimum]


def login_required(fn):
    @functools.wraps(fn)
    def wrapper(*a, **kw):
        if not current_user():
            session["next"] = request.full_path if request.method == "GET" else None
            return redirect(url_for("login"))
        return fn(*a, **kw)
    return wrapper


def require_role(minimum: str):
    """Route decorator: must be logged in AND have at least `minimum` role, else 403."""
    def deco(fn):
        @functools.wraps(fn)
        @login_required
        def wrapper(*a, **kw):
            if not has_role(minimum):
                from flask import abort
                abort(403)
            return fn(*a, **kw)
        return wrapper
    return deco


# ---------- seeding ----------

def ensure_seed_admin(conn) -> str | None:
    """On an empty users table, create an admin. Returns a message, or None if users already exist.

    Credentials come from SOC_ADMIN_USER / SOC_ADMIN_PASSWORD, else a generated one-time password
    is printed to the server log so the owner can log in and change it.
    """
    from soc.agent import store
    if store.count_users(conn):
        return None
    name = os.environ.get("SOC_ADMIN_USER", "admin")
    pw = os.environ.get("SOC_ADMIN_PASSWORD")
    generated = pw is None
    pw = pw or secrets.token_urlsafe(12)
    store.create_user(conn, name, hash_password(pw), "admin")
    if generated:
        return f"Created admin user '{name}' with one-time password: {pw}  (change it after logging in)"
    return f"Created admin user '{name}' from SOC_ADMIN_PASSWORD"


def _cli(argv: list[str] | None = None) -> int:
    """`python -m soc.web.auth adduser NAME --role analyst` / `passwd NAME` / `list`."""
    import argparse
    import getpass

    from soc.agent import store
    p = argparse.ArgumentParser(prog="soc.web.auth", description="manage console users")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("adduser"); a.add_argument("username"); a.add_argument("--role", choices=ROLES, default="analyst")
    pw = sub.add_parser("passwd"); pw.add_argument("username")
    rl = sub.add_parser("role"); rl.add_argument("username"); rl.add_argument("role", choices=ROLES)
    sub.add_parser("list")
    args = p.parse_args(argv)
    conn = store.connect()
    if args.cmd == "list":
        for u in store.list_users(conn):
            print(f"{u['username']:<20} {u['role']:<8} tenant={u['tenant']} last_login={u['last_login'] or '-'}")
        return 0
    if args.cmd == "adduser":
        if not valid_username(args.username):
            print("invalid username (letters, digits, . _ - only)"); return 2
        if store.get_user(conn, args.username):
            print("user already exists"); return 2
        pwd = getpass.getpass("password: ")
        if pwd != getpass.getpass("confirm:  "):
            print("passwords do not match"); return 2
        store.create_user(conn, args.username, hash_password(pwd), args.role)
        print(f"created {args.username} ({args.role})"); return 0
    if args.cmd == "passwd":
        if not store.get_user(conn, args.username):
            print("no such user"); return 2
        pwd = getpass.getpass("new password: ")
        store.set_user_password(conn, args.username, hash_password(pwd))
        print("password updated"); return 0
    if args.cmd == "role":
        if not store.get_user(conn, args.username):
            print("no such user"); return 2
        store.set_user_role(conn, args.username, args.role)
        print(f"{args.username} is now {args.role}"); return 0
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_cli())
