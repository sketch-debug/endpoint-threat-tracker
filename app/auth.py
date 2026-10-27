"""Local accounts, PBKDF2 password hashing, login rate limiting, signed
session cookies. No external auth dependencies; LDAP/AD can be added later
behind the same interface (documented in the admin guide).

Roles: admin (edit indicators/config, manage users), analyst (work incidents),
viewer (read-only). Enforced by require_role on every mutating route.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import time
from typing import Callable

from fastapi import HTTPException, Request

from .audit import audit
from .config import Settings
from .db import Database
from .normalize import iso, now_iso, utcnow

log = logging.getLogger("tracker.auth")

SESSION_COOKIE = "tracker_session"
SESSION_TTL_HOURS = 12
_ROLES = ("admin", "analyst", "viewer")
_ROLE_RANK = {"viewer": 1, "analyst": 2, "admin": 3}

_PBKDF2_ITERATIONS = 390_000


def hash_password(password: str, *, salt_hex: str | None = None,
                  iterations: int = _PBKDF2_ITERATIONS) -> str:
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iter_s, salt_hex, digest_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        candidate = hash_password(password, salt_hex=salt_hex, iterations=int(iter_s))
        return hmac.compare_digest(candidate, stored)
    except (ValueError, AttributeError):
        return False


# ---------------------------------------------------------------- users ----

def create_user(db: Database, username: str, password: str, role: str,
                actor: str = "system") -> None:
    if role not in _ROLES:
        raise ValueError(f"role must be one of {_ROLES}")
    if len(password or "") < 8:
        raise ValueError("password must be at least 8 characters")
    with db.tx():
        db.execute("INSERT INTO users(username, password_hash, role, created_at) "
                   "VALUES(?,?,?,?)", (username.lower(), hash_password(password), role,
                                       now_iso()))
        audit(db, actor, "user_create", username.lower(), f"role={role}")


def set_password(db: Database, username: str, new_password: str, actor: str) -> None:
    if len(new_password or "") < 8:
        raise ValueError("password must be at least 8 characters")
    with db.tx():
        db.execute("UPDATE users SET password_hash=? WHERE username=?",
                   (hash_password(new_password), username.lower()))
        # A password change must kill live sessions: an admin resetting a
        # compromised account would otherwise leave the intruder's cookie
        # valid for the rest of its 12-hour TTL. Self-changes simply force a
        # clean re-login.
        db.execute("DELETE FROM sessions WHERE username=?", (username.lower(),))
        audit(db, actor, "user_password", username.lower(), "password changed")


def env_password_status(db: Database, username: str, password: str) -> str:
    """Does the account accept `password`? Pure check, never writes.

    Returns no-password / short / no-admin / matched / mismatch.
    """
    if not password:
        return "no-password"
    if len(password) < 8:
        return "short"
    row = db.one("SELECT password_hash FROM users WHERE username=?",
                 (username.lower(),))
    if row is None:
        return "no-admin"
    return "matched" if verify_password(password, row["password_hash"]) \
        else "mismatch"


def adopt_env_password(db: Database, username: str, password: str,
                       actor: str = "installer") -> str:
    """Make the password install.ps1 is about to print actually work.

    install.ps1 writes TRACKER_ADMIN_PASSWORD into .env - freshly generated
    when .env was missing, or -AdminPassword applied over a default - and
    prints it as the first login. But bootstrap_admin only *creates* the
    account: on an instance that already has one, the advertised password is
    then refused, five refusals lock the account for five minutes, and the
    only reset short of knowing the old password is deleting the database.

    Called by the installer at that moment, never at startup (a startup sync
    would silently undo a password changed later on the Users page). Returns
    what happened so the installer can print it:
      no-password / short / no-admin / matched / synced / error:...
    """
    status = env_password_status(db, username, password)
    if status != "mismatch":
        return status
    try:
        set_password(db, username, password, actor=actor)
    except Exception as exc:  # defensive: never break the caller over this
        log.warning("could not adopt the installer password for %s: %s",
                    username, exc)
        return f"error:{exc}"
    return "synced"


def set_role(db: Database, username: str, role: str, actor: str) -> None:
    if role not in _ROLES:
        raise ValueError(f"role must be one of {_ROLES}")
    with db.tx():
        db.execute("UPDATE users SET role=? WHERE username=?", (role, username.lower()))
        audit(db, actor, "user_role", username.lower(), f"role={role}")


def list_users(db: Database) -> list:
    return db.query("SELECT id, username, role, created_at, last_login FROM users "
                    "ORDER BY username")


def delete_user(db: Database, username: str, actor: str) -> None:
    with db.tx():
        db.execute("DELETE FROM users WHERE username=?", (username.lower(),))
        db.execute("DELETE FROM sessions WHERE username=?", (username.lower(),))
        audit(db, actor, "user_delete", username.lower(), "")


# ------------------------------------------------------- rate limiting ----

_MAX_ATTEMPTS = 5
_WINDOW_SECONDS = 300


def _too_many_attempts(db: Database, username: str) -> bool:
    since = time.time() - _WINDOW_SECONDS
    row = db.one(
        "SELECT COUNT(*) AS n FROM audit_log WHERE action='login_failed' "
        "AND entity=? AND ts >= ?", (username, _epoch_to_iso(since)))
    return int(row["n"] if row else 0) >= _MAX_ATTEMPTS


def _epoch_to_iso(epoch: float) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def authenticate(db: Database, username: str, password: str, client_ip: str = "") -> dict | None:
    """Returns the user row on success, None on failure. Rate limited."""
    username = (username or "").lower().strip()
    if _too_many_attempts(db, username):
        audit(db, "system", "login_blocked", username, f"too many attempts from {client_ip}")
        raise HTTPException(status_code=429, detail="too many login attempts; try later")
    row = db.one("SELECT * FROM users WHERE username=?", (username,))
    ok = bool(row) and verify_password(password or "", row["password_hash"])
    if not ok:
        audit(db, "system", "login_failed", username, f"ip={client_ip}")
        return None
    db.execute("UPDATE users SET last_login=? WHERE username=?", (now_iso(), username))
    audit(db, username, "login_success", username, f"ip={client_ip}")
    return row


# --------------------------------------------------------- sessions -------

def _sign(secret: str, payload: str) -> str:
    return hmac.new(secret.encode("utf-8"), payload.encode("utf-8"),
                    hashlib.sha256).hexdigest()


def create_session(db: Database, settings: Settings, username: str, role: str) -> str:
    secret = _session_secret(settings)
    token = secrets.token_urlsafe(32)
    from datetime import timedelta
    # UTC with the same Z-suffix format resolve_session compares against.
    # A naive datetime.now() here made the real TTL off by the machine's UTC
    # offset: hours short on west-of-Greenwich hosts, hours long (failing
    # open) east of it.
    expires = iso(utcnow() + timedelta(hours=SESSION_TTL_HOURS))
    with db.tx():
        db.execute("INSERT INTO sessions(token_hash, username, role, created_at, expires_at) "
                   "VALUES(?,?,?,?,?)",
                   (hashlib.sha256(token.encode()).hexdigest(), username, role,
                    now_iso(), expires))
    return f"{token}.{_sign(secret, token)}"


def _session_secret(settings: Settings) -> str:
    # SESSION_SECRET (explicit override) -> SECRET_KEY (.env, generated by
    # install.ps1 and documented as "signs session cookies" - it used to be
    # dead config) -> stable per-install file.
    for env_name in ("SESSION_SECRET", "SECRET_KEY"):
        secret = os.environ.get(env_name, "")
        if secret:
            return secret
    # derive a stable per-install secret kept out of version control
    state_dir = settings.base_dir / "data"
    state_dir.mkdir(parents=True, exist_ok=True)
    secret_file = state_dir / ".session_secret"
    if secret_file.exists():
        return secret_file.read_text(encoding="utf-8").strip()
    secret = secrets.token_urlsafe(48)
    secret_file.write_text(secret, encoding="utf-8")
    try:
        os.chmod(secret_file, 0o600)
    except OSError:
        pass  # best effort on Windows
    return secret


def resolve_session(db: Database, settings: Settings, cookie_value: str | None) -> dict | None:
    if not cookie_value or "." not in cookie_value:
        return None
    token, signature = cookie_value.rsplit(".", 1)
    if not hmac.compare_digest(signature, _sign(_session_secret(settings), token)):
        return None
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    # Join users so the role is read fresh: a demoted admin must lose admin
    # on their next request, not when the cookie finally expires, and a
    # deleted account's leftover sessions die with it (INNER JOIN).
    row = db.one(
        "SELECT s.username AS username, u.role AS role "
        "FROM sessions s JOIN users u ON u.username = s.username "
        "WHERE s.token_hash=? AND s.expires_at > ?",
        (token_hash, now_iso()))
    if row is None:
        return None
    return {"username": row["username"], "role": row["role"]}


def destroy_session(db: Database, cookie_value: str | None) -> None:
    if not cookie_value or "." not in cookie_value:
        return
    token = cookie_value.rsplit(".", 1)[0]
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    db.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))


def purge_expired(db: Database) -> int:
    """Delete expired session rows; returns how many. Database.execute()
    returns a rowid int (0 for multi-row deletes), NOT a cursor - reading
    `.rowcount` off it raised AttributeError on every scheduler run."""
    with db.tx():
        db.execute("DELETE FROM sessions WHERE expires_at <= ?", (now_iso(),))
        row = db.one("SELECT changes() AS n")
    return int(row["n"]) if row else 0


# ------------------------------------------------------- dependencies ----

def current_user(request: Request) -> dict | None:
    app = request.app.state
    return app.user  # set by the auth middleware on every request


def require_user(request: Request) -> dict:
    user = request.app.state.user
    if not user:
        raise HTTPException(status_code=401, detail="login required")
    return user


def require_role(minimum: str) -> Callable:
    def checker(request: Request) -> dict:
        user = request.app.state.user
        if not user:
            raise HTTPException(status_code=401, detail="login required")
        if _ROLE_RANK.get(user["role"], 0) < _ROLE_RANK.get(minimum, 99):
            raise HTTPException(status_code=403,
                                detail=f"role {minimum} or higher required")
        return user
    return checker


def role_allows(user: dict | None, minimum: str) -> bool:
    if not user:
        return False
    return _ROLE_RANK.get(user["role"], 0) >= _ROLE_RANK.get(minimum, 99)
