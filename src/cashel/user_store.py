"""User CRUD and credential operations for multi-user auth.

All blueprint code calls this module — nothing touches the DB directly.
"""

import re
import secrets
from datetime import datetime, timezone
from uuid import uuid4

from werkzeug.security import check_password_hash, generate_password_hash

from .crypto import decrypt, encrypt
from .db import get_conn

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{3,64}$")
_VALID_ROLES = {"admin", "auditor", "viewer"}


class UserValidationError(ValueError):
    pass


# ── Helpers ───────────────────────────────────────────────────────────────────


def _row_to_dict(row, include_hash: bool = False, include_enc: bool = False) -> dict:
    d = dict(row)
    if not include_hash:
        d.pop("password_hash", None)
    if not include_enc:
        d.pop("api_key_enc", None)
    return d


def _safe_dict(row) -> dict:
    """Public-safe user dict: no password_hash, no api_key_enc; adds has_api_key."""
    d = dict(row)
    d.pop("password_hash", None)
    enc = d.pop("api_key_enc", "")
    d["has_api_key"] = bool(enc)
    return d


# ── Public API ────────────────────────────────────────────────────────────────


def has_users() -> bool:
    """Return True if any row exists in the users table."""
    conn = get_conn()
    row = conn.execute("SELECT COUNT(*) FROM users").fetchone()
    return row[0] > 0


def create_user(username: str, password: str, role: str = "viewer") -> dict:
    """Create a new user.  Returns safe user dict (no hash, no enc key).

    Raises UserValidationError on bad input or duplicate username.
    """
    if not _USERNAME_RE.match(username):
        raise UserValidationError(
            "Username must be 3–64 characters: letters, digits, underscore, hyphen."
        )
    if len(password) < 12:
        raise UserValidationError("Password must be at least 12 characters.")
    if role not in _VALID_ROLES:
        raise UserValidationError(f"Role must be one of: {', '.join(sorted(_VALID_ROLES))}.")

    user_id = uuid4().hex[:12]
    pw_hash = generate_password_hash(password)
    created_at = datetime.now(timezone.utc).isoformat()

    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO users (id, username, password_hash, role, api_key_enc, created_at) "
            "VALUES (?, ?, ?, ?, '', ?)",
            (user_id, username.lower(), pw_hash, role, created_at),
        )
        conn.commit()
    except Exception as exc:
        if "UNIQUE constraint" in str(exc):
            raise UserValidationError(f"Username '{username}' is already taken.")
        raise

    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return _safe_dict(row)


def get_user_by_id(user_id: str) -> dict | None:
    """Return safe user dict or None."""
    conn = get_conn()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        return None
    return _safe_dict(row)


def get_user_by_username(username: str) -> dict | None:
    """Case-insensitive lookup.  Returns safe user dict or None."""
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM users WHERE LOWER(username) = LOWER(?)", (username,)
    ).fetchone()
    if row is None:
        return None
    return _safe_dict(row)


def get_user_by_api_key(plaintext_key: str) -> dict | None:
    """Timing-safe API key lookup.  Returns safe user dict or None."""
    if not plaintext_key:
        return None
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM users WHERE api_key_enc != ''"
    ).fetchall()
    for row in rows:
        enc = dict(row).get("api_key_enc", "")
        if not enc:
            continue
        try:
            stored = decrypt(enc)
        except Exception:
            continue
        if stored and secrets.compare_digest(plaintext_key, stored):
            return _safe_dict(row)
    return None


def check_password(username: str, plaintext: str) -> dict | None:
    """Verify credentials.  Returns safe user dict or None."""
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM users WHERE LOWER(username) = LOWER(?)", (username,)
    ).fetchone()
    if row is None:
        return None
    row_dict = dict(row)
    if not check_password_hash(row_dict["password_hash"], plaintext):
        return None
    return _safe_dict(row)


def list_users() -> list:
    """Return list of safe user dicts (id, username, role, has_api_key, created_at)."""
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM users ORDER BY created_at ASC"
    ).fetchall()
    return [_safe_dict(r) for r in rows]


def delete_user(user_id: str) -> bool:
    """Delete a user.  Raises UserValidationError if deleting last admin.

    Returns True if deleted, False if not found.
    """
    conn = get_conn()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        return False

    row_dict = dict(row)
    if row_dict["role"] == "admin":
        admin_count = conn.execute(
            "SELECT COUNT(*) FROM users WHERE role = 'admin'"
        ).fetchone()[0]
        if admin_count <= 1:
            raise UserValidationError("Cannot delete the last admin user.")

    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    return True


def change_password(user_id: str, new_password: str) -> None:
    """Re-hash and update the user's password.

    Raises UserValidationError if password too short or user not found.
    """
    if len(new_password) < 12:
        raise UserValidationError("Password must be at least 12 characters.")
    conn = get_conn()
    row = conn.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        raise UserValidationError("User not found.")
    pw_hash = generate_password_hash(new_password)
    conn.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?", (pw_hash, user_id)
    )
    conn.commit()


def generate_api_key(user_id: str) -> str:
    """Generate and store a per-user API key.  Returns the plaintext key (shown once)."""
    conn = get_conn()
    row = conn.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        raise UserValidationError("User not found.")
    plaintext = "csh_" + secrets.token_urlsafe(32)
    enc = encrypt(plaintext)
    conn.execute("UPDATE users SET api_key_enc = ? WHERE id = ?", (enc, user_id))
    conn.commit()
    return plaintext


def revoke_api_key(user_id: str) -> None:
    """Clear the API key for a user."""
    conn = get_conn()
    conn.execute("UPDATE users SET api_key_enc = '' WHERE id = ?", (user_id,))
    conn.commit()
