"""Auth blueprint — /login, /logout, /setup, /auth/users/*.

Seed location for future LDAP/OIDC/TACACS+ routes.
"""

import time

from flask import (
    Blueprint,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from cashel._helpers import _require_role
from cashel.db import get_conn
from cashel.settings import get_settings, save_settings
from cashel.user_store import (
    UserValidationError,
    change_password,
    check_password,
    create_user,
    delete_user,
    generate_api_key,
    has_users,
    list_users,
    revoke_api_key,
)

auth_bp = Blueprint("auth", __name__)

_LOCKOUT_THRESHOLD = 5
_LOCKOUT_SECONDS = 300  # 5 minutes


def _get_lockout(username: str) -> tuple[int, float]:
    row = (
        get_conn()
        .execute(
            "SELECT attempts, lockout_until FROM login_attempts WHERE username = ?",
            (username.lower(),),
        )
        .fetchone()
    )
    if row:
        return row["attempts"], row["lockout_until"]
    return 0, 0.0


def _record_failed_login(username: str) -> None:
    conn = get_conn()
    attempts, _ = _get_lockout(username)
    attempts += 1
    lockout_until = (
        time.time() + _LOCKOUT_SECONDS if attempts >= _LOCKOUT_THRESHOLD else 0.0
    )
    conn.execute(
        "INSERT INTO login_attempts (username, attempts, lockout_until) VALUES (?, ?, ?) "
        "ON CONFLICT(username) DO UPDATE SET attempts=excluded.attempts, lockout_until=excluded.lockout_until",
        (username.lower(), attempts, lockout_until),
    )
    conn.commit()


def _clear_lockout(username: str) -> None:
    conn = get_conn()
    conn.execute("DELETE FROM login_attempts WHERE username = ?", (username.lower(),))
    conn.commit()


# ── Login / Logout ─────────────────────────────────────────────────────────────


@auth_bp.route("/login", methods=["GET"])
def login():
    if session.get("authenticated") and session.get("user_id"):
        return redirect(url_for("index"))
    return render_template("login.html")


@auth_bp.route("/login", methods=["POST"])
def login_post():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        return render_template(
            "login.html", error="Username and password are required."
        ), 401

    attempts, lockout_until = _get_lockout(username)
    if lockout_until and time.time() < lockout_until:
        remaining = int(lockout_until - time.time())
        return render_template(
            "login.html", error=f"Account locked. Try again in {remaining}s."
        ), 429

    user = check_password(username, password)
    if user:
        _clear_lockout(username)
        session.clear()
        session["authenticated"] = True
        session["user_id"] = user["id"]
        session["last_seen"] = time.time()
        next_url = request.args.get("next", "")
        if next_url and next_url.startswith("/") and not next_url.startswith("//"):
            return redirect(next_url)
        return redirect(url_for("index"))
    else:
        _record_failed_login(username)
        return render_template("login.html", error="Invalid username or password."), 401


@auth_bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("auth.login"))


# ── First-run Setup ────────────────────────────────────────────────────────────


@auth_bp.route("/setup", methods=["GET"])
def setup():
    if has_users():
        return redirect(url_for("auth.login"))
    return render_template("setup.html")


@auth_bp.route("/setup", methods=["POST"])
def setup_post():
    if has_users():
        return redirect(url_for("auth.login"))

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    confirm = request.form.get("confirm_password", "")

    errors = []
    if not username:
        errors.append("Username is required.")
    if not password:
        errors.append("Password is required.")
    elif len(password) < 12:
        errors.append("Password must be at least 12 characters.")
    if password and confirm != password:
        errors.append("Passwords do not match.")

    if errors:
        return render_template("setup.html", errors=errors, username=username), 400

    try:
        user = create_user(username, password, role="admin")
    except UserValidationError as exc:
        return render_template("setup.html", errors=[str(exc)], username=username), 400

    settings = get_settings()
    save_settings({**settings, "auth_enabled": True})

    session.clear()
    session["authenticated"] = True
    session["user_id"] = user["id"]
    session["last_seen"] = time.time()
    return redirect(url_for("index"))


# ── User Management (admin only) ───────────────────────────────────────────────


@auth_bp.route("/auth/users", methods=["GET"])
@_require_role("admin")
def list_users_route():
    return jsonify(list_users())


@auth_bp.route("/auth/users", methods=["POST"])
@_require_role("admin")
def create_user_route():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    role = (data.get("role") or "viewer").strip()
    try:
        user = create_user(username, password, role)
    except UserValidationError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(user), 201


@auth_bp.route("/auth/users/<user_id>", methods=["DELETE"])
@_require_role("admin")
def delete_user_route(user_id):
    current = getattr(g, "current_user", None)
    if current and current.get("id") == user_id:
        return jsonify({"error": "Cannot delete your own account."}), 400
    try:
        deleted = delete_user(user_id)
    except UserValidationError as exc:
        return jsonify({"error": str(exc)}), 400
    if not deleted:
        return jsonify({"error": "User not found."}), 404
    return jsonify({"deleted": True})


# ── Per-user credential management (any authenticated user) ────────────────────


@auth_bp.route("/auth/change-password", methods=["POST"])
def change_password_route():
    current = getattr(g, "current_user", None)
    if current is None:
        return jsonify({"error": "Authentication required."}), 401

    data = request.get_json(silent=True) or {}
    new_password = data.get("new_password") or ""
    try:
        change_password(current["id"], new_password)
    except UserValidationError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"ok": True})


@auth_bp.route("/auth/generate-api-key", methods=["POST"])
def generate_api_key_route():
    current = getattr(g, "current_user", None)
    if current is None:
        return jsonify({"error": "Authentication required."}), 401

    plaintext = generate_api_key(current["id"])
    hint = ("csh_..." + plaintext[-4:]) if len(plaintext) >= 4 else ""
    return jsonify({"ok": True, "api_key": plaintext, "api_key_hint": hint})


@auth_bp.route("/auth/revoke-api-key", methods=["POST"])
def revoke_api_key_route():
    current = getattr(g, "current_user", None)
    if current is None:
        return jsonify({"error": "Authentication required."}), 401

    revoke_api_key(current["id"])
    return jsonify({"ok": True})
