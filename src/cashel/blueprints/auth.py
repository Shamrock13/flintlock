"""Auth blueprint — /login, /logout, /setup, /auth/users/*.

Seed location for future LDAP/OIDC/TACACS+ routes.
"""

import time

from flask import Blueprint, g, jsonify, redirect, render_template, request, session, url_for

from cashel._helpers import _require_role
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

# In-memory lockout: {username_lower: (attempts, lockout_until)}
_lockout: dict = {}


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
        return render_template("login.html", error="Username and password are required."), 401

    key = username.lower()
    attempts, lockout_until = _lockout.get(key, (0, 0))
    if lockout_until and time.time() < lockout_until:
        remaining = int(lockout_until - time.time())
        return render_template(
            "login.html", error=f"Account locked. Try again in {remaining}s."
        ), 429

    user = check_password(username, password)
    if user:
        _lockout.pop(key, None)
        session.clear()
        session["authenticated"] = True
        session["user_id"] = user["id"]
        session["last_seen"] = time.time()
        next_url = request.args.get("next", "")
        # Guard against open-redirect: only accept relative paths
        if next_url and next_url.startswith("/") and not next_url.startswith("//"):
            return redirect(next_url)
        return redirect(url_for("index"))
    else:
        attempts += 1
        lockout_until_new = time.time() + 300 if attempts >= 5 else 0
        _lockout[key] = (attempts, lockout_until_new)
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

    # Enable auth
    settings = get_settings()
    save_settings({**settings, "auth_enabled": True})

    # Auto-login the new admin
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
    # Prevent self-deletion
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
