import hashlib
import os
import json
from datetime import datetime

# This is your secret salt - change this to something unique before publishing
SECRET_SALT = os.environ.get("CASHEL_SECRET", "fallback-for-dev-only")

LICENSE_FILE = os.environ.get("LICENSE_PATH", os.path.expanduser("~/.cashel_license"))


def generate_key(email: str) -> str:
    """Generate a license key from an email address - must match the Cashel license server algorithm"""
    raw = f"{email.strip().lower()}:{SECRET_SALT}"
    digest = hashlib.sha256(raw.encode()).hexdigest().upper()
    # Format as CSL-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX (5 groups of 8)
    groups = "-".join(digest[i : i + 8] for i in range(0, 40, 8))
    return f"CSL-{groups}"


def validate_key(key: str) -> bool:
    """Validate a Cashel license key — format: CSL-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX"""
    if not key or len(key) != 48:
        return False
    parts = key.split("-")
    if len(parts) != 6 or parts[0] != "CSL":
        return False
    if any(len(p) != 8 for p in parts[1:]):
        return False
    return True


def activate_license(key: str) -> tuple:
    """Activate and store a license key"""
    key = key.strip().upper()
    if not validate_key(key):
        return (
            False,
            "Invalid license key format. Keys should look like: CSL-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX",
        )

    license_data = {
        "key": key,
        "activated": datetime.now().isoformat(),
    }

    try:
        with open(LICENSE_FILE, "w") as f:
            json.dump(license_data, f)
        return True, "License activated successfully"
    except Exception as e:
        return False, f"Failed to save license: {e}"


def mask_key(key: str) -> str:
    """Return an obfuscated version of a license key showing only the first segment."""
    parts = key.split("-")
    if len(parts) >= 2:
        masked = "-".join([parts[0], parts[1]] + ["\u2022" * len(p) for p in parts[2:]])
        return masked
    return key[:4] + "\u2022" * (len(key) - 4)


def check_license() -> tuple:
    """Check if a valid license is activated"""
    if not os.path.exists(LICENSE_FILE):
        return False, "No license found."

    try:
        with open(LICENSE_FILE, "r") as f:
            data = json.load(f)
        key = data.get("key", "")
        if validate_key(key):
            return True, key
        else:
            return (
                False,
                "Invalid license key. Please re-enter your CSL- key to reactivate.",
            )
    except Exception as e:
        return False, f"License check failed: {e}"


def deactivate_license():
    """Remove stored license"""
    if os.path.exists(LICENSE_FILE):
        os.remove(LICENSE_FILE)
        return True, "License deactivated"
    return False, "No license found"
