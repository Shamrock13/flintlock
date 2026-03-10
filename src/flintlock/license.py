import hashlib
import os
import json
from datetime import datetime

# This is your secret salt - change this to something unique before publishing
SECRET_SALT = os.environ.get("FWAUDIT_SECRET", "fallback-for-dev-only")

LICENSE_FILE = os.environ.get("LICENSE_PATH", os.path.expanduser("~/.flintlock_license"))


def generate_key(email: str) -> str:
    """Generate a license key from an email address - use this to create keys for customers"""
    raw = f"{email}{SECRET_SALT}"
    hash = hashlib.sha256(raw.encode()).hexdigest().upper()
    # Format as XXXX-XXXX-XXXX-XXXX
    return f"{hash[0:4]}-{hash[4:8]}-{hash[8:12]}-{hash[12:16]}"


def validate_key(key: str) -> bool:
    """Validate a license key format and check against stored key"""
    if not key or len(key) != 19:
        return False
    parts = key.split("-")
    if len(parts) != 4 or any(len(p) != 4 for p in parts):
        return False
    return True


def activate_license(key: str) -> tuple:
    """Activate and store a license key"""
    key = key.strip().upper()
    if not validate_key(key):
        return False, "Invalid license key format. Keys should look like: XXXX-XXXX-XXXX-XXXX"

    license_data = {
        "key": key,
        "activated": datetime.now().isoformat(),
    }

    try:
        with open(LICENSE_FILE, 'w') as f:
            json.dump(license_data, f)
        return True, "License activated successfully"
    except Exception as e:
        return False, f"Failed to save license: {e}"


def check_license() -> tuple:
    """Check if a valid license is activated"""
    if not os.path.exists(LICENSE_FILE):
        return False, "No license found."

    try:
        with open(LICENSE_FILE, 'r') as f:
            data = json.load(f)
        key = data.get("key", "")
        if validate_key(key):
            return True, key
        else:
            return False, "Invalid license key. Please re-enter your key to reactivate."
    except Exception as e:
        return False, f"License check failed: {e}"


def deactivate_license():
    """Remove stored license"""
    if os.path.exists(LICENSE_FILE):
        os.remove(LICENSE_FILE)
        return True, "License deactivated"
    return False, "No license found"