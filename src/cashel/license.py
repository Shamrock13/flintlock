import hashlib
import os
import json
from datetime import datetime

# This is your secret salt - change this to something unique before publishing
SECRET_SALT = os.environ.get("CASHEL_SECRET", "fallback-for-dev-only")

LICENSE_FILE = os.environ.get("LICENSE_PATH", os.path.expanduser("~/.cashel_license"))

# Demo mode: set CASHEL_DEMO_MODE=true to bypass license checks and disable
# all persistent write operations. Intended exclusively for the hosted demo.
DEMO_MODE: bool = os.environ.get("CASHEL_DEMO_MODE", "false").lower() == "true"


def generate_key(email: str) -> str:
    """Generate a legacy compatibility key from an email address."""
    raw = f"{email.strip().lower()}:{SECRET_SALT}"
    digest = hashlib.sha256(raw.encode()).hexdigest().upper()
    # Format as CSL-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX (5 groups of 8)
    groups = "-".join(digest[i : i + 8] for i in range(0, 40, 8))
    return f"CSL-{groups}"


def validate_key(key: str) -> bool:
    """Validate a legacy compatibility key."""
    if not key or len(key) != 48:
        return False
    parts = key.split("-")
    if len(parts) != 6 or parts[0] != "CSL":
        return False
    if any(len(p) != 8 for p in parts[1:]):
        return False
    return True


def activate_license(key: str) -> tuple:
    """Store a legacy compliance access key."""
    key = key.strip().upper()
    if not validate_key(key):
        return (
            False,
            "Invalid legacy access key format. Keys should look like: CSL-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX",
        )

    license_data = {
        "key": key,
        "activated": datetime.now().isoformat(),
    }

    try:
        with open(LICENSE_FILE, "w") as f:
            json.dump(license_data, f)
        return True, "Legacy compliance access updated"
    except Exception as e:
        return False, f"Failed to save legacy access state: {e}"


def mask_key(key: str) -> str:
    """Return an obfuscated version of a legacy key showing only the first segment."""
    parts = key.split("-")
    if len(parts) >= 2:
        masked = "-".join([parts[0], parts[1]] + ["\u2022" * len(p) for p in parts[2:]])
        return masked
    return key[:4] + "\u2022" * (len(key) - 4)


def check_license() -> tuple:
    """Check whether legacy compliance access is active.
    In demo mode this always returns True so compliance features are available.
    """
    if DEMO_MODE:
        return True, "DEMO-MODE-ACTIVE"

    if not os.path.exists(LICENSE_FILE):
        return False, "No legacy compliance access state found."

    try:
        with open(LICENSE_FILE, "r") as f:
            data = json.load(f)
        key = data.get("key", "")
        if validate_key(key):
            return True, key
        else:
            return (
                False,
                "Invalid legacy access key. Please re-enter your CSL- key to update compatibility state.",
            )
    except Exception as e:
        return False, f"Legacy compliance access check failed: {e}"


def deactivate_license():
    """Remove stored legacy compliance access state."""
    if os.path.exists(LICENSE_FILE):
        os.remove(LICENSE_FILE)
        return True, "Legacy compliance access cleared"
    return False, "No legacy compliance access state found"
