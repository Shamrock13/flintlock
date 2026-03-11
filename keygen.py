import hashlib
import sys
import os

SECRET_SALT = os.environ.get("FWAUDIT_SECRET", "fallback-for-dev-only")

def generate_key(email: str) -> str:
    raw = f"{email}{SECRET_SALT}"
    hash = hashlib.sha256(raw.encode()).hexdigest().upper()
    return f"{hash[0:4]}-{hash[4:8]}-{hash[8:12]}-{hash[12:16]}"

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 keygen.py customer@email.com")
        sys.exit(1)
    email = sys.argv[1].strip().lower()
    key = generate_key(email)
    print(f"\nLicense key for {email}:")
    print(f"{key}\n")