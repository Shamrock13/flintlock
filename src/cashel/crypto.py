"""Fernet symmetric encryption for stored credentials.

The key is generated on first use and persisted at CASHEL_KEY_FILE.
The default path is ``~/.config/cashel/cashel.key`` so the tool works
out of the box on macOS and Linux without root access.  Docker and
production deployments should override this by setting the environment
variable ``CASHEL_KEY_FILE=/data/cashel.key`` explicitly.

Treat this file like a private key — restrict permissions and back it
up.  Loss of this file means stored credentials cannot be recovered.

Migration: decrypt() silently falls back to legacy base64 decoding so
existing schedule files and settings are transparently upgraded on next
write without a manual migration step.
"""

import base64
import os

from cryptography.fernet import Fernet, InvalidToken


def _key_file() -> str:
    """Return the path to the Fernet key file.

    Defaults to ``~/.config/cashel/cashel.key`` so local development
    works without root access.  Set the ``CASHEL_KEY_FILE`` environment
    variable to override (e.g. ``/data/cashel.key`` in Docker/prod).
    """
    default = os.path.join(os.path.expanduser("~"), ".config", "cashel", "cashel.key")
    return os.environ.get("CASHEL_KEY_FILE", default)


def _load_or_create_key() -> bytes:
    """Return the Fernet key bytes, creating and persisting on first call."""
    path = _key_file()
    if os.path.exists(path):
        with open(path, "rb") as f:
            return f.read().strip()
    key = Fernet.generate_key()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "wb") as f:
        f.write(key)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # Windows / restricted environments
    return key


def get_fernet() -> Fernet:
    return Fernet(_load_or_create_key())


def encrypt(plaintext: str) -> str:
    """Encrypt *plaintext* and return a URL-safe base64 ciphertext string."""
    if not plaintext:
        return ""
    return get_fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt(ciphertext: str) -> str:
    """Decrypt a Fernet ciphertext string.

    Falls back to legacy base64 decoding for credentials stored before
    Fernet encryption was introduced, enabling transparent migration.
    """
    if not ciphertext:
        return ""
    try:
        return get_fernet().decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except (InvalidToken, Exception):
        try:
            return base64.b64decode(ciphertext.encode("ascii")).decode("utf-8")
        except Exception:
            return ""
