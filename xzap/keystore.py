"""
XZAP KeyStore — multi-user key management.

Each user has a unique AES-256 key. Server tries all keys
to decrypt the first frame, identifying the user.

keys.json format:
{
    "users": {
        "vitaly": "base64-key-1",
        "guest1": "base64-key-2"
    }
}

Usage:
    store = KeyStore("keys.json")
    crypto, username = store.identify(encrypted_frame)
"""

import base64
import json
import logging
import os
from pathlib import Path
from .crypto import XZAPCrypto, ALGO_AES_GCM

log = logging.getLogger("xzap.keystore")

PREFIX_SIZE = 16


class KeyStore:
    """Multi-user key management with user identification."""

    def __init__(self, keys_file: str = "keys.json"):
        self.keys_file = keys_file
        self.users: dict[str, XZAPCrypto] = {}
        self.load()

    def load(self):
        """Load keys from JSON file."""
        p = Path(self.keys_file)
        if not p.exists():
            log.warning("KeyStore: %s not found, creating default", self.keys_file)
            self._create_default()
            return

        data = json.loads(p.read_text(encoding="utf-8"))
        self.users.clear()

        for username, key_b64 in data.get("users", {}).items():
            key = base64.b64decode(key_b64)
            self.users[username] = XZAPCrypto(key=key)
            log.info("KeyStore: loaded key for '%s'", username)

        log.info("KeyStore: %d users loaded", len(self.users))

    def _create_default(self):
        """Create default keys.json with existing key."""
        # Check if xzap.key exists (legacy single-key)
        legacy_key = None
        if Path("xzap.key").exists():
            legacy_key = Path("xzap.key").read_bytes()

        users = {}
        if legacy_key:
            users["default"] = base64.b64encode(legacy_key).decode()
        else:
            # Generate new key
            new_key = os.urandom(32)
            users["default"] = base64.b64encode(new_key).decode()

        data = {"users": users}
        Path(self.keys_file).write_text(
            json.dumps(data, indent=2), encoding="utf-8"
        )
        log.info("KeyStore: created %s with %d users", self.keys_file, len(users))
        self.load()

    def add_user(self, username: str) -> str:
        """Add a new user, return base64 key."""
        key = os.urandom(32)
        key_b64 = base64.b64encode(key).decode()

        # Update file
        p = Path(self.keys_file)
        data = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {"users": {}}
        data["users"][username] = key_b64
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")

        # Reload
        self.load()
        log.info("KeyStore: added user '%s'", username)
        return key_b64

    def remove_user(self, username: str) -> bool:
        """Remove a user."""
        p = Path(self.keys_file)
        if not p.exists():
            return False
        data = json.loads(p.read_text(encoding="utf-8"))
        if username not in data.get("users", {}):
            return False
        del data["users"][username]
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
        self.load()
        log.info("KeyStore: removed user '%s'", username)
        return True

    def identify(self, raw_payload: bytes) -> tuple:
        """Try to decrypt payload with each user's key.

        Args:
            raw_payload: [PREFIX_SIZE bytes prefix][encrypted data]

        Returns:
            (XZAPCrypto, username) or (None, None) if no key matches
        """
        encrypted = raw_payload[PREFIX_SIZE:]

        for username, crypto in self.users.items():
            try:
                crypto.decrypt(encrypted)
                return crypto, username
            except Exception:
                continue

        return None, None

    def list_users(self) -> list[str]:
        """Return list of usernames."""
        return list(self.users.keys())
