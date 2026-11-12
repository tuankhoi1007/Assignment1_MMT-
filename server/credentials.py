"""
CO3093 - Password database.

Passwords are stored as scrypt hashes with a random per-user salt.
The file is JSON so an operator can seed accounts by copying it; the
password itself is never written.
"""

import hashlib
import hmac
import json
import os
import secrets
import threading

MIN_PASSWORD_LEN = 4
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
HASH_LEN = 32


class CredentialStore:
    """Thread-safe username -> salted scrypt record, optionally persisted as JSON."""

    def __init__(self, path=None):
        self.path = path
        self._users = {}
        self._lock = threading.RLock()
        if path and os.path.isfile(path):
            self._load()

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                self._users = {str(k): v for k, v in data.items() if isinstance(v, dict)}
        except (OSError, ValueError):
            self._users = {}

    def _save(self):
        if not self.path:
            return
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._users, f, indent=2)
            f.write("\n")
        os.replace(tmp, self.path)

    def is_registered(self, username):
        with self._lock:
            return username in self._users

    def register(self, username, password):
        """Create an account. Returns (ok, reason)."""
        username = (username or "").strip()
        if not username:
            return False, "Username cannot be empty"
        if not isinstance(password, str) or len(password) < MIN_PASSWORD_LEN:
            return False, f"Password must be at least {MIN_PASSWORD_LEN} characters"
        with self._lock:
            if username in self._users:
                return False, "Username already registered"
            salt = secrets.token_bytes(16)
            digest = hashlib.scrypt(
                password.encode("utf-8"),
                salt=salt,
                n=SCRYPT_N,
                r=SCRYPT_R,
                p=SCRYPT_P,
                dklen=HASH_LEN,
            )
            self._users[username] = {
                "salt": salt.hex(),
                "hash": digest.hex(),
                "n": SCRYPT_N,
                "r": SCRYPT_R,
                "p": SCRYPT_P,
            }
            self._save()
        return True, "Registered"

    def verify(self, username, password):
        """Constant-time check of a password against the stored scrypt hash."""
        if not isinstance(password, str):
            return False
        with self._lock:
            rec = self._users.get(username)
            if not rec:
                return False
            try:
                salt = bytes.fromhex(rec["salt"])
                expected = bytes.fromhex(rec["hash"])
                digest = hashlib.scrypt(
                    password.encode("utf-8"),
                    salt=salt,
                    n=int(rec.get("n", SCRYPT_N)),
                    r=int(rec.get("r", SCRYPT_R)),
                    p=int(rec.get("p", SCRYPT_P)),
                    dklen=len(expected),
                )
            except (KeyError, ValueError, TypeError):
                return False
            return hmac.compare_digest(digest, expected)
