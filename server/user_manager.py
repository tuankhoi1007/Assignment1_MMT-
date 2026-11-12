"""
CO3093 - User State & Session Manager.
Maintains thread-safe user records, active socket references, and heartbeat timestamps.
"""

import time
import secrets
import threading

from protocol.crypto import fingerprint


class UserSession:
    """Represents an active client session."""

    def __init__(self, username, tcp_sock, addr, udp_port=0, pubkey=None):
        self.username = username
        self.tcp_sock = tcp_sock
        self.ip = addr[0]
        self.tcp_port = addr[1]
        self.udp_port = udp_port
        self.last_heartbeat = time.time()
        self.authenticated = False
        self.lock = threading.RLock()
        self.pubkey = pubkey
        self.udp_token = secrets.token_hex(16)  # legacy secret; UDP heartbeats no longer carry it
        self.heartbeat_key = None  # HMAC key derived from the login X25519 handshake
        self.hb_counter = 0
        self.pending_challenge = None
        self.pending_challenge_addr = None
        self.pending_challenge_until = 0.0
        self.udp_addr = None  # (ip, port) confirmed by an authenticated heartbeat
        self.guest = False

    def to_dict(self):
        """Serialize user information for peer discovery. The UDP token is not included."""
        return {
            "username": self.username,
            "ip": self.ip,
            "tcp_port": self.tcp_port,
            "udp_port": self.udp_port,
            "last_active": self.last_heartbeat,
            "pubkey": self.pubkey,
            "fingerprint": fingerprint(self.pubkey) if self.pubkey else None,
        }


class UserManager:
    """Thread-safe registry of connected users."""

    def __init__(self):
        self._users = {}
        self._lock = threading.RLock()

    def add_user(self, username, tcp_sock, addr, udp_port=0, pubkey=None):
        """Register a new user session if the username is unique."""
        with self._lock:
            if username in self._users:
                return None
            session = UserSession(username, tcp_sock, addr, udp_port, pubkey)
            self._users[username] = session
            return session

    def remove_user(self, username):
        """Remove a user session upon disconnection."""
        with self._lock:
            return self._users.pop(username, None)

    def get_user(self, username):
        """Look up a user session by username."""
        with self._lock:
            return self._users.get(username)

    def get_all_users(self):
        """Return serialized info for all authenticated users."""
        with self._lock:
            return [s.to_dict() for s in self._users.values() if s.authenticated]

    def get_all_sessions(self):
        """Return active sessions for broadcast delivery."""
        with self._lock:
            return [s for s in self._users.values() if s.authenticated]

    def update_heartbeat(self, username, udp_addr=None):
        """Refresh last-active time. Pass udp_addr only after that source has been authenticated."""
        with self._lock:
            user = self._users.get(username)
            if user:
                user.last_heartbeat = time.time()
                if udp_addr:
                    user.udp_addr = udp_addr

    def cleanup_inactive_users(self, timeout_sec=15.0):
        """Remove users who have not sent a heartbeat within timeout period; returns removed sessions."""
        now = time.time()
        with self._lock:
            stale_names = [name for name, s in self._users.items() if now - s.last_heartbeat > timeout_sec]
            return [self._users.pop(name) for name in stale_names if name in self._users]
