"""
CO3093 - Security layer: X25519 key agreement, HKDF-SHA256, AES-256-GCM.

Each login mints a fresh X25519 key pair. Two uses follow from the same primitive:

* Client <-> server: the handshake exchanges ephemeral public keys and both sides
  derive a per-connection channel key. The password travels under that key.
  A second derived key (context "udp-heartbeat") authenticates UDP heartbeats,
  so the login token is never sent in the clear. The server never learns a
  client's long-term private key (there isn't one; keys are session keys).
* Client <-> client: chat and file chunks are encrypted with a key derived from
  X25519(my_private, peer_public). The server only relays public keys and
  ciphertext, so it cannot read them.

Limitation: public keys are distributed by the server and are not certified.
A server that substitutes keys can sit in the middle. Peers can compare
KeyPair.fingerprint out of band to detect that.
"""

import os
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

NONCE_SIZE = 12
TAG_SIZE = 16
KEY_INFO_PREFIX = b"CO3093-collab-v2|"


class CryptoManager:
    """AES-256-GCM for one 32-byte key. Output is nonce || ciphertext || tag."""

    def __init__(self, key=None):
        # No shared hard-coded key. Callers that omit `key` get a random one,
        # which is only useful inside a single process (unit tests).
        self.key = key if key is not None else AESGCM.generate_key(bit_length=256)
        if len(self.key) != 32:
            raise ValueError("AES-256 key must be 32 bytes")
        self.aesgcm = AESGCM(self.key)

    def encrypt(self, plaintext, aad=None):
        """Encrypt bytes. `aad` is authenticated but not encrypted (binds context)."""
        nonce = os.urandom(NONCE_SIZE)
        return nonce + self.aesgcm.encrypt(nonce, plaintext, aad)

    def decrypt(self, encrypted_data, aad=None):
        """Decrypt and check the GCM tag. Raises InvalidTag if the tag or AAD mismatches."""
        if len(encrypted_data) < NONCE_SIZE + TAG_SIZE:
            raise ValueError("Encrypted data is too short (< 28 bytes)")
        nonce = encrypted_data[:NONCE_SIZE]
        ciphertext = encrypted_data[NONCE_SIZE:]
        return self.aesgcm.decrypt(nonce, ciphertext, aad)

    def encrypt_string(self, text, aad=None):
        """Encrypt a text string and return Base64 suitable for a JSON field."""
        return base64.b64encode(self.encrypt(text.encode("utf-8"), aad)).decode("ascii")

    def decrypt_string(self, b64_text, aad=None):
        """Decrypt a string produced by encrypt_string."""
        raw = base64.b64decode(b64_text.encode("ascii"))
        return self.decrypt(raw, aad).decode("utf-8")


def fingerprint(public_b64):
    """Short fingerprint of a public key: first 16 hex chars of SHA-256, grouped by 4."""
    try:
        raw = base64.b64decode(public_b64)
        digest = hashlib.sha256(raw).hexdigest()[:16].upper()
        return " ".join(digest[i:i + 4] for i in range(0, 16, 4))
    except Exception:
        return None


class KeyPair:
    """A fresh X25519 key pair. Generated per login; the private key never leaves the process."""

    def __init__(self):
        self._private = X25519PrivateKey.generate()
        raw_pub = self._private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.public_bytes = raw_pub
        self.public_b64 = base64.b64encode(raw_pub).decode("ascii")

    @property
    def fingerprint(self):
        return fingerprint(self.public_b64)

    def derive(self, peer_public_b64, context):
        """
        ECDH + HKDF. Both sides compute the same 32-byte AES key:

            shared = X25519(my_private, peer_public)
            key    = HKDF-SHA256(shared, info = prefix | context | sorted(pubA, pubB))

        `context` separates keys that share the same pair ("client-server", "chat", "file:<id>").
        Sorting the public keys makes the info string independent of who initiates.
        """
        peer_raw = base64.b64decode(peer_public_b64)
        if len(peer_raw) != 32:
            raise ValueError("X25519 public key must be 32 bytes")
        shared = self._private.exchange(X25519PublicKey.from_public_bytes(peer_raw))
        pubs = b"|".join(sorted((self.public_bytes, peer_raw)))
        info = KEY_INFO_PREFIX + str(context).encode("utf-8") + b"|" + pubs
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared)
        return CryptoManager(key)


# Process-local random key. StreamSender/StreamReceiver fall back to it only when the
# caller does not pass a pairwise key (same-process unit tests). It is never sent.
default_crypto = CryptoManager()
