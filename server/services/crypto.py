"""
Server-side cryptography mirror of the agent's C implementation.
Algorithm chain: ECDH X25519 → HKDF-SHA256 → ChaCha20-Poly1305
Library: PyCA cryptography
"""
from __future__ import annotations
import base64
import json
import os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)


NONCE_SIZE  = 12
TAG_SIZE    = 16
KEY_SIZE    = 32
HKDF_INFO   = b"kdf-sess-v1"


class AgentCrypto:
    """Holds ECDH keypair + derived session key for one agent."""

    def __init__(self):
        self._priv: X25519PrivateKey | None = None
        self._session_key: bytes | None = None

    # ---- Keypair ----

    def generate_keypair(self) -> bytes:
        """Generate server ECDH keypair. Returns 32-byte raw public key."""
        self._priv = X25519PrivateKey.generate()
        return self._priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def server_pubkey_bytes(self) -> bytes:
        if self._priv is None:
            raise RuntimeError("keypair not generated")
        return self._priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def server_privkey_hex(self) -> str:
        if self._priv is None:
            raise RuntimeError("keypair not generated")
        return self._priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()

    # ---- Handshake ----

    def do_handshake(self, agent_pubkey_bytes: bytes) -> None:
        """Perform ECDH + HKDF, derive session key from agent's raw public key."""
        if self._priv is None:
            raise RuntimeError("generate_keypair() must be called first")
        agent_pub = X25519PublicKey.from_public_bytes(agent_pubkey_bytes)
        shared    = self._priv.exchange(agent_pub)
        hkdf = HKDF(
            algorithm=SHA256(),
            length=KEY_SIZE,
            salt=None,
            info=HKDF_INFO,
        )
        self._session_key = hkdf.derive(shared)

    def load_from_hex(self, privkey_hex: str, session_key_hex: str) -> None:
        """Restore crypto state from DB-persisted hex strings."""
        raw_priv = bytes.fromhex(privkey_hex)
        self._priv = X25519PrivateKey.from_private_bytes(raw_priv)
        if session_key_hex:
            self._session_key = bytes.fromhex(session_key_hex)

    def session_key_hex(self) -> str:
        if self._session_key is None:
            return ""
        return self._session_key.hex()

    @property
    def ready(self) -> bool:
        return self._session_key is not None

    # ---- Encryption / Decryption ----

    def seal(self, plaintext: bytes) -> str:
        """Encrypt bytes, return base64 string (nonce|ct|tag)."""
        if not self.ready:
            raise RuntimeError("session key not established")
        nonce = os.urandom(NONCE_SIZE)
        aead  = ChaCha20Poly1305(self._session_key)
        ct    = aead.encrypt(nonce, plaintext, None)  # ct includes tag
        blob  = nonce + ct
        return base64.b64encode(blob).decode()

    def open(self, b64_blob: str) -> bytes:
        """Decrypt base64 blob (nonce|ct|tag), return plaintext bytes."""
        if not self.ready:
            raise RuntimeError("session key not established")
        blob  = base64.b64decode(b64_blob)
        nonce = blob[:NONCE_SIZE]
        ct    = blob[NONCE_SIZE:]
        aead  = ChaCha20Poly1305(self._session_key)
        return aead.decrypt(nonce, ct, None)

    # ---- JSON packet helpers ----

    def seal_json(self, payload: dict) -> str:
        """Encrypt a dict as JSON, return base64."""
        return self.seal(json.dumps(payload).encode())

    def open_json(self, b64_blob: str) -> dict:
        """Decrypt a base64 blob, parse as JSON dict."""
        return json.loads(self.open(b64_blob).decode())


# Standalone helpers  

def decode_handshake_packet(b64_pkt: str) -> dict:
    """
    Decode a plaintext (non-encrypted) handshake packet from the agent.
    Format: base64({"t":"h","id":"...","pk":"<b64>"})
    """
    raw = base64.b64decode(b64_pkt)
    return json.loads(raw.decode())


def build_handshake_response(server_pubkey_bytes: bytes) -> str:
    """
    Build a plaintext handshake response for the agent.
    Returns base64({"t":"hr","spk":"<b64>"})
    """
    payload = {
        "t":   "hr",
        "spk": base64.b64encode(server_pubkey_bytes).decode(),
    }
    return base64.b64encode(json.dumps(payload).encode()).decode()
