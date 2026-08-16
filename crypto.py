"""AES-256-GCM token encryption utilities.

All platform access/refresh tokens are encrypted at rest using AES-256-GCM.
The encryption key is derived from SESSION_SECRET via HKDF-SHA256 so no
additional secret needs to be managed.

Usage:
    from crypto import encrypt_token, decrypt_token

    stored = encrypt_token("raw_access_token")
    original = decrypt_token(stored)
"""

import os
import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


_ENCRYPTION_INFO = b"alpha-platform-token-aes256gcm-v1"
_NONCE_LEN = 12  # 96-bit nonce — GCM standard


def _derive_key() -> bytes:
    """Derive a 32-byte AES key from SESSION_SECRET via HKDF-SHA256."""
    raw_secret = os.environ.get("SESSION_SECRET", "")
    if not raw_secret:
        raise RuntimeError(
            "SESSION_SECRET is not set. Cannot derive token encryption key."
        )
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_ENCRYPTION_INFO,
    )
    return hkdf.derive(raw_secret.encode())


def encrypt_token(plaintext: str) -> str:
    """Encrypt *plaintext* and return a base64-encoded «nonce‖ciphertext» blob.

    The blob is safe to store as TEXT in any database column.
    """
    key = _derive_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(_NONCE_LEN)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext).decode("ascii")


def decrypt_token(encoded: str) -> str:
    """Decrypt a blob previously produced by :func:`encrypt_token`.

    Falls back to returning *encoded* unchanged if decryption fails — this
    allows backward-compatibility with legacy unencrypted tokens that were
    stored before encryption was introduced.
    """
    try:
        key = _derive_key()
        aesgcm = AESGCM(key)
        raw = base64.b64decode(encoded)
        nonce, ciphertext = raw[:_NONCE_LEN], raw[_NONCE_LEN:]
        return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")
    except Exception:  # noqa: BLE001
        # Graceful fallback: treat as unencrypted (legacy token)
        return encoded
