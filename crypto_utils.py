import os, base64, hashlib
from typing import Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PBKDF2_ITERS = 310_000
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32  # 256-bit

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()

def b64d(s: str) -> bytes:
    return base64.b64decode(s)

def new_salt_b64() -> str:
    return b64e(os.urandom(SALT_LEN))

def sha256_auth_hash(password: str, auth_salt_b64: str) -> bytes:
    """SHA-256(auth_salt || password) -> 32B digest for login verification."""
    return hashlib.sha256(b64d(auth_salt_b64) + password.encode()).digest()

def derive_key(password: str, kdf_salt_b64: str, iters: int = PBKDF2_ITERS, length: int = KEY_LEN) -> bytes:
    """Derive AES key from password+salt via PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), b64d(kdf_salt_b64), iters, length)

def aesgcm_encrypt(key: bytes, plaintext: bytes, aad: Optional[bytes] = None) -> Tuple[str, str]:
    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return b64e(nonce), b64e(ct)

def aesgcm_decrypt(key: bytes, nonce_b64: str, ct_b64: str, aad: Optional[bytes] = None) -> bytes:
    nonce = b64d(nonce_b64)
    ct = b64d(ct_b64)
    return AESGCM(key).decrypt(nonce, ct, aad)

import re

def validate_password(password: str):
    """
    Validates password with rules:
    - Min length 6
    - At least one lowercase
    - At least one uppercase
    - At least one symbol
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[a-z]", password):
        return False, "Password must include at least one lowercase letter."
    if not re.search(r"[A-Z]", password):
        return False, "Password must include at least one uppercase letter."
    if not re.search(r"[^A-Za-z0-9]", password):
        return False, "Password must include at least one symbol."
    return True, ""
