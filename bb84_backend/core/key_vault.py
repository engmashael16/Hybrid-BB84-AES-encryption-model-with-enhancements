"""
Option A - Key Vault Module
Stores Key B encrypted at rest using a passphrase-derived key (PBKDF2-HMAC-SHA256)
and binds the vault to a specific .bb84 file using SHA-256 as AES-GCM AAD.

Goal: remove manual copy/paste of Key B and reduce user workflow risks.
"""

import os
import json
import base64
import hashlib
import time
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VAULT_VERSION = 1
DEFAULT_PBKDF2_ITERS = 200_000  # you can tune this later for UX/performance


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def normalize_bitstring(bits: str) -> str:
    """
    Accepts a bitstring possibly with surrounding whitespace/newlines (from GUI/file),
    and returns a clean '0/1 only' string.
    """
    if bits is None:
        raise ValueError("Key B is missing.")
    bits = bits.strip()
    if bits == "":
        raise ValueError("Key B is empty.")
    if any(ch not in "01" for ch in bits):
        raise ValueError("Key B must be a binary string (only 0s and 1s).")
    return bits


def compute_sha256(path: str) -> bytes:
    """Streaming SHA-256 to handle large files safely."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.digest()  # 32 bytes


def default_vault_path(bb84_path: str) -> str:
    """
    For 'file.bb84' -> 'file.bb84key'
    """
    if bb84_path.lower().endswith(".bb84"):
        return bb84_path[:-5] + ".bb84key"
    return bb84_path + ".bb84key"


def derive_key(passphrase: str, salt: bytes, iterations: int = DEFAULT_PBKDF2_ITERS) -> bytes:
    if not isinstance(passphrase, str) or passphrase == "":
        raise ValueError("Passphrase is required.")
    return hashlib.pbkdf2_hmac(
        "sha256",
        passphrase.encode("utf-8"),
        salt,
        int(iterations),
        dklen=32,  # 256-bit key for AESGCM
    )


def create_vault(
    key_b_bits: str,
    bb84_path: str,
    passphrase: str,
    vault_path: Optional[str] = None,
    iterations: int = DEFAULT_PBKDF2_ITERS,
) -> str:
    """
    Encrypt Key B into a vault file and bind it to the .bb84 file.
    Binding is done via AES-GCM associated data (AAD) = SHA-256(.bb84).
    """
    key_b_bits = normalize_bitstring(key_b_bits)

    if vault_path is None:
        vault_path = default_vault_path(bb84_path)

    bb84_hash = compute_sha256(bb84_path)

    salt = os.urandom(16)
    key = derive_key(passphrase, salt, iterations)

    nonce = os.urandom(12)  # AESGCM standard nonce size
    aesgcm = AESGCM(key)

    # AAD binding: if bb84 file changes OR wrong bb84 selected, decrypt fails.
    ciphertext = aesgcm.encrypt(
        nonce,
        key_b_bits.encode("ascii"),
        bb84_hash,
    )

    payload: Dict[str, Any] = {
        "version": VAULT_VERSION,
        "created_utc": int(time.time()),
        "kdf": {
            "name": "pbkdf2_hmac_sha256",
            "iterations": int(iterations),
            "salt_b64": _b64e(salt),
        },
        "aead": {
            "name": "aes_256_gcm",
            "nonce_b64": _b64e(nonce),
        },
        "binding": {
            "type": "sha256_of_bb84",
            "bb84_sha256_hex": bb84_hash.hex(),
        },
        "ciphertext_b64": _b64e(ciphertext),
        "key_b_len": len(key_b_bits),
    }

    with open(vault_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    return vault_path


def load_vault(vault_path: str, bb84_path: str, passphrase: str) -> str:
    """
    Load vault and recover Key B.
    Will fail if passphrase is wrong OR bb84 file does not match binding.
    """
    with open(vault_path, "r", encoding="utf-8") as f:
        payload = json.load(f)

    if int(payload.get("version", 0)) != VAULT_VERSION:
        raise ValueError("Unsupported key vault version.")

    bb84_hash = compute_sha256(bb84_path)

    expected_hex = payload.get("binding", {}).get("bb84_sha256_hex", "")
    if expected_hex and expected_hex.lower() != bb84_hash.hex():
        raise ValueError("Selected .bb84 file does not match this key vault (binding mismatch).")

    iterations = int(payload["kdf"]["iterations"])
    salt = _b64d(payload["kdf"]["salt_b64"])
    nonce = _b64d(payload["aead"]["nonce_b64"])
    ciphertext = _b64d(payload["ciphertext_b64"])

    key = derive_key(passphrase, salt, iterations)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, bb84_hash)
    except Exception:
        raise ValueError("Wrong passphrase or wrong .bb84 file (vault decryption failed).")

    key_b_bits = plaintext.decode("ascii")
    return normalize_bitstring(key_b_bits)
