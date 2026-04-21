# secure_packager.py
# Secure packaging and unpackaging of encrypted files with BB84, AES + HMAC, and post-quantum signature validation
# ----------------------------------------------------------------------------
# Copyright 2025 Hector Mozo
# Licensed under the Apache License, Version 2.0 (the "License");
# ----------------------------------------------------------------------------

import json
import base64
from typing import List, Tuple, Dict
import os

# Core AES encryption and key utilities
from bb84_backend.core.aes_engine import aes_encrypt, aes_decrypt
from bb84_backend.core.key_utils import (
    derive_aes_key_from_bits,
    verify_key_integrity,
    bits_to_bytes
)

# ----------------------------------------------------------------------------
# Post-quantum (Dilithium) import — this build exposes DEFAULT_PARAMETERS
# and instance methods: keygen(seed), sign_with_input(sk, m), verify(pk, m, sig)
# ----------------------------------------------------------------------------
try:
    from dilithium import Dilithium, DEFAULT_PARAMETERS
    # Prefer Dilithium5 if present (keys are lowercase in this build)
    ps = DEFAULT_PARAMETERS.get("dilithium5") or next(iter(DEFAULT_PARAMETERS.values()))
    dilithium_obj = Dilithium(parameter_set=ps)
    PQCRYPTO_AVAILABLE = True
except Exception as e:
    print(f"[secure_packager] Dilithium unavailable: {e}")
    PQCRYPTO_AVAILABLE = False
    dilithium_obj = None


def _dilithium_keypair_pk_sk(dil) -> Tuple[bytes, bytes]:
    """
    Generate a keypair for this Dilithium build.
    This build requires keygen(key_seed) and returns (pk_bytes, sk_bytes).
    """
    seed = os.urandom(64)  # 64-byte seed works with this build
    pair = dil.keygen(seed)
    if not (isinstance(pair, (tuple, list)) and len(pair) == 2):
        raise RuntimeError("Unexpected keygen output; expected (pk_bytes, sk_bytes).")
    pk, sk = pair
    if not isinstance(pk, (bytes, bytearray)) or not isinstance(sk, (bytes, bytearray)):
        raise RuntimeError("Keygen did not return raw bytes for (pk, sk).")
    return bytes(pk), bytes(sk)


def save_encrypted_file(
    plaintext: bytes,
    key_a_bits: List[int],
    key_b_bits: List[int],
    original_filename: str = "file"
) -> bytes:
    """
    Encrypts the file and returns a secure JSON package (as bytes).
    Now: sensitive fields (file content, key_a_encoded, metadata) are inside the encrypted INTERNAL payload.
    The OUTER package only contains ciphertext, salt, and the post-quantum signature/public key.
    """
    # 1) Derive AES-256 key with salt using Key A
    key_with_salt = derive_aes_key_from_bits(key_a_bits)

    # 2) Build the INTERNAL payload (this will be encrypted)
    internal_payload = {
        "file_bytes_b64": base64.b64encode(plaintext).decode("utf-8"),
        "key_a_encoded": base64.b64encode(bits_to_bytes(key_a_bits)).decode("utf-8"),
        # Optional: hide sensitive metadata inside as well
        "original_filename": original_filename,
        # "extension": "bin",  # add if you track it elsewhere
    }
    internal_bytes = json.dumps(internal_payload).encode("utf-8")

    # 3) Encrypt the entire INTERNAL payload
    encrypted = aes_encrypt(internal_bytes, key_with_salt)

    # 4) OUTER package (NO sensitive fields exposed here)
    package = {
        "ciphertext": base64.b64encode(encrypted).decode("utf-8"),
        "salt": base64.b64encode(key_with_salt[32:]).decode("utf-8"),  # last 16 bytes are salt
        # <-- no key_a_encoded here anymore
    }

    # 5) Require post-quantum signature; fail early if not available
    if not PQCRYPTO_AVAILABLE:
        raise RuntimeError("Dilithium module not available — cannot sign the package.")

    # 6) Post-quantum signature (using this build's API)
    #    Generate (pk, sk) — order confirmed: (pk_bytes, sk_bytes)
    pk_bytes, sk_bytes = _dilithium_keypair_pk_sk(dilithium_obj)

    #    Sign the exact OUTER package bytes using sign_with_input(sk, message)
    package_bytes = json.dumps(package).encode("utf-8")
    signature = dilithium_obj.sign_with_input(sk_bytes, package_bytes)

    #    Attach signature and public key (base64)
    package["pq_signature"] = base64.b64encode(signature).decode("utf-8")
    package["pq_public_key"] = base64.b64encode(pk_bytes).decode("utf-8")

    # 7) Return the complete OUTER JSON package as bytes
    return json.dumps(package).encode("utf-8")


def load_and_decrypt_bytes(
    package_bytes: bytes,
    key_b_bits: List[int]
) -> Tuple[bytes, Dict[str, str], bool]:
    """
    Loads encrypted package and decrypts using derived key if valid.
    Validates post-quantum signature and key integrity before decrypting.

    Returns:
        - Decrypted plaintext bytes
        - Metadata dict
        - Boolean indicating integrity success
    """
    # Parse OUTER package
    package = json.loads(package_bytes.decode("utf-8"))

    # 1) Verify post-quantum signature (if included)
    if PQCRYPTO_AVAILABLE and "pq_signature" in package and "pq_public_key" in package:
        pq_signature = base64.b64decode(package["pq_signature"])
        pq_public_key = base64.b64decode(package["pq_public_key"])

        # Rebuild OUTER package without signature fields for validation
        unsigned_package = {k: v for k, v in package.items() if k not in ("pq_signature", "pq_public_key")}
        unsigned_bytes = json.dumps(unsigned_package).encode("utf-8")

        try:
            # This build's verify order: verify(pk_bytes, message, sig_bytes)
            if not dilithium_obj.verify(pq_public_key, unsigned_bytes, pq_signature):
                return b"", {}, False
        except Exception:
            return b"", {}, False
    else:
        # PQC available but no signature included -> invalid
        return b"", {}, False

    # 2) Extract OUTER encrypted components
    salt = base64.b64decode(package["salt"])
    ciphertext = base64.b64decode(package["ciphertext"])

    # 3) Derive AES key using Bob’s bits and the stored salt
    candidate_key = derive_aes_key_from_bits(key_b_bits, salt)

    # 4) Decrypt the INTERNAL payload
    internal_bytes = aes_decrypt(ciphertext, candidate_key)

    # 5) Parse INTERNAL payload (contains original file and protected fields)
    try:
        internal = json.loads(internal_bytes.decode("utf-8"))
    except Exception:
        return b"", {}, False

    # 6) Rehydrate original content and protected `key_a_encoded`
    try:
        plaintext = base64.b64decode(internal["file_bytes_b64"])
        key_a_encoded_b64 = internal["key_a_encoded"]
    except KeyError:
        return b"", {}, False

    # 7) Reconstruct stored Key A bits from INTERNAL payload (for integrity check)
    encoded_key_a = base64.b64decode(key_a_encoded_b64)
    stored_key_a_bits = [int(bit) for byte in encoded_key_a for bit in f"{byte:08b}"]

    # 8) Integrity check using HMAC (candidate_key vs stored Key A bits)
    integrity_ok = verify_key_integrity(candidate_key, stored_key_a_bits)
    if not integrity_ok:
        return b"", {}, False

    # 9) Metadata (extracted from INTERNAL payload if stored)
    orig_name = internal.get("original_filename") or "decrypted_file"
    orig_name = os.path.basename(orig_name)

    # لا تفرض "bin" إذا مو موجودة.. استنتجها من اسم الملف الأصلي
    ext = internal.get("extension")
    if not ext:
        _, _ext = os.path.splitext(orig_name)
        ext = _ext.lstrip(".") if _ext else ""

    ext = ext.strip().lstrip(".").lower() if ext else ""

    metadata = {"original_filename": orig_name}
    if ext:
        metadata["extension"] = ext

    return plaintext, metadata, True

