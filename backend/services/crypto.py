"""
Ed25519 key generation, DID:key construction, and contract signing/verification.

DID:key spec: https://w3c-ccg.github.io/did-method-key/#ed25519-x25519
  - Generate Ed25519 keypair (32-byte raw keys)
  - Prefix public key with multicodec 0xed 0x01
  - Base58btc-encode the 34 bytes
  - Prepend 'z' (multibase prefix for base58btc)
  - Result: did:key:z6Mk...
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any

import base58
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

# Multicodec prefix for Ed25519 public key
_ED25519_PREFIX = bytes([0xED, 0x01])


def generate_keypair() -> dict:
    """Generate an Ed25519 keypair and return base64 keys + DID:key."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    did = _public_key_to_did(public_bytes)

    return {
        "private_key": base64.b64encode(private_bytes).decode(),
        "public_key": base64.b64encode(public_bytes).decode(),
        "did": did,
    }


def _public_key_to_did(public_bytes: bytes) -> str:
    prefixed = _ED25519_PREFIX + public_bytes
    return "did:key:z" + base58.b58encode(prefixed).decode()


def public_key_to_did(public_key_b64: str) -> str:
    return _public_key_to_did(base64.b64decode(public_key_b64))


def canonicalize(obj: dict) -> str:
    """RFC 8785 JSON Canonicalization — sort keys recursively."""
    def sort_keys(o: Any) -> Any:
        if isinstance(o, dict):
            return {k: sort_keys(v) for k, v in sorted(o.items())}
        if isinstance(o, list):
            return [sort_keys(i) for i in o]
        return o
    return json.dumps(sort_keys(obj), separators=(",", ":"))


def sign_contract(contract_body: dict, private_key_b64: str) -> str:
    """Sign canonical JSON of contract_body. Returns 'ed25519:<base64_sig>'."""
    private_bytes = base64.b64decode(private_key_b64)
    private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
    msg = canonicalize(contract_body).encode()
    signature = private_key.sign(msg)
    return "ed25519:" + base64.b64encode(signature).decode()


def verify_signature(contract_body: dict, signature: str, public_key_b64: str) -> bool:
    """Verify an 'ed25519:<base64_sig>' signature against contract_body."""
    try:
        prefix, sig_b64 = signature.split(":", 1)
        if prefix != "ed25519":
            return False
        sig_bytes = base64.b64decode(sig_b64)
        pub_bytes = base64.b64decode(public_key_b64)
        public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        msg = canonicalize(contract_body).encode()
        public_key.verify(sig_bytes, msg)
        return True
    except Exception:
        return False


def hash_payload(data: str) -> str:
    """SHA-256 hex digest of a string (for audit log payload_hash)."""
    return hashlib.sha256(data.encode()).hexdigest()
