"""
Ed25519 key generation and DID:key construction.

DID:key spec: https://w3c-ccg.github.io/did-method-key/#ed25519-x25519
  raw Ed25519 public key → prefix 0xED 0x01 → base58btc → prepend 'z'
"""
from __future__ import annotations

import base64

import base58
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

_ED25519_PREFIX = bytes([0xED, 0x01])


def generate_keypair() -> dict[str, str]:
    """
    Generate a new Ed25519 keypair with a DID:key identifier.

    Returns:
        {"public_key": "<base64>", "private_key": "<base64>", "did": "did:key:z6Mk..."}

    The private_key should be stored securely and never shared.
    Register the public_key + did with Codios via POST /agents.
    """
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_bytes = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {
        "public_key": base64.b64encode(pub_bytes).decode(),
        "private_key": base64.b64encode(priv_bytes).decode(),
        "did": _bytes_to_did(pub_bytes),
    }


def public_key_to_did(public_key_b64: str) -> str:
    """Derive DID:key from a base64-encoded Ed25519 public key."""
    return _bytes_to_did(base64.b64decode(public_key_b64))


def _bytes_to_did(pub_bytes: bytes) -> str:
    return "did:key:z" + base58.b58encode(_ED25519_PREFIX + pub_bytes).decode()
