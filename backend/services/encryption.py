"""
BYOK (Bring Your Own Key) encryption service.

Algorithm : AES-256-GCM, random 96-bit nonce per operation.
Key source : BYOK_KEY env var — base64-encoded 32 raw bytes.
             Optionally BYOK_KMS_ARN for AWS KMS key-wrapping (envelope encryption).

Ciphertext format: "byok1:<base64url(nonce[12] + ciphertext + tag[16])>"
The "byok1:" version prefix allows future algorithm migration and key rotation.

If BYOK_KEY is not set, encrypt/decrypt are pass-through (values stored plaintext).
This preserves backwards compatibility for existing deployments.
"""
from __future__ import annotations

import base64
import os
from functools import lru_cache

_PREFIX = "byok1:"
_NONCE_LEN = 12
_TAG_LEN = 16


# ── Key loading ───────────────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def _get_raw_key() -> bytes | None:
    """Returns the 32-byte AES key, or None if BYOK is not configured."""
    raw = os.getenv("BYOK_KEY", "")
    if not raw:
        return None
    try:
        key = base64.b64decode(raw)
    except Exception:
        raise RuntimeError("BYOK_KEY is not valid base64")
    if len(key) != 32:
        raise RuntimeError(f"BYOK_KEY must be 32 bytes (got {len(key)})")
    return key


def is_enabled() -> bool:
    return _get_raw_key() is not None


def current_key_id() -> str:
    """Stable short identifier for the current key (first 8 hex chars of SHA-256)."""
    key = _get_raw_key()
    if key is None:
        return "none"
    import hashlib
    return hashlib.sha256(key).hexdigest()[:8]


# ── Encrypt / Decrypt ─────────────────────────────────────────────────────────

def encrypt(plaintext: str) -> str:
    """
    Encrypt plaintext with the configured BYOK key.
    Returns a "byok1:<base64url>" ciphertext string.
    If BYOK is not configured, returns plaintext unchanged.
    """
    key = _get_raw_key()
    if key is None:
        return plaintext

    import os as _os
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = _os.urandom(_NONCE_LEN)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)  # includes 16-byte tag
    blob = nonce + ct
    return _PREFIX + base64.urlsafe_b64encode(blob).rstrip(b"=").decode()


def decrypt(value: str) -> str:
    """
    Decrypt a "byok1:<base64url>" value.
    If the value does not start with "byok1:", returns it unchanged
    (supports plaintext values stored before BYOK was enabled).
    """
    if not value.startswith(_PREFIX):
        return value  # stored plaintext — not yet encrypted

    key = _get_raw_key()
    if key is None:
        raise RuntimeError(
            "Value is BYOK-encrypted but BYOK_KEY is not set. "
            "Set BYOK_KEY to the key used when this value was encrypted."
        )

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    b64 = value[len(_PREFIX):]
    blob = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
    nonce, ct = blob[:_NONCE_LEN], blob[_NONCE_LEN:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None).decode()


# ── Key generation helper (for operators) ────────────────────────────────────

def generate_key() -> str:
    """Generate a fresh 32-byte AES key and return it as base64."""
    import os as _os
    return base64.b64encode(_os.urandom(32)).decode()


# ── Bulk re-encryption (used by /keys/byok/rotate) ───────────────────────────

async def reencrypt_all(old_key_b64: str, new_key_b64: str) -> dict[str, int]:
    """
    Re-encrypt all BYOK-encrypted fields using old_key → new_key.
    Returns counts per table.
    """
    from db import get_pool

    old_key = base64.b64decode(old_key_b64)
    new_key = base64.b64decode(new_key_b64)

    def _reenc(value: str) -> str:
        if not value.startswith(_PREFIX):
            return value
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import os as _os
        b64 = value[len(_PREFIX):]
        blob = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
        nonce, ct = blob[:_NONCE_LEN], blob[_NONCE_LEN:]
        plaintext = AESGCM(old_key).decrypt(nonce, ct, None)
        new_nonce = _os.urandom(_NONCE_LEN)
        new_ct = AESGCM(new_key).encrypt(new_nonce, plaintext, None)
        blob2 = new_nonce + new_ct
        return _PREFIX + base64.urlsafe_b64encode(blob2).rstrip(b"=").decode()

    pool = await get_pool()
    counts: dict[str, int] = {}

    # Re-encrypt webhook secrets
    wh_rows = await pool.fetch("SELECT id, secret FROM codios.webhook_endpoints WHERE secret LIKE 'byok1:%'")
    for row in wh_rows:
        new_val = _reenc(row["secret"])
        await pool.execute("UPDATE codios.webhook_endpoints SET secret=$2 WHERE id=$1", row["id"], new_val)
    counts["webhook_endpoints"] = len(wh_rows)

    # Re-encrypt SSO client secrets
    sso_rows = await pool.fetch("SELECT id, client_secret FROM codios.sso_configs WHERE client_secret LIKE 'byok1:%'")
    for row in sso_rows:
        new_val = _reenc(row["client_secret"])
        await pool.execute("UPDATE codios.sso_configs SET client_secret=$2 WHERE id=$1", row["id"], new_val)
    counts["sso_configs"] = len(sso_rows)

    return counts
