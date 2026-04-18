"""
Contract issue + verification — fully offline, no network calls.

Verification order: expiry → action scope → signature (fail-fast).
All checks complete in < 1ms; safe to call from async handlers without asyncio.to_thread.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


# ── Types ──────────────────────────────────────────────────────────────────────

@dataclass
class VerifyResult:
    valid: bool
    reason: str | None = None
    payload: dict | None = None   # full contract dict when valid=True


# ── Public API ─────────────────────────────────────────────────────────────────

def verify_contract(
    encoded: str | dict,
    platform_public_key: str,
    action: str | None = None,
) -> VerifyResult:
    """
    Verify a signed Codios contract offline.

    Args:
        encoded:              Base64 contract string (X-Codios-Contract header value)
                              OR already-decoded contract dict.
        platform_public_key:  Base64 Ed25519 public key (CODIOS_PUBLIC_KEY env var).
        action:               Action to scope-check (optional).

    Returns:
        VerifyResult — .valid bool, .reason str on failure, .payload dict on success.

    Reasons: "missing" | "expired" | "action_not_allowed" | "invalid_signature"
    """
    if not encoded:
        return VerifyResult(valid=False, reason="missing")

    if isinstance(encoded, str):
        try:
            contract = decode_contract(encoded)
        except Exception:
            return VerifyResult(valid=False, reason="invalid_signature")
    else:
        contract = encoded

    # 1. Expiry
    try:
        expires_at = datetime.fromisoformat(contract["expires_at"])
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < datetime.now(timezone.utc):
            return VerifyResult(valid=False, reason="expired")
    except (KeyError, ValueError):
        return VerifyResult(valid=False, reason="invalid_signature")

    # 2. Action scope
    if action:
        if action in contract.get("forbidden_actions", []):
            return VerifyResult(valid=False, reason="action_not_allowed")
        allowed = contract.get("allowed_actions", [])
        if allowed and action not in allowed:
            return VerifyResult(valid=False, reason="action_not_allowed")

    # 3. Ed25519 signature
    signature = contract.get("signature", "")
    body = {k: v for k, v in contract.items() if k != "signature"}
    if not _verify_sig(body, signature, platform_public_key):
        return VerifyResult(valid=False, reason="invalid_signature")

    return VerifyResult(valid=True, payload=contract)


def issue_contract(
    *,
    issuer_agent_id: str,
    issuer_did: str,
    target_agent_id: str,
    target_did: str,
    allowed_actions: list[str],
    forbidden_actions: list[str] | None = None,
    max_calls: int | None = None,
    max_tokens: int | None = None,
    max_duration_seconds: int | None = None,
    ttl_seconds: int = 3600,
    codios_private_key: str,
) -> dict:
    """
    Issue and sign a capability contract. Call server-side only — requires the private key.

    Returns the full signed contract dict ready to be encoded and sent as a header.
    """
    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=ttl_seconds)

    limits: dict[str, int] = {}
    if max_calls is not None:
        limits["max_calls"] = max_calls
    if max_tokens is not None:
        limits["max_tokens"] = max_tokens
    if max_duration_seconds is not None:
        limits["max_duration_seconds"] = max_duration_seconds

    body: dict = {
        "contract_id": "ctr_" + secrets.token_hex(16),
        "version": "1.0",
        "issued_at": now.isoformat(),
        "expires_at": expires.isoformat(),
        "issuer": {"agent_id": issuer_agent_id, "did": issuer_did},
        "target": {"agent_id": target_agent_id, "did": target_did},
        "allowed_actions": allowed_actions,
        "forbidden_actions": forbidden_actions or [],
        "resource_limits": limits,
        "nonce": secrets.token_hex(32),
    }
    return {**body, "signature": _sign(body, codios_private_key)}


def encode_contract(contract: dict) -> str:
    """Base64-encode a contract dict for use as X-Codios-Contract header value."""
    return base64.b64encode(json.dumps(contract).encode()).decode()


def decode_contract(encoded: str) -> dict:
    """Decode a base64 contract string back to a dict."""
    return json.loads(base64.b64decode(encoded).decode())


def hash_payload(data: Any) -> str:
    """SHA-256 hex digest — use for audit log payload_hash field."""
    import hashlib
    return hashlib.sha256(json.dumps(data, separators=(",", ":")).encode()).hexdigest()


# ── Internals ──────────────────────────────────────────────────────────────────

def _canonicalize(obj: Any) -> str:
    def sort_keys(o: Any) -> Any:
        if isinstance(o, dict):
            return {k: sort_keys(v) for k, v in sorted(o.items())}
        if isinstance(o, list):
            return [sort_keys(i) for i in o]
        return o
    return json.dumps(sort_keys(obj), separators=(",", ":"))


def _sign(body: dict, private_key_b64: str) -> str:
    priv_bytes = base64.b64decode(private_key_b64)
    key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
    sig = key.sign(_canonicalize(body).encode())
    return "ed25519:" + base64.b64encode(sig).decode()


def _verify_sig(body: dict, signature: str, public_key_b64: str) -> bool:
    try:
        prefix, sig_b64 = signature.split(":", 1)
        if prefix != "ed25519":
            return False
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        pub.verify(base64.b64decode(sig_b64), _canonicalize(body).encode())
        return True
    except (InvalidSignature, Exception):
        return False
