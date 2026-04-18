"""
Enforcement endpoint — for agents that can't embed the SDK.

POST /enforce
  Reads X-Codios-Contract header (base64 encoded contract).
  Performs full enforcement pipeline:
    1. Decode + signature verify   (offline, ~0ms)
    2. Nonce consume               (Redis SET NX, ~0.5ms)
    3. Policy evaluate             (Python rules or OPA, ~0ms)
    4. Call counter increment      (Redis INCR, ~0.5ms)
    5. Audit log                   (async, non-blocking)

Returns:
  200  { allowed: true }
  403  { allowed: false, deny_reason: "..." }

No authentication required — the contract signature is the proof.
Rate-limited by IP at the infra level (Cloudflare / Railway).
"""
from __future__ import annotations

import base64
import json
import time
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel

from config import get_settings
from services.crypto import verify_signature, canonicalize, hash_payload
from services.policy import evaluate
from services.audit_buffer import push_audit_event, AuditEvent
from services.redis_client import get_redis
from routers.nonces import _consume_nonce_postgres  # reuse Postgres fallback

router = APIRouter(prefix="/enforce")


class EnforceBody(BaseModel):
    action: str
    caller_did: Optional[str] = None
    payload: Optional[dict] = None     # hashed for audit, never stored raw
    metadata: Optional[dict] = None


@router.post("")
async def enforce(body: EnforceBody, request: Request):
    t0 = time.monotonic()
    settings = get_settings()

    if not settings.codios_public_key:
        raise HTTPException(status_code=503, detail="CODIOS_PUBLIC_KEY not configured")

    # ── 1. Decode contract from header ───────────────────────────────────────
    encoded = request.headers.get("x-codios-contract")
    if not encoded:
        raise HTTPException(status_code=401, detail="Missing X-Codios-Contract header")

    try:
        contract = json.loads(base64.b64decode(encoded).decode())
    except Exception:
        raise HTTPException(status_code=400, detail="Malformed contract — expected base64 JSON")

    # ── 2. Offline signature verification ────────────────────────────────────
    signature = contract.pop("signature", None)
    if not signature:
        _log_denied(contract, body, request, "missing_signature", 0)
        raise HTTPException(status_code=403, detail="missing_signature")

    if not verify_signature(contract, signature, settings.codios_public_key):
        contract["signature"] = signature
        _log_denied(contract, body, request, "invalid_signature", 0)
        raise HTTPException(status_code=403, detail="invalid_signature")

    contract["signature"] = signature

    # ── 3. Expiry fast-path (before Redis call) ───────────────────────────────
    try:
        expires_at = datetime.fromisoformat(contract["expires_at"])
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= datetime.now(timezone.utc):
            _log_denied(contract, body, request, "contract_expired", 0)
            raise HTTPException(status_code=403, detail="contract_expired")
    except HTTPException:
        raise
    except Exception:
        _log_denied(contract, body, request, "invalid_contract", 0)
        raise HTTPException(status_code=400, detail="Invalid expires_at in contract")

    # ── 4. Nonce consumption (replay defense) ─────────────────────────────────
    nonce = contract.get("nonce", "")
    contract_id = contract.get("contract_id", "")

    redis = await get_redis()
    if redis is not None:
        ttl = max(1, int((expires_at - datetime.now(timezone.utc)).total_seconds()))
        stored = await redis.set(f"codios:nonce:{nonce}", contract_id, ex=ttl, nx=True)
        if not stored:
            _log_denied(contract, body, request, "nonce_already_used", 0)
            raise HTTPException(status_code=403, detail="nonce_already_used")
    else:
        try:
            await _consume_nonce_postgres(nonce, contract_id, expires_at)
        except HTTPException as e:
            if e.status_code == 409:
                _log_denied(contract, body, request, "nonce_already_used", 0)
            raise

    # ── 5. Get current call count for resource limit evaluation ───────────────
    calls_used = 0
    if redis is not None:
        count_key = f"codios:calls:{contract_id}"
        raw = await redis.get(count_key)
        calls_used = int(raw) if raw else 0

    # ── 6. Policy evaluation ──────────────────────────────────────────────────
    allowed, deny_reason = await evaluate(
        contract, body.action, calls_used, body.caller_did
    )

    duration_ms = int((time.monotonic() - t0) * 1000)

    if not allowed:
        _log_denied(contract, body, request, deny_reason or "policy_denied", duration_ms, calls_used)
        raise HTTPException(status_code=403, detail=deny_reason or "policy_denied")

    # ── 7. Increment call counter (non-blocking) ─────────────────────────────
    new_count = calls_used + 1
    if redis is not None:
        pipe = redis.pipeline()
        count_key = f"codios:calls:{contract_id}"
        pipe.incr(count_key)
        ttl = max(1, int((expires_at - datetime.now(timezone.utc)).total_seconds()))
        pipe.expire(count_key, ttl)
        await pipe.execute()

    # ── 8. Audit log (async, non-blocking) ────────────────────────────────────
    push_audit_event(AuditEvent(
        org_id=contract.get("issuer", {}).get("agent_id", "unknown"),  # best effort — no auth on this endpoint
        contract_id=contract_id,
        issuer_agent_id=contract.get("issuer", {}).get("agent_id"),
        target_agent_id=contract.get("target", {}).get("agent_id"),
        action=body.action,
        outcome="allowed",
        payload_hash=hash_payload(json.dumps(body.payload)) if body.payload else None,
        ip_address=_get_ip(request),
        duration_ms=duration_ms,
        calls_count=new_count,
        metadata=body.metadata or {},
    ))

    return {
        "allowed": True,
        "contract_id": contract_id,
        "calls_used": new_count,
        "duration_ms": duration_ms,
    }


# ── Helpers ────────────────────────────────────────────────────────────────────

def _log_denied(
    contract: dict,
    body: EnforceBody,
    request: Request,
    reason: str,
    duration_ms: int,
    calls_used: int = 0,
) -> None:
    push_audit_event(AuditEvent(
        org_id=contract.get("issuer", {}).get("agent_id", "unknown"),
        contract_id=contract.get("contract_id"),
        issuer_agent_id=contract.get("issuer", {}).get("agent_id"),
        target_agent_id=contract.get("target", {}).get("agent_id"),
        action=body.action,
        outcome="denied",
        deny_reason=reason,
        ip_address=_get_ip(request),
        duration_ms=duration_ms,
        calls_count=calls_used,
        metadata=body.metadata or {},
    ))


def _get_ip(request: Request) -> Optional[str]:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return None
