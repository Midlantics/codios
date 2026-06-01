"""
Nonce consumption endpoint — replay defense for Codios contracts.
 
Each contract carries a unique nonce. When Agent B receives a request, the
Codios middleware calls POST /nonces/consume. A Redis SET NX records the nonce
with a TTL matching the contract expiry. Any retry of the same nonce is rejected.

If Redis is unavailable, falls back to a Postgres INSERT with a UNIQUE constraint
on the nonce column. ~10x slower but still correct.

This endpoint is intentionally unauthenticated — the contract signature already
proves the caller is legitimate. We do validate nonce format and expiry to avoid
storing junk.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator
from db import get_pool
from services.redis_client import get_redis

router = APIRouter(prefix="/nonces")

# Nonces are 64 hex chars (32-byte secrets.token_hex)
_NONCE_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_TTL_SECONDS = 86_400  # 24 hours — refuse absurdly long-lived contracts


class ConsumeRequest(BaseModel):
    nonce: str
    contract_id: str
    expires_at: str  # ISO-8601 UTC

    @field_validator("nonce")
    @classmethod
    def validate_nonce(cls, v: str) -> str:
        if not _NONCE_RE.match(v):
            raise ValueError("nonce must be 64 hex characters")
        return v


@router.post("/consume", status_code=200)
async def consume_nonce(body: ConsumeRequest):
    """
    Atomically consume a nonce.
    Returns 200 if accepted (first use), 409 if already consumed, 400 if expired.
    """
    try:
        expires_at = datetime.fromisoformat(body.expires_at)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid expires_at format")

    now = datetime.now(timezone.utc)
    if expires_at <= now:
        raise HTTPException(status_code=400, detail="Contract already expired")

    ttl_seconds = int((expires_at - now).total_seconds())
    if ttl_seconds > _MAX_TTL_SECONDS:
        raise HTTPException(status_code=400, detail="Contract TTL exceeds maximum (24h)")

    redis = await get_redis()

    if redis is not None:
        key = f"codios:nonce:{body.nonce}"
        stored = await redis.set(key, body.contract_id, ex=ttl_seconds, nx=True)
        if not stored:
            raise HTTPException(
                status_code=409,
                detail="nonce_already_used",
            )
        return {"ok": True, "backend": "redis"}

    # Postgres fallback
    return await _consume_nonce_postgres(body.nonce, body.contract_id, expires_at)


async def _consume_nonce_postgres(nonce: str, contract_id: str, expires_at: datetime) -> dict:
    pool = await get_pool()
    try:
        await pool.execute(
            """
            INSERT INTO codios.nonces (nonce, contract_id, expires_at)
            VALUES ($1, $2, $3)
            """,
            nonce, contract_id, expires_at,
        )
        return {"ok": True, "backend": "postgres"}
    except Exception as e:
        if "unique" in str(e).lower() or "duplicate" in str(e).lower():
            raise HTTPException(status_code=409, detail="nonce_already_used")
        raise HTTPException(status_code=500, detail=f"Nonce storage error: {e}")


@router.delete("/expired", status_code=200)
async def cleanup_expired_nonces():
    """Prune expired Postgres nonce rows. Called by Vercel Cron."""
    pool = await get_pool()
    result = await pool.execute(
        "DELETE FROM codios.nonces WHERE expires_at < NOW()"
    )
    deleted = int(result.split()[-1]) if result else 0
    return {"ok": True, "deleted": deleted}
