"""
API Key management for Codios.

Keys use prefix 'codios_sk_' and are SHA-256 hashed before storage.
The raw key is returned only once on creation.
"""
from __future__ import annotations

import hashlib
import secrets
import uuid
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
from db import get_pool
from auth import get_org_id

router = APIRouter(prefix="/keys")

_PREFIX = "codios_sk_"


class KeyCreate(BaseModel):
    name: str
    agent_id: str | None = None  # optionally scope to a specific agent


@router.get("")
async def list_keys(request: Request):
    org_id = await get_org_id(request)
    pool = await get_pool()
    rows = await pool.fetch(
        """
        SELECT k.id, k.name, k.agent_id, k.revoked, k.last_used_at, k.created_at,
               a.name AS agent_name
        FROM codios.api_keys k
        LEFT JOIN codios.agents a ON a.id = k.agent_id
        WHERE k.org_id = $1
        ORDER BY k.created_at DESC
        """,
        org_id,
    )
    return [dict(r) for r in rows]


@router.post("", status_code=201)
async def create_key(body: KeyCreate, request: Request):
    org_id = await get_org_id(request)
    pool = await get_pool()

    if body.agent_id:
        agent = await pool.fetchrow(
            "SELECT id FROM codios.agents WHERE id=$1 AND org_id=$2",
            body.agent_id, org_id,
        )
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")

    raw = _PREFIX + secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw.encode()).hexdigest()

    row = await pool.fetchrow(
        """
        INSERT INTO codios.api_keys (org_id, agent_id, name, key_hash)
        VALUES ($1, $2, $3, $4)
        RETURNING id
        """,
        org_id, body.agent_id, body.name, key_hash,
    )

    return {
        "ok": True,
        "id": row["id"],
        "key": raw,
        "warning": "Store this key securely — it will not be shown again.",
    }


@router.delete("/{key_id}", status_code=204)
async def revoke_key(key_id: str, request: Request):
    org_id = await get_org_id(request)
    pool = await get_pool()
    result = await pool.execute(
        "UPDATE codios.api_keys SET revoked=true WHERE id=$1 AND org_id=$2",
        key_id, org_id,
    )
    if result == "UPDATE 0":
        raise HTTPException(status_code=404, detail="Key not found")


# ── BYOK (Bring Your Own Key) ─────────────────────────────────────────────────

@router.get("/byok/status")
async def byok_status(request: Request):
    """Return BYOK encryption status for the org. Requires authentication."""
    await get_org_id(request)
    from services.encryption import is_enabled, current_key_id
    enabled = is_enabled()
    return {
        "enabled": enabled,
        "key_id": current_key_id() if enabled else None,
        "algorithm": "AES-256-GCM" if enabled else None,
        "fields_protected": ["webhook_endpoints.secret", "sso_configs.client_secret"] if enabled else [],
    }


class RotateBody(BaseModel):
    old_key: str   # base64 AES-256 key currently in use
    new_key: str   # base64 AES-256 key to rotate to


@router.post("/byok/rotate")
async def byok_rotate(body: RotateBody, request: Request):
    """
    Re-encrypt all BYOK-protected fields from old_key to new_key.
    After rotation, set BYOK_KEY=<new_key> in your environment and restart.
    Requires owner role.
    """
    from auth import get_org_id_and_role
    org_id, role = await get_org_id_and_role(request)
    from auth import ROLE_LEVEL
    if ROLE_LEVEL.get(role, 99) > ROLE_LEVEL["owner"]:
        raise HTTPException(403, "Key rotation requires owner role")

    from services.encryption import reencrypt_all
    counts = await reencrypt_all(body.old_key, body.new_key)
    return {
        "ok": True,
        "rotated": counts,
        "next_step": "Set BYOK_KEY=<new_key> in your environment and restart the service.",
    }


@router.post("/bootstrap", status_code=201)
async def bootstrap_key(request: Request):
    """
    One-time VPC bootstrap: creates the first org and API key.
    Called automatically by setup-vpc.sh via x-vpc-bootstrap header.
    Blocked once any API key exists, so it cannot be replayed.
    """
    from config import get_settings
    settings = get_settings()

    if not settings.vpc_mode:
        raise HTTPException(status_code=404)

    provided = request.headers.get("x-vpc-bootstrap", "")
    if not provided or provided != settings.gateway_secret:
        raise HTTPException(status_code=401, detail="Invalid bootstrap secret")

    pool = await get_pool()

    existing = await pool.fetchval("SELECT COUNT(*) FROM codios.api_keys")
    if existing > 0:
        raise HTTPException(
            status_code=409,
            detail="Bootstrap already complete. Use your existing API key.",
        )

    org_id = str(uuid.uuid4())
    await pool.execute(
        "INSERT INTO codios.organizations (id, plan) VALUES ($1, 'enterprise') ON CONFLICT DO NOTHING",
        org_id,
    )
    await pool.execute(
        """
        INSERT INTO codios.org_members (org_id, user_id, email, role, status, joined_at)
        VALUES ($1, $1, 'admin@localhost', 'owner', 'active', NOW())
        ON CONFLICT DO NOTHING
        """,
        org_id,
    )

    raw = _PREFIX + secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw.encode()).hexdigest()
    await pool.execute(
        "INSERT INTO codios.api_keys (org_id, name, key_hash) VALUES ($1, 'default', $2)",
        org_id, key_hash,
    )

    return {
        "ok": True,
        "key": raw,
        "org_id": org_id,
        "warning": "Store this key securely — it will not be shown again.",
    }


@router.get("/byok/generate")
async def byok_generate(request: Request):
    """Generate a fresh 32-byte AES-256 key for use as BYOK_KEY."""
    await get_org_id(request)
    from services.encryption import generate_key
    key = generate_key()
    return {
        "key": key,
        "warning": "Store this key securely. Set BYOK_KEY=<key> in your environment.",
        "note": "This key is not stored by Codios. If lost, encrypted data cannot be recovered.",
    }
