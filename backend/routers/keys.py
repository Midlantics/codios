"""
API Key management for Codios.

Keys use prefix 'codios_sk_' and are SHA-256 hashed before storage.
The raw key is returned only once on creation.
"""
from __future__ import annotations

import hashlib
import secrets
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
