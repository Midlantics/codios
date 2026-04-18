"""
Agent Registry — register, list, get, and delete AI agents.

Each agent has an Ed25519 keypair. The private key never leaves the agent's
environment. Codios stores only the public key and the derived DID:key.

The caller (agent owner) provides the public key at registration time.
If they don't have one, they can call POST /agents/keygen to generate a pair
(useful for development; in production, agents generate their own keys).
"""
from __future__ import annotations

import json
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
from typing import Any
from db import get_pool
from auth import get_org_id
from services.crypto import generate_keypair, public_key_to_did

router = APIRouter(prefix="/agents")


class AgentCreate(BaseModel):
    name: str
    description: str = ""
    public_key: str | None = None  # base64 Ed25519 public key; omit to auto-generate
    capabilities: list[str] = []
    agent_card: dict[str, Any] = {}


class AgentUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    capabilities: list[str] | None = None
    agent_card: dict[str, Any] | None = None
    status: str | None = None


@router.get("/keygen")
async def keygen():
    """Generate a new Ed25519 keypair. Private key is returned ONCE — store it securely."""
    return generate_keypair()


@router.get("")
async def list_agents(request: Request):
    org_id = await get_org_id(request)
    pool = await get_pool()
    rows = await pool.fetch(
        """
        SELECT id, name, description, did, public_key, capabilities, agent_card, status, created_at, updated_at
        FROM codios.agents
        WHERE org_id = $1
        ORDER BY created_at DESC
        """,
        org_id,
    )
    return [_serialize(dict(r)) for r in rows]


@router.post("", status_code=201)
async def create_agent(body: AgentCreate, request: Request):
    org_id = await get_org_id(request)
    pool = await get_pool()

    if body.public_key:
        # Caller provided their own key
        try:
            did = public_key_to_did(body.public_key)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid public_key — must be base64-encoded Ed25519 raw public key")
        public_key = body.public_key
        returned_private = None
    else:
        # Auto-generate for convenience
        kp = generate_keypair()
        public_key = kp["public_key"]
        did = kp["did"]
        returned_private = kp["private_key"]

    # Seat limit check (VPC license)
    from config import get_settings
    if get_settings().vpc_mode:
        from services.license import get_license
        lic = get_license()
        if lic.seats != -1:
            count = await pool.fetchval(
                "SELECT COUNT(*) FROM codios.agents WHERE org_id=$1 AND status='active'", org_id
            )
            if count >= lic.seats:
                raise HTTPException(
                    status_code=402,
                    detail=f"License seat limit reached ({lic.seats} agents). Contact sales@midlantics.com to upgrade."
                )

    # Check DID uniqueness
    existing = await pool.fetchrow("SELECT id FROM codios.agents WHERE did = $1", did)
    if existing:
        raise HTTPException(status_code=409, detail="An agent with this public key (DID) already exists")

    row = await pool.fetchrow(
        """
        INSERT INTO codios.agents (org_id, name, description, did, public_key, capabilities, agent_card)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id
        """,
        org_id,
        body.name,
        body.description,
        did,
        public_key,
        body.capabilities,
        json.dumps(body.agent_card),
    )

    result: dict = {"ok": True, "id": row["id"], "did": did}
    if returned_private:
        result["private_key"] = returned_private
        result["warning"] = "Store this private_key securely — it will not be shown again."
    from services.webhook_dispatcher import dispatch
    dispatch(org_id, "agent.created", {"agent_id": row["id"], "did": did, "name": body.name})
    return result


@router.get("/{agent_id}")
async def get_agent(agent_id: str, request: Request):
    org_id = await get_org_id(request)
    pool = await get_pool()
    row = await pool.fetchrow(
        "SELECT * FROM codios.agents WHERE id = $1 AND org_id = $2",
        agent_id, org_id,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Agent not found")
    return _serialize(dict(row))


@router.patch("/{agent_id}")
async def update_agent(agent_id: str, body: AgentUpdate, request: Request):
    org_id = await get_org_id(request)
    pool = await get_pool()

    row = await pool.fetchrow(
        "SELECT * FROM codios.agents WHERE id = $1 AND org_id = $2",
        agent_id, org_id,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Agent not found")

    current = dict(row)
    name = body.name if body.name is not None else current["name"]
    description = body.description if body.description is not None else current["description"]
    capabilities = body.capabilities if body.capabilities is not None else current["capabilities"]
    agent_card = json.dumps(body.agent_card) if body.agent_card is not None else json.dumps(current["agent_card"] if isinstance(current["agent_card"], dict) else json.loads(current["agent_card"] or "{}"))
    status = body.status if body.status is not None else current["status"]

    if status not in ("active", "suspended", "revoked"):
        raise HTTPException(status_code=400, detail="status must be active | suspended | revoked")

    await pool.execute(
        """
        UPDATE codios.agents
        SET name=$3, description=$4, capabilities=$5, agent_card=$6, status=$7, updated_at=NOW()
        WHERE id=$1 AND org_id=$2
        """,
        agent_id, org_id, name, description, capabilities, agent_card, status,
    )
    if status != current["status"]:
        from services.webhook_dispatcher import dispatch
        dispatch(org_id, "agent.status_changed", {"agent_id": agent_id, "status": status, "previous_status": current["status"]})
    return {"ok": True}


@router.delete("/{agent_id}", status_code=204)
async def delete_agent(agent_id: str, request: Request):
    org_id = await get_org_id(request)
    pool = await get_pool()
    result = await pool.execute(
        "DELETE FROM codios.agents WHERE id=$1 AND org_id=$2",
        agent_id, org_id,
    )
    if result == "DELETE 0":
        raise HTTPException(status_code=404, detail="Agent not found")


# ── Heartbeat (agent → Codios) ────────────────────────────────────────────────

@router.post("/{agent_id}/heartbeat", status_code=200)
async def agent_heartbeat(agent_id: str, request: Request):
    """
    Lightweight liveness ping from a running agent. Updates last_seen_at and last_seen_ip.

    Agents should call this on startup and every 30–60 seconds while running.
    The caller must present a valid Codios API key or JWT (org ownership check).

    Returns: {"ok": true, "last_seen_at": "<ISO timestamp>"}
    """
    org_id = await get_org_id(request)
    pool = await get_pool()

    ip = (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or request.client.host if request.client else None
    )

    row = await pool.fetchrow(
        """
        UPDATE codios.agents
        SET last_seen_at = NOW(), last_seen_ip = $3
        WHERE id = $1 AND org_id = $2
        RETURNING last_seen_at
        """,
        agent_id, org_id, ip,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Agent not found")
    return {"ok": True, "last_seen_at": row["last_seen_at"].isoformat()}


# ── Agent Card (public, no auth) ──────────────────────────────────────────────

@router.get("/card/{did:path}")
async def get_agent_card(did: str):
    """Public endpoint: serve A2A Agent Card by DID. No auth required."""
    pool = await get_pool()
    row = await pool.fetchrow(
        "SELECT name, description, did, capabilities, agent_card FROM codios.agents WHERE did = $1 AND status = 'active'",
        did,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Agent not found or inactive")

    card = row["agent_card"]
    if isinstance(card, str):
        card = json.loads(card or "{}")

    return {
        "name": row["name"],
        "description": row["description"],
        "did": row["did"],
        "capabilities": row["capabilities"],
        **card,
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _serialize(d: dict) -> dict:
    for field in ("agent_card",):
        val = d.get(field)
        if isinstance(val, str):
            d[field] = json.loads(val or "{}")
    return d
