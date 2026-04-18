"""
Contract Engine — issue, list, get, revoke, and verify signed capability contracts.

A contract is an Ed25519-signed JSON object that defines exactly what Agent A
is allowed to do when calling Agent B. The signature is produced by the Codios
platform key (CODIOS_PRIVATE_KEY env var), making Codios the trusted authority.

Verification is fully offline: any agent holding CODIOS_PUBLIC_KEY can verify
a contract locally without calling back to this API.
"""
from __future__ import annotations

import json
import os
import secrets
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
from typing import Any
from db import get_pool
from auth import get_org_id
from config import get_settings
from services.crypto import sign_contract, verify_signature, canonicalize

router = APIRouter(prefix="/contracts")


class ContractIssueRequest(BaseModel):
    issuer_agent_id: str
    target_agent_id: str
    allowed_actions: list[str]
    forbidden_actions: list[str] = []
    resource_limits: dict[str, Any] = {}
    ttl_seconds: int = 3600  # default 1 hour


class ContractVerifyRequest(BaseModel):
    contract: dict[str, Any]
    requested_action: str | None = None


@router.get("")
async def list_contracts(request: Request, status: str | None = None):
    org_id = await get_org_id(request)
    pool = await get_pool()

    query = """
        SELECT c.id, c.issuer_agent_id, c.target_agent_id, c.allowed_actions,
               c.forbidden_actions, c.resource_limits, c.status,
               c.issued_at, c.expires_at, c.revoked_at, c.revoke_reason,
               ia.name AS issuer_name, ta.name AS target_name
        FROM codios.contracts c
        JOIN codios.agents ia ON ia.id = c.issuer_agent_id
        JOIN codios.agents ta ON ta.id = c.target_agent_id
        WHERE c.org_id = $1
    """
    args: list = [org_id]

    if status:
        query += " AND c.status = $2"
        args.append(status)

    query += " ORDER BY c.issued_at DESC LIMIT 100"

    rows = await pool.fetch(query, *args)
    return [_serialize(dict(r)) for r in rows]


@router.post("", status_code=201)
async def issue_contract(body: ContractIssueRequest, request: Request):
    org_id = await get_org_id(request)
    settings = get_settings()
    pool = await get_pool()

    if not settings.codios_private_key:
        raise HTTPException(
            status_code=503,
            detail="CODIOS_PRIVATE_KEY not configured. Run: python -c \"from services.crypto import generate_keypair; import json; print(json.dumps(generate_keypair()))\" and set the env vars.",
        )

    # Validate both agents belong to this org
    issuer = await pool.fetchrow(
        "SELECT id, did FROM codios.agents WHERE id=$1 AND org_id=$2 AND status='active'",
        body.issuer_agent_id, org_id,
    )
    if not issuer:
        raise HTTPException(status_code=404, detail="Issuer agent not found or inactive")

    target = await pool.fetchrow(
        "SELECT id, did FROM codios.agents WHERE id=$1 AND org_id=$2 AND status='active'",
        body.target_agent_id, org_id,
    )
    if not target:
        raise HTTPException(status_code=404, detail="Target agent not found or inactive")

    # Build contract body (all fields except signature, for signing)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=body.ttl_seconds)
    nonce = secrets.token_hex(32)

    contract_id = "ctr_" + secrets.token_hex(10)

    contract_body = {
        "contract_id": contract_id,
        "version": "1.0",
        "issued_at": now.isoformat(),
        "expires_at": expires.isoformat(),
        "issuer": {"agent_id": str(issuer["id"]), "did": str(issuer["did"])},
        "target": {"agent_id": str(target["id"]), "did": str(target["did"])},
        "allowed_actions": body.allowed_actions,
        "forbidden_actions": body.forbidden_actions,
        "resource_limits": body.resource_limits,
        "nonce": nonce,
    }

    signature = sign_contract(contract_body, settings.codios_private_key)
    signed_contract = {**contract_body, "signature": signature}

    # Persist
    await pool.execute(
        """
        INSERT INTO codios.contracts
          (id, org_id, issuer_agent_id, target_agent_id, allowed_actions,
           forbidden_actions, resource_limits, nonce, signature, payload,
           issued_at, expires_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
        """,
        contract_id,
        org_id,
        body.issuer_agent_id,
        body.target_agent_id,
        body.allowed_actions,
        body.forbidden_actions,
        json.dumps(body.resource_limits),
        nonce,
        signature,
        json.dumps(signed_contract),
        now,
        expires,
    )

    return {"ok": True, "contract_id": contract_id, "contract": signed_contract}


@router.get("/{contract_id}")
async def get_contract(contract_id: str, request: Request):
    org_id = await get_org_id(request)
    pool = await get_pool()
    row = await pool.fetchrow(
        """
        SELECT c.*, ia.name AS issuer_name, ta.name AS target_name
        FROM codios.contracts c
        JOIN codios.agents ia ON ia.id = c.issuer_agent_id
        JOIN codios.agents ta ON ta.id = c.target_agent_id
        WHERE c.id = $1 AND c.org_id = $2
        """,
        contract_id, org_id,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Contract not found")
    return _serialize(dict(row))


@router.post("/{contract_id}/revoke")
async def revoke_contract(contract_id: str, request: Request, reason: str = ""):
    org_id = await get_org_id(request)
    pool = await get_pool()
    result = await pool.execute(
        """
        UPDATE codios.contracts
        SET status='revoked', revoked_at=NOW(), revoke_reason=$3
        WHERE id=$1 AND org_id=$2 AND status='active'
        """,
        contract_id, org_id, reason,
    )
    if result == "UPDATE 0":
        raise HTTPException(status_code=404, detail="Contract not found or already revoked/expired")
    return {"ok": True}


@router.post("/verify")
async def verify_contract_endpoint(body: ContractVerifyRequest, request: Request):
    """
    Verify a signed contract offline.
    Returns verdict: valid | expired | invalid_signature | action_not_permitted | action_forbidden | revoked
    """
    org_id = await get_org_id(request)
    settings = get_settings()

    if not settings.codios_public_key:
        raise HTTPException(status_code=503, detail="CODIOS_PUBLIC_KEY not configured")

    contract = body.contract
    signature = contract.get("signature", "")
    contract_body = {k: v for k, v in contract.items() if k != "signature"}

    # 1. Expiry
    try:
        expires = datetime.fromisoformat(contract.get("expires_at", ""))
        if expires < datetime.now(timezone.utc):
            return {"valid": False, "reason": "contract_expired"}
    except ValueError:
        return {"valid": False, "reason": "invalid_contract"}

    # 2. Signature
    if not verify_signature(contract_body, signature, settings.codios_public_key):
        return {"valid": False, "reason": "invalid_signature"}

    # 3. Action scope
    if body.requested_action:
        if body.requested_action in contract.get("forbidden_actions", []):
            return {"valid": False, "reason": "action_forbidden"}
        allowed = contract.get("allowed_actions", [])
        if allowed and body.requested_action not in allowed:
            return {"valid": False, "reason": "action_not_permitted"}

    # 4. DB revocation check (optional — offline verification skips this)
    pool = await get_pool()
    row = await pool.fetchrow(
        "SELECT status FROM codios.contracts WHERE id=$1 AND org_id=$2",
        contract.get("contract_id"), org_id,
    )
    if row and row["status"] != "active":
        return {"valid": False, "reason": "contract_revoked"}

    return {"valid": True}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _serialize(d: dict) -> dict:
    for field in ("resource_limits", "payload"):
        val = d.get(field)
        if isinstance(val, str):
            try:
                d[field] = json.loads(val)
            except Exception:
                pass
    return d
