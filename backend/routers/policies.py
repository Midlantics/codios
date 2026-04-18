"""
Custom OPA policy management.

Orgs on the Pro plan can write custom Rego policies that extend or override
the base scope rules. Policies are stored as Rego source text. Testing
requires OPA_URL to be configured; activation stores the policy and flags it
for use by the enforcement gateway.

Only one policy can be active at a time per org.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
from typing import Optional
import httpx

from db import get_pool
from auth import get_org_id
from routers.billing import require_feature

router = APIRouter(prefix="/policies")

OPA_URL = os.getenv("OPA_URL", "")

_BASE_POLICY_HINT = """\
# Base Codios scope policy — loaded by default on all plans.
# Write your custom rules below to extend or override it.
#
# The input object available to your policy:
#   input.contract       — the full signed contract object
#   input.action         — the requested action string
#   input.calls_used     — number of times this contract has been used
#   input.caller_did     — DID of the calling agent (if provided)
#
# Return: allow (bool) and deny_reason (string)

package codios.custom

import future.keywords.if
import future.keywords.in

default allow = false
default deny_reason = ""

allow if {
    # Your rules here
    input.action in input.contract.allowed_actions
}
"""


# ── Models ────────────────────────────────────────────────────────────────────

class PolicyCreate(BaseModel):
    name: str
    description: str = ""
    rego_source: str


class PolicyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    rego_source: Optional[str] = None


class PolicyTestRequest(BaseModel):
    rego_source: str
    input: dict


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("")
async def list_policies(request: Request):
    org_id = await get_org_id(request)
    await require_feature(org_id, "custom_policies")
    pool = await get_pool()
    rows = await pool.fetch(
        """
        SELECT id, name, description, active, last_tested_at, last_test_result, created_at, updated_at
        FROM codios.custom_policies
        WHERE org_id = $1
        ORDER BY updated_at DESC
        """,
        org_id,
    )
    return [_serialize(dict(r)) for r in rows]


@router.get("/template")
async def get_template(request: Request):
    """Return the starter Rego template for new policies."""
    await get_org_id(request)
    return {"template": _BASE_POLICY_HINT}


@router.post("", status_code=201)
async def create_policy(body: PolicyCreate, request: Request):
    org_id = await get_org_id(request)
    await require_feature(org_id, "custom_policies")

    if not body.name.strip():
        raise HTTPException(status_code=400, detail="Policy name is required")
    if len(body.rego_source.strip()) < 20:
        raise HTTPException(status_code=400, detail="Rego source is too short")

    pool = await get_pool()
    row = await pool.fetchrow(
        """
        INSERT INTO codios.custom_policies (org_id, name, description, rego_source)
        VALUES ($1, $2, $3, $4)
        RETURNING id, name, description, active, created_at, updated_at
        """,
        org_id, body.name.strip(), body.description.strip(), body.rego_source,
    )
    return _serialize(dict(row))


@router.get("/{policy_id}")
async def get_policy(policy_id: str, request: Request):
    org_id = await get_org_id(request)
    await require_feature(org_id, "custom_policies")
    pool = await get_pool()
    row = await pool.fetchrow(
        "SELECT * FROM codios.custom_policies WHERE id=$1 AND org_id=$2",
        policy_id, org_id,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Policy not found")
    return _serialize(dict(row))


@router.patch("/{policy_id}")
async def update_policy(policy_id: str, body: PolicyUpdate, request: Request):
    org_id = await get_org_id(request)
    await require_feature(org_id, "custom_policies")
    pool = await get_pool()

    updates: list[str] = ["updated_at = NOW()"]
    args: list = []
    idx = 1

    if body.name is not None:
        updates.append(f"name = ${idx}")
        args.append(body.name.strip())
        idx += 1
    if body.description is not None:
        updates.append(f"description = ${idx}")
        args.append(body.description.strip())
        idx += 1
    if body.rego_source is not None:
        updates.append(f"rego_source = ${idx}")
        args.append(body.rego_source)
        idx += 1
        # Clear last test result when source changes
        updates.append("last_tested_at = NULL")
        updates.append("last_test_result = NULL")

    if len(updates) == 1:
        raise HTTPException(status_code=400, detail="No fields to update")

    args += [policy_id, org_id]
    row = await pool.fetchrow(
        f"UPDATE codios.custom_policies SET {', '.join(updates)} WHERE id=${idx} AND org_id=${idx+1} RETURNING *",
        *args,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Policy not found")
    return _serialize(dict(row))


@router.delete("/{policy_id}", status_code=204)
async def delete_policy(policy_id: str, request: Request):
    org_id = await get_org_id(request)
    await require_feature(org_id, "custom_policies")
    pool = await get_pool()
    result = await pool.execute(
        "DELETE FROM codios.custom_policies WHERE id=$1 AND org_id=$2",
        policy_id, org_id,
    )
    if result == "DELETE 0":
        raise HTTPException(status_code=404, detail="Policy not found")


@router.post("/{policy_id}/activate")
async def activate_policy(policy_id: str, request: Request):
    """Mark this policy as active (deactivates all others for this org)."""
    org_id = await get_org_id(request)
    await require_feature(org_id, "custom_policies")
    pool = await get_pool()

    # Verify policy exists and belongs to org
    row = await pool.fetchrow(
        "SELECT id, last_test_result FROM codios.custom_policies WHERE id=$1 AND org_id=$2",
        policy_id, org_id,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Policy not found")

    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                "UPDATE codios.custom_policies SET active=FALSE WHERE org_id=$1",
                org_id,
            )
            await conn.execute(
                "UPDATE codios.custom_policies SET active=TRUE, updated_at=NOW() WHERE id=$1",
                policy_id,
            )

    return {"ok": True, "active_policy_id": policy_id}


@router.post("/{policy_id}/deactivate")
async def deactivate_policy(policy_id: str, request: Request):
    """Deactivate — revert to base Python policy evaluation."""
    org_id = await get_org_id(request)
    await require_feature(org_id, "custom_policies")
    pool = await get_pool()
    result = await pool.execute(
        "UPDATE codios.custom_policies SET active=FALSE, updated_at=NOW() WHERE id=$1 AND org_id=$2",
        policy_id, org_id,
    )
    if result == "UPDATE 0":
        raise HTTPException(status_code=404, detail="Policy not found")
    return {"ok": True}


@router.post("/test")
async def test_policy(body: PolicyTestRequest, request: Request):
    """
    Evaluate custom Rego against sample input via OPA REST API.
    Requires OPA_URL env var to be set. Returns { allow, deny_reason } or an error.
    """
    org_id = await get_org_id(request)
    await require_feature(org_id, "custom_policies")

    if not OPA_URL:
        return {
            "available": False,
            "message": "Set OPA_URL in Railway to enable live policy testing. Without it, policies are stored and activated but not testable here.",
        }

    # Submit policy + input to OPA REST API
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            # Create a temporary policy in OPA
            policy_id_opa = f"codios_test_{org_id[:8]}"
            put_res = await client.put(
                f"{OPA_URL}/v1/policies/{policy_id_opa}",
                content=body.rego_source,
                headers={"Content-Type": "text/plain"},
            )
            if not put_res.is_success:
                err = put_res.json()
                return {
                    "available": True,
                    "allow": False,
                    "error": err.get("message", "Policy syntax error"),
                    "code": err.get("code", "unknown"),
                }

            # Evaluate
            eval_res = await client.post(
                f"{OPA_URL}/v1/data/codios/custom",
                json={"input": body.input},
            )
            result = eval_res.json().get("result", {})

            # Clean up temp policy
            await client.delete(f"{OPA_URL}/v1/policies/{policy_id_opa}")

            return {
                "available": True,
                "allow": result.get("allow", False),
                "deny_reason": result.get("deny_reason"),
                "result": result,
            }

    except httpx.TimeoutException:
        return {"available": True, "error": "OPA request timed out (>5s)"}
    except Exception as e:
        return {"available": True, "error": str(e)}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _serialize(d: dict) -> dict:
    for k in ("last_test_result",):
        val = d.get(k)
        if isinstance(val, str):
            try:
                d[k] = json.loads(val)
            except Exception:
                pass
    return d
