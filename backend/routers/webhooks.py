"""
Webhooks — register and manage webhook endpoints.

Events emitted:
  contract.created   contract.revoked   contract.expired
  audit.denied
  agent.created      agent.status_changed

Signature verification (in your receiver):
  import hashlib, hmac
  expected = "sha256=" + hmac.new(secret.encode(), f"{ts}.{raw_body}".encode(), hashlib.sha256).hexdigest()
  assert hmac.compare_digest(expected, request.headers["X-Codios-Signature"])
"""
from __future__ import annotations

import secrets
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel, HttpUrl
from auth import get_org_id

router = APIRouter(prefix="/webhooks")

ALL_EVENTS = {
    "contract.created",
    "contract.revoked",
    "contract.expired",
    "audit.denied",
    "agent.created",
    "agent.status_changed",
}


class EndpointCreate(BaseModel):
    url: HttpUrl
    description: str = ""
    events: list[str] = []   # empty = subscribe to all events


class EndpointUpdate(BaseModel):
    url: HttpUrl | None = None
    description: str | None = None
    events: list[str] | None = None
    enabled: bool | None = None


@router.get("")
async def list_endpoints(request: Request):
    org_id = await get_org_id(request)
    from db import get_pool
    pool = await get_pool()
    rows = await pool.fetch(
        """
        SELECT id, url, description, events, enabled, created_at, updated_at
        FROM codios.webhook_endpoints
        WHERE org_id = $1
        ORDER BY created_at DESC
        """,
        org_id,
    )
    return [dict(r) for r in rows]


@router.post("", status_code=201)
async def create_endpoint(body: EndpointCreate, request: Request):
    org_id = await get_org_id(request)

    invalid = set(body.events) - ALL_EVENTS
    if invalid:
        raise HTTPException(400, f"Unknown event types: {sorted(invalid)}. Valid: {sorted(ALL_EVENTS)}")

    from db import get_pool
    from services.encryption import encrypt, current_key_id
    pool = await get_pool()
    signing_secret = secrets.token_hex(32)
    stored_secret = encrypt(signing_secret)

    row = await pool.fetchrow(
        """
        INSERT INTO codios.webhook_endpoints (org_id, url, secret, enc_key_id, description, events)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id, created_at
        """,
        org_id, str(body.url), stored_secret, current_key_id(), body.description, body.events,
    )
    return {
        "ok": True,
        "id": row["id"],
        "secret": signing_secret,  # raw — returned once, never stored plaintext if BYOK enabled
        "warning": "Store this secret securely — it will not be shown again. Use it to verify webhook signatures.",
    }


@router.get("/{endpoint_id}")
async def get_endpoint(endpoint_id: str, request: Request):
    org_id = await get_org_id(request)
    from db import get_pool
    pool = await get_pool()
    row = await pool.fetchrow(
        "SELECT id, url, description, events, enabled, created_at, updated_at FROM codios.webhook_endpoints WHERE id=$1 AND org_id=$2",
        endpoint_id, org_id,
    )
    if not row:
        raise HTTPException(404, "Endpoint not found")
    return dict(row)


@router.patch("/{endpoint_id}")
async def update_endpoint(endpoint_id: str, body: EndpointUpdate, request: Request):
    org_id = await get_org_id(request)
    from db import get_pool
    pool = await get_pool()

    row = await pool.fetchrow(
        "SELECT id, url, description, events, enabled FROM codios.webhook_endpoints WHERE id=$1 AND org_id=$2",
        endpoint_id, org_id,
    )
    if not row:
        raise HTTPException(404, "Endpoint not found")

    if body.events is not None:
        invalid = set(body.events) - ALL_EVENTS
        if invalid:
            raise HTTPException(400, f"Unknown event types: {sorted(invalid)}")

    url         = str(body.url)      if body.url         is not None else row["url"]
    description = body.description   if body.description  is not None else row["description"]
    events      = body.events        if body.events       is not None else row["events"]
    enabled     = body.enabled       if body.enabled      is not None else row["enabled"]

    await pool.execute(
        """
        UPDATE codios.webhook_endpoints
        SET url=$3, description=$4, events=$5, enabled=$6, updated_at=NOW()
        WHERE id=$1 AND org_id=$2
        """,
        endpoint_id, org_id, url, description, events, enabled,
    )
    return {"ok": True}


@router.delete("/{endpoint_id}", status_code=204)
async def delete_endpoint(endpoint_id: str, request: Request):
    org_id = await get_org_id(request)
    from db import get_pool
    pool = await get_pool()
    result = await pool.execute(
        "DELETE FROM codios.webhook_endpoints WHERE id=$1 AND org_id=$2",
        endpoint_id, org_id,
    )
    if result == "DELETE 0":
        raise HTTPException(404, "Endpoint not found")


@router.get("/{endpoint_id}/deliveries")
async def list_deliveries(endpoint_id: str, request: Request):
    """Recent delivery attempts for an endpoint (last 50)."""
    org_id = await get_org_id(request)
    from db import get_pool
    pool = await get_pool()
    # Verify ownership
    ep = await pool.fetchrow(
        "SELECT id FROM codios.webhook_endpoints WHERE id=$1 AND org_id=$2",
        endpoint_id, org_id,
    )
    if not ep:
        raise HTTPException(404, "Endpoint not found")

    rows = await pool.fetch(
        """
        SELECT id, event_type, status_code, success, duration_ms, error, attempted_at
        FROM codios.webhook_deliveries
        WHERE endpoint_id = $1
        ORDER BY attempted_at DESC
        LIMIT 50
        """,
        endpoint_id,
    )
    return [dict(r) for r in rows]


@router.post("/{endpoint_id}/ping", status_code=202)
async def ping_endpoint(endpoint_id: str, request: Request):
    """Send a test ping event to verify endpoint reachability."""
    org_id = await get_org_id(request)
    from db import get_pool
    pool = await get_pool()
    row = await pool.fetchrow(
        "SELECT url, secret FROM codios.webhook_endpoints WHERE id=$1 AND org_id=$2",
        endpoint_id, org_id,
    )
    if not row:
        raise HTTPException(404, "Endpoint not found")

    from services.webhook_dispatcher import _deliver, _sign
    from services.encryption import decrypt
    import time, json
    body = json.dumps({"event": "ping", "org_id": org_id, "data": {}}, separators=(",", ":"))
    ts = str(int(time.time()))
    asyncio.create_task(
        _deliver(endpoint_id, row["url"], decrypt(row["secret"]), body, ts, "ping", org_id)
    )
    return {"ok": True, "message": "Ping dispatched"}


import asyncio
