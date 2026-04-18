"""
Webhook dispatcher — fire-and-forget delivery with HMAC-SHA256 signing.

Events:
  contract.created   contract.revoked   contract.expired
  audit.denied
  agent.created      agent.status_changed

Customers verify authenticity with:
  HMAC-SHA256(f"{timestamp}.{raw_body}", secret) == X-Codios-Signature (after "sha256=")
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_TIMEOUT_SECONDS = 10
_MAX_RESPONSE_BODY = 1024  # bytes saved in delivery log


def dispatch(org_id: str, event_type: str, payload: dict[str, Any]) -> None:
    """Enqueue a webhook dispatch. Never blocks the caller."""
    asyncio.create_task(_dispatch(org_id, event_type, payload))


async def _dispatch(org_id: str, event_type: str, payload: dict[str, Any]) -> None:
    try:
        from db import get_pool
        pool = await get_pool()

        # Load enabled endpoints subscribed to this event
        rows = await pool.fetch(
            """
            SELECT id, url, secret, events FROM codios.webhook_endpoints
            WHERE org_id = $1 AND enabled = TRUE
            """,
            org_id,
        )
    except Exception:
        logger.exception("[webhooks] Failed to load endpoints for org=%s", org_id)
        return

    if not rows:
        return

    body = json.dumps({"event": event_type, "org_id": org_id, "data": payload}, separators=(",", ":"))
    ts = str(int(time.time()))

    tasks = [
        _deliver(row["id"], row["url"], row["secret"], body, ts, event_type, org_id)
        for row in rows
        if not row["events"] or event_type in row["events"]
    ]
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


async def _deliver(
    endpoint_id: str,
    url: str,
    secret: str,
    body: str,
    ts: str,
    event_type: str,
    org_id: str,
) -> None:
    sig = _sign(ts, body, secret)
    headers = {
        "Content-Type": "application/json",
        "X-Codios-Event": event_type,
        "X-Codios-Timestamp": ts,
        "X-Codios-Signature": f"sha256={sig}",
        "User-Agent": "Codios-Webhook/1.0",
    }

    t0 = time.monotonic()
    status_code: int | None = None
    error: str | None = None
    success = False
    response_snippet = ""

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
            resp = await client.post(url, content=body.encode(), headers=headers)
        status_code = resp.status_code
        success = 200 <= status_code < 300
        response_snippet = resp.text[:_MAX_RESPONSE_BODY]
    except Exception as exc:
        error = str(exc)

    duration_ms = int((time.monotonic() - t0) * 1000)

    if not success:
        logger.warning(
            "[webhooks] Delivery failed endpoint=%s event=%s status=%s error=%s",
            endpoint_id, event_type, status_code, error,
        )

    # Log delivery attempt (best-effort)
    try:
        from db import get_pool
        pool = await get_pool()
        await pool.execute(
            """
            INSERT INTO codios.webhook_deliveries
              (endpoint_id, org_id, event_type, payload, status_code, success, duration_ms, error)
            VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8)
            """,
            endpoint_id, org_id, event_type,
            json.dumps({"event": event_type, "response": response_snippet}),
            status_code, success, duration_ms, error,
        )
    except Exception:
        logger.exception("[webhooks] Failed to log delivery for endpoint=%s", endpoint_id)


def _sign(timestamp: str, body: str, secret: str) -> str:
    msg = f"{timestamp}.{body}".encode()
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()
