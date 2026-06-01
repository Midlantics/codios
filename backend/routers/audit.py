"""
Audit Log — append-only record of every contract enforcement decision.

The DB-level triggers (audit_logs_immutable) prevent UPDATE/DELETE at the
Postgres level. The API also enforces append-only: no PUT/DELETE endpoints.
 
Export endpoints produce JSONL or CSV with a SHA-256 integrity hash, and
optionally upload to S3 for immutable archival (ISO 27001 A.12.4).
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from auth import get_org_id
from config import get_settings
from db import get_pool
from routers.billing import require_feature
from services.crypto import hash_payload

router = APIRouter(prefix="/audit")


class AuditEntry(BaseModel):
    contract_id: str | None = None
    issuer_agent_id: str | None = None
    target_agent_id: str | None = None
    action: str
    outcome: str               # allowed | denied | error
    deny_reason: str | None = None
    payload: dict[str, Any] | None = None   # hashed before storage
    ip_address: str | None = None
    duration_ms: int | None = None
    metadata: dict[str, Any] = {}


@router.get("")
async def list_audit(
    request: Request,
    outcome: str | None = None,
    agent_id: str | None = None,
    limit: int = 100,
):
    org_id = await get_org_id(request)
    pool = await get_pool()

    conditions = ["a.org_id = $1"]
    args: list = [org_id]
    idx = 2

    if outcome:
        conditions.append(f"a.outcome = ${idx}")
        args.append(outcome)
        idx += 1
    if agent_id:
        conditions.append(f"(a.issuer_agent_id = ${idx} OR a.target_agent_id = ${idx})")
        args.append(agent_id)
        idx += 1

    limit = min(max(1, limit), 500)

    where = " AND ".join(conditions)
    rows = await pool.fetch(
        f"""
        SELECT a.id, a.contract_id, a.issuer_agent_id, a.target_agent_id,
               a.action, a.outcome, a.deny_reason, a.payload_hash,
               a.ip_address, a.duration_ms, a.metadata, a.created_at,
               ia.name AS issuer_name, ta.name AS target_name
        FROM codios.audit_logs a
        LEFT JOIN codios.agents ia ON ia.id = a.issuer_agent_id
        LEFT JOIN codios.agents ta ON ta.id = a.target_agent_id
        WHERE {where}
        ORDER BY a.created_at DESC
        LIMIT {limit}
        """,
        *args,
    )
    return [_serialize(dict(r)) for r in rows]


@router.get("/stats")
async def audit_stats(request: Request):
    """Aggregated counts for dashboard metrics."""
    org_id = await get_org_id(request)
    pool = await get_pool()

    row = await pool.fetchrow(
        """
        SELECT
          COUNT(*) FILTER (WHERE outcome='allowed')  AS allowed,
          COUNT(*) FILTER (WHERE outcome='denied')   AS denied,
          COUNT(*) FILTER (WHERE outcome='error')    AS errors,
          COUNT(*) AS total,
          COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours') AS last_24h
        FROM codios.audit_logs
        WHERE org_id = $1
        """,
        org_id,
    )
    return dict(row) if row else {"allowed": 0, "denied": 0, "errors": 0, "total": 0, "last_24h": 0}


@router.post("", status_code=201)
async def append_audit(body: AuditEntry, request: Request):
    org_id = await get_org_id(request)

    if body.outcome not in ("allowed", "denied", "error"):
        raise HTTPException(status_code=400, detail="outcome must be allowed | denied | error")

    pool = await get_pool()

    payload_hash = None
    if body.payload:
        payload_hash = hash_payload(json.dumps(body.payload, sort_keys=True))

    row = await pool.fetchrow(
        """
        INSERT INTO codios.audit_logs
          (org_id, contract_id, issuer_agent_id, target_agent_id, action,
           outcome, deny_reason, payload_hash, ip_address, duration_ms, metadata)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
        RETURNING id
        """,
        org_id,
        body.contract_id,
        body.issuer_agent_id,
        body.target_agent_id,
        body.action,
        body.outcome,
        body.deny_reason,
        payload_hash,
        body.ip_address,
        body.duration_ms,
        json.dumps(body.metadata),
    )
    return {"ok": True, "id": row["id"]}


# ── Export ────────────────────────────────────────────────────────────────────

_EXPORT_COLS = [
    "id", "contract_id", "issuer_agent_id", "target_agent_id",
    "action", "outcome", "deny_reason", "payload_hash",
    "ip_address", "duration_ms", "created_at",
]


@router.get("/export")
async def export_audit(
    request: Request,
    from_date: str | None = None,
    to_date:   str | None = None,
    fmt:       str        = "jsonl",
    s3:        bool       = False,
):
    """
    Stream audit log as JSONL or CSV.
    Returns X-Export-Hash (SHA-256) and X-Export-Rows headers.
    If s3=true and S3_AUDIT_BUCKET is configured, uploads to S3 and
    returns a JSON manifest instead of streaming the file.
    """
    org_id = await get_org_id(request)
    await require_feature(org_id, "audit")

    if fmt not in ("jsonl", "csv"):
        raise HTTPException(400, "fmt must be jsonl or csv")

    try:
        from_dt = datetime.fromisoformat(from_date) if from_date else datetime(2000, 1, 1, tzinfo=timezone.utc)
        to_dt   = datetime.fromisoformat(to_date)   if to_date   else datetime.now(timezone.utc)
    except ValueError:
        raise HTTPException(400, "from_date / to_date must be ISO 8601")

    pool = await get_pool()
    rows = await pool.fetch(
        f"""
        SELECT {', '.join(_EXPORT_COLS)}
        FROM codios.audit_logs
        WHERE org_id = $1
          AND created_at >= $2
          AND created_at <= $3
        ORDER BY created_at ASC
        """,
        org_id, from_dt, to_dt,
    )

    content, sha256, row_count = _serialize_export(rows, fmt)

    settings = get_settings()
    if s3 and settings.s3_audit_bucket:
        return await _upload_to_s3(
            org_id, content, sha256, row_count, from_dt, to_dt, fmt, settings
        )

    # Record export manifest
    await pool.execute(
        """
        INSERT INTO codios.audit_exports
          (org_id, from_date, to_date, row_count, sha256_hash, format)
        VALUES ($1,$2,$3,$4,$5,$6)
        """,
        org_id, from_dt, to_dt, row_count, sha256, fmt,
    )

    media = "application/x-ndjson" if fmt == "jsonl" else "text/csv"
    filename = f"codios-audit-{org_id[:8]}-{from_dt.date()}-{to_dt.date()}.{fmt}"
    return StreamingResponse(
        iter([content]),
        media_type=media,
        headers={
            "Content-Disposition":  f'attachment; filename="{filename}"',
            "X-Export-Hash":        sha256,
            "X-Export-Rows":        str(row_count),
            "X-Export-Format":      fmt,
        },
    )


@router.get("/exports")
async def list_exports(request: Request):
    """List previous audit exports (manifest only, not the data)."""
    org_id = await get_org_id(request)
    await require_feature(org_id, "audit")
    pool = await get_pool()
    rows = await pool.fetch(
        """
        SELECT id, from_date, to_date, row_count, sha256_hash, format, s3_url, created_at
        FROM codios.audit_exports
        WHERE org_id = $1
        ORDER BY created_at DESC
        LIMIT 100
        """,
        org_id,
    )
    return [dict(r) for r in rows]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _serialize_export(rows: list, fmt: str) -> tuple[bytes, str, int]:
    if fmt == "jsonl":
        lines = []
        for r in rows:
            d = dict(r)
            d["created_at"] = d["created_at"].isoformat() if d.get("created_at") else None
            lines.append(json.dumps(d))
        content = ("\n".join(lines) + "\n").encode()
    else:
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=_EXPORT_COLS)
        writer.writeheader()
        for r in rows:
            d = dict(r)
            d["created_at"] = d["created_at"].isoformat() if d.get("created_at") else None
            writer.writerow(d)
        content = buf.getvalue().encode()

    sha256    = hashlib.sha256(content).hexdigest()
    row_count = len(rows)
    return content, sha256, row_count


async def _upload_to_s3(
    org_id: str,
    content: bytes,
    sha256: str,
    row_count: int,
    from_dt: datetime,
    to_dt: datetime,
    fmt: str,
    settings,
) -> dict:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError

    key = f"audit/{org_id}/{from_dt.date()}-{to_dt.date()}-{sha256[:8]}.{fmt}"
    try:
        s3 = boto3.client(
            "s3",
            aws_access_key_id     = settings.aws_access_key_id or None,
            aws_secret_access_key = settings.aws_secret_key or None,
            region_name           = settings.aws_region,
        )
        s3.put_object(
            Bucket      = settings.s3_audit_bucket,
            Key         = key,
            Body        = content,
            ContentType = "application/x-ndjson" if fmt == "jsonl" else "text/csv",
            Metadata    = {"sha256": sha256, "org_id": org_id, "row_count": str(row_count)},
        )
        presigned_url = s3.generate_presigned_url(
            "get_object",
            Params  = {"Bucket": settings.s3_audit_bucket, "Key": key},
            ExpiresIn = 3600,
        )
    except (BotoCoreError, ClientError) as e:
        raise HTTPException(502, f"S3 upload failed: {e}")

    pool = await get_pool()
    await pool.execute(
        """
        INSERT INTO codios.audit_exports
          (org_id, from_date, to_date, row_count, sha256_hash, format, s3_key, s3_url)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
        """,
        org_id, from_dt, to_dt, row_count, sha256, fmt, key, presigned_url,
    )

    return {
        "s3_key":      key,
        "presigned_url": presigned_url,
        "sha256":      sha256,
        "row_count":   row_count,
        "expires_in":  3600,
    }


def _serialize(d: dict) -> dict:
    val = d.get("metadata")
    if isinstance(val, str):
        try:
            d["metadata"] = json.loads(val)
        except Exception:
            d["metadata"] = {}
    return d
