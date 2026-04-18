"""
Alert rule CRUD — create, list, update, toggle, delete.

Alert rules define thresholds that trigger email notifications when anomalous
agent behavior is detected. Supported condition types:
  denial_spike        — N+ denials in the last M minutes
  rate_limit_exceeded — contract max_calls limit was hit

The cron job (Vercel, every minute) evaluates rules and fires emails via Resend.
Cooldown prevents repeat alerts within cooldown_minutes of the last fire.
"""
from __future__ import annotations

from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel, field_validator
from typing import Optional
from db import get_pool
from auth import get_org_id
from routers.billing import require_feature

router = APIRouter(prefix="/alert-rules")

_CONDITION_TYPES = {"denial_spike", "rate_limit_exceeded"}
_MAX_EMAILS = 10


class AlertRuleCreate(BaseModel):
    name: str
    condition_type: str = "denial_spike"
    threshold: int = 10
    window_minutes: int = 5
    cooldown_minutes: int = 15
    notify_emails: list[str] = []

    @field_validator("condition_type")
    @classmethod
    def valid_condition(cls, v: str) -> str:
        if v not in _CONDITION_TYPES:
            raise ValueError(f"condition_type must be one of: {', '.join(_CONDITION_TYPES)}")
        return v

    @field_validator("threshold")
    @classmethod
    def positive_threshold(cls, v: int) -> int:
        if v < 1:
            raise ValueError("threshold must be >= 1")
        return v

    @field_validator("window_minutes")
    @classmethod
    def valid_window(cls, v: int) -> int:
        if not (1 <= v <= 1440):
            raise ValueError("window_minutes must be 1–1440")
        return v

    @field_validator("notify_emails")
    @classmethod
    def valid_emails(cls, v: list[str]) -> list[str]:
        if len(v) > _MAX_EMAILS:
            raise ValueError(f"Maximum {_MAX_EMAILS} notification emails per rule")
        return [e.strip().lower() for e in v if e.strip()]


class AlertRuleUpdate(BaseModel):
    name: Optional[str] = None
    threshold: Optional[int] = None
    window_minutes: Optional[int] = None
    cooldown_minutes: Optional[int] = None
    notify_emails: Optional[list[str]] = None
    enabled: Optional[bool] = None


@router.get("")
async def list_rules(request: Request):
    org_id = await get_org_id(request)
    await require_feature(org_id, "alerts")
    pool = await get_pool()
    rows = await pool.fetch(
        """
        SELECT id, name, condition_type, threshold, window_minutes,
               cooldown_minutes, notify_emails, enabled, last_fired_at, created_at
        FROM codios.alert_rules
        WHERE org_id = $1
        ORDER BY created_at DESC
        """,
        org_id,
    )
    return [dict(r) for r in rows]


@router.post("", status_code=201)
async def create_rule(body: AlertRuleCreate, request: Request):
    org_id = await get_org_id(request)
    await require_feature(org_id, "alerts")

    if not body.name.strip():
        raise HTTPException(status_code=400, detail="Rule name is required")
    if not body.notify_emails:
        raise HTTPException(status_code=400, detail="At least one notification email is required")

    pool = await get_pool()
    row = await pool.fetchrow(
        """
        INSERT INTO codios.alert_rules
          (org_id, name, condition_type, threshold, window_minutes, cooldown_minutes, notify_emails)
        VALUES ($1,$2,$3,$4,$5,$6,$7)
        RETURNING *
        """,
        org_id, body.name.strip(), body.condition_type,
        body.threshold, body.window_minutes, body.cooldown_minutes,
        body.notify_emails,
    )
    return dict(row)


@router.patch("/{rule_id}")
async def update_rule(rule_id: str, body: AlertRuleUpdate, request: Request):
    org_id = await get_org_id(request)
    await require_feature(org_id, "alerts")
    pool = await get_pool()

    updates: list[str] = []
    args: list = []
    idx = 1

    for field, col in [
        ("name", "name"), ("threshold", "threshold"),
        ("window_minutes", "window_minutes"), ("cooldown_minutes", "cooldown_minutes"),
        ("notify_emails", "notify_emails"), ("enabled", "enabled"),
    ]:
        val = getattr(body, field)
        if val is not None:
            updates.append(f"{col} = ${idx}")
            args.append(val.strip() if isinstance(val, str) else val)
            idx += 1

    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    args += [rule_id, org_id]
    row = await pool.fetchrow(
        f"UPDATE codios.alert_rules SET {', '.join(updates)} WHERE id=${idx} AND org_id=${idx+1} RETURNING *",
        *args,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Alert rule not found")
    return dict(row)


@router.delete("/{rule_id}", status_code=204)
async def delete_rule(rule_id: str, request: Request):
    org_id = await get_org_id(request)
    await require_feature(org_id, "alerts")
    pool = await get_pool()
    result = await pool.execute(
        "DELETE FROM codios.alert_rules WHERE id=$1 AND org_id=$2",
        rule_id, org_id,
    )
    if result == "DELETE 0":
        raise HTTPException(status_code=404, detail="Alert rule not found")
