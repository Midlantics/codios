"""
Team — org member management.

Roles (highest → lowest): owner > admin > member > viewer
- owner:  1 per org; cannot be removed or role-changed
- admin:  invite/remove non-owners, manage all resources
- member: full resource read/write, no team management
- viewer: read-only across the dashboard

API keys are treated as admin.
"""
from __future__ import annotations

import asyncio
import os
import secrets
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel, field_validator
from auth import get_org_id_and_role, ROLE_LEVEL, _extract_token, verify_token

router = APIRouter(prefix="/team")

_INVITE_TTL_HOURS = 72


class InviteBody(BaseModel):
    email: str
    role: str = "member"

    @field_validator("email")
    @classmethod
    def _check_email(cls, v: str) -> str:
        v = v.strip().lower()
        if "@" not in v or "." not in v.split("@")[-1]:
            raise ValueError("invalid email address")
        return v


class RoleUpdate(BaseModel):
    role: str


@router.get("/members")
async def list_members(request: Request):
    org_id, _ = await get_org_id_and_role(request)
    from db import get_pool
    pool = await get_pool()
    rows = await pool.fetch(
        """
        SELECT id, user_id, email, role, status, invited_by, joined_at, created_at
        FROM codios.org_members
        WHERE org_id = $1
        ORDER BY
          CASE role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 WHEN 'member' THEN 2 ELSE 3 END,
          created_at ASC
        """,
        org_id,
    )
    return [dict(r) for r in rows]


@router.post("/invites", status_code=201)
async def invite_member(body: InviteBody, request: Request):
    org_id, caller_role = await get_org_id_and_role(request)
    _assert_min_role(caller_role, "admin")

    if body.role not in ("admin", "member", "viewer"):
        raise HTTPException(400, "role must be admin | member | viewer")

    from db import get_pool
    pool = await get_pool()

    existing = await pool.fetchrow(
        "SELECT id, status FROM codios.org_members WHERE org_id=$1 AND email=$2",
        org_id, body.email,
    )
    if existing and existing["status"] == "active":
        raise HTTPException(409, "User is already an active member of this organization")

    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(hours=_INVITE_TTL_HOURS)

    # Resolve inviter user_id from JWT (best-effort)
    inviter_id: str | None = None
    raw = _extract_token(request)
    if raw and not raw.startswith("codios_sk_"):
        inviter_id = verify_token(raw).get("sub")

    if existing:
        await pool.execute(
            """
            UPDATE codios.org_members
            SET role=$3, invite_token=$4, invite_expires_at=$5, status='pending'
            WHERE id=$1 AND org_id=$2
            """,
            existing["id"], org_id, body.role, token, expires,
        )
        member_id = existing["id"]
    else:
        row = await pool.fetchrow(
            """
            INSERT INTO codios.org_members (org_id, email, role, status, invite_token, invite_expires_at, invited_by)
            VALUES ($1, $2, $3, 'pending', $4, $5, $6)
            RETURNING id
            """,
            org_id, body.email, body.role, token, expires, inviter_id,
        )
        member_id = row["id"]

    from config import get_settings
    accept_url = f"{get_settings().app_url}/auth/accept-invite?token={token}"

    await _send_invite_email(body.email, accept_url)

    return {
        "ok": True,
        "id": member_id,
        "invite_url": accept_url,
        "expires_at": expires.isoformat(),
    }


@router.post("/invites/accept")
async def accept_invite(request: Request):
    """Accept a pending invite. Caller must be authenticated; email must match the invite."""
    token = request.query_params.get("token")
    if not token:
        raise HTTPException(400, "token query param required")

    from db import get_pool
    pool = await get_pool()

    invite = await pool.fetchrow(
        """
        SELECT id, org_id, email, role FROM codios.org_members
        WHERE invite_token=$1 AND status='pending'
          AND (invite_expires_at IS NULL OR invite_expires_at > NOW())
        """,
        token,
    )
    if not invite:
        raise HTTPException(404, "Invite not found or expired")

    raw = _extract_token(request)
    if not raw:
        raise HTTPException(401, "Authorization header required")
    payload = verify_token(raw)
    user_id = payload.get("sub")
    caller_email = payload.get("email", "")

    if caller_email and caller_email.lower() != invite["email"].lower():
        raise HTTPException(403, f"This invite was sent to {invite['email']}")

    await pool.execute(
        """
        UPDATE codios.org_members
        SET user_id=$2, status='active', invite_token=NULL, joined_at=NOW()
        WHERE id=$1
        """,
        invite["id"], user_id,
    )
    return {"ok": True, "org_id": invite["org_id"], "role": invite["role"]}


@router.delete("/invites/{member_id}", status_code=204)
async def cancel_invite(member_id: str, request: Request):
    org_id, caller_role = await get_org_id_and_role(request)
    _assert_min_role(caller_role, "admin")

    from db import get_pool
    pool = await get_pool()
    result = await pool.execute(
        "DELETE FROM codios.org_members WHERE id=$1 AND org_id=$2 AND status='pending'",
        member_id, org_id,
    )
    if result == "DELETE 0":
        raise HTTPException(404, "Pending invite not found")


@router.patch("/members/{member_id}")
async def update_member_role(member_id: str, body: RoleUpdate, request: Request):
    org_id, caller_role = await get_org_id_and_role(request)
    _assert_min_role(caller_role, "owner")

    if body.role not in ("admin", "member", "viewer"):
        raise HTTPException(400, "role must be admin | member | viewer")

    from db import get_pool
    pool = await get_pool()
    target = await pool.fetchrow(
        "SELECT role FROM codios.org_members WHERE id=$1 AND org_id=$2 AND status='active'",
        member_id, org_id,
    )
    if not target:
        raise HTTPException(404, "Member not found")
    if target["role"] == "owner":
        raise HTTPException(400, "Cannot change the owner's role")

    await pool.execute(
        "UPDATE codios.org_members SET role=$2 WHERE id=$1",
        member_id, body.role,
    )
    return {"ok": True}


@router.delete("/members/{member_id}", status_code=204)
async def remove_member(member_id: str, request: Request):
    org_id, caller_role = await get_org_id_and_role(request)
    _assert_min_role(caller_role, "admin")

    from db import get_pool
    pool = await get_pool()
    target = await pool.fetchrow(
        "SELECT role FROM codios.org_members WHERE id=$1 AND org_id=$2 AND status='active'",
        member_id, org_id,
    )
    if not target:
        raise HTTPException(404, "Member not found")
    if target["role"] == "owner":
        raise HTTPException(400, "Cannot remove the org owner")

    await pool.execute(
        "DELETE FROM codios.org_members WHERE id=$1 AND org_id=$2",
        member_id, org_id,
    )


# ── helpers ──────────────────────────────────────────────────────────────────

def _assert_min_role(role: str, minimum: str) -> None:
    if ROLE_LEVEL.get(role, 99) > ROLE_LEVEL[minimum]:
        raise HTTPException(403, f"Requires {minimum} role or higher")


async def _send_invite_email(to_email: str, accept_url: str) -> None:
    resend_key = os.getenv("RESEND_API_KEY", "")
    resend_from = os.getenv("RESEND_FROM", "Codios <noreply@mail.codios.midlantics.com>")
    smtp_host = os.getenv("SMTP_HOST", "")

    subject = "You've been invited to Codios"
    html = (
        "<p>You've been invited to join a Codios organization.</p>"
        f'<p><a href="{accept_url}">Accept invite</a> (expires in {_INVITE_TTL_HOURS} hours)</p>'
        f"<p>Or copy this link:<br><code>{accept_url}</code></p>"
    )

    try:
        if resend_key:
            import httpx
            async with httpx.AsyncClient(timeout=10.0) as client:
                await client.post(
                    "https://api.resend.com/emails",
                    headers={"Authorization": f"Bearer {resend_key}"},
                    json={"from": resend_from, "to": [to_email], "subject": subject, "html": html},
                )
        elif smtp_host:
            import smtplib, ssl as ssl_mod
            from email.mime.multipart import MIMEMultipart
            from email.mime.text import MIMEText

            smtp_port = int(os.getenv("SMTP_PORT", "587"))
            smtp_user = os.getenv("SMTP_USER", "")
            smtp_pass = os.getenv("SMTP_PASSWORD", "")

            def _send():
                msg = MIMEMultipart("alternative")
                msg["Subject"] = subject
                msg["From"] = smtp_user
                msg["To"] = to_email
                msg.attach(MIMEText(html, "html"))
                ctx = ssl_mod.create_default_context()
                with smtplib.SMTP(smtp_host, smtp_port) as s:
                    s.ehlo()
                    s.starttls(context=ctx)
                    if smtp_user:
                        s.login(smtp_user, smtp_pass)
                    s.sendmail(smtp_user, [to_email], msg.as_string())

            await asyncio.get_event_loop().run_in_executor(None, _send)
    except Exception:
        pass  # email failure is non-fatal; invite_url is returned in the API response
