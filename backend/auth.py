import hashlib
import secrets
from fastapi import Request, HTTPException
from jose import jwt, JWTError
from config import get_settings

_PREFIX = "codios_sk_"

# Higher index = lower privilege
ROLES = ("owner", "admin", "member", "viewer")
ROLE_LEVEL = {r: i for i, r in enumerate(ROLES)}


def _extract_token(request: Request) -> str | None:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return None


def verify_token(token: str) -> dict:
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.supabase_jwt_secret,
            algorithms=["HS256"],
            options={"verify_aud": False},
        )
        return payload
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")


async def _resolve_api_key(raw_key: str) -> str | None:
    from db import get_pool
    hashed = hashlib.sha256(raw_key.encode()).hexdigest()
    pool = await get_pool()
    row = await pool.fetchrow(
        """
        UPDATE codios.api_keys
        SET last_used_at = NOW()
        WHERE key_hash = $1 AND revoked = false
        RETURNING org_id
        """,
        hashed,
    )
    return str(row["org_id"]) if row else None


async def get_org_id(request: Request) -> str:
    """Resolve org_id from auth header. Raises 401 if invalid."""
    org_id, _ = await get_org_id_and_role(request)
    return org_id


async def get_org_id_and_role(request: Request) -> tuple[str, str]:
    """Returns (org_id, role). API keys get role='admin'."""
    token = _extract_token(request)
    if not token:
        raise HTTPException(status_code=401, detail="Authorization header required")

    if token.startswith(_PREFIX):
        org_id = await _resolve_api_key(token)
        if not org_id:
            raise HTTPException(status_code=401, detail="Invalid or revoked API key")
        return org_id, "admin"

    payload = verify_token(token)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Token missing sub claim")

    email = payload.get("email", "")
    return await _resolve_or_bootstrap(user_id, email)


async def _resolve_or_bootstrap(user_id: str, email: str) -> tuple[str, str]:
    from db import get_pool
    pool = await get_pool()

    # Check existing active membership
    row = await pool.fetchrow(
        "SELECT org_id, role FROM codios.org_members WHERE user_id = $1 AND status = 'active' LIMIT 1",
        user_id,
    )
    if row:
        return str(row["org_id"]), str(row["role"])

    # Auto-accept pending invite matching this email
    if email:
        invite = await pool.fetchrow(
            """
            SELECT id, org_id, role FROM codios.org_members
            WHERE email = $1 AND status = 'pending'
              AND (invite_expires_at IS NULL OR invite_expires_at > NOW())
            LIMIT 1
            """,
            email,
        )
        if invite:
            await pool.execute(
                """
                UPDATE codios.org_members
                SET user_id=$2, status='active', invite_token=NULL, joined_at=NOW()
                WHERE id=$1
                """,
                invite["id"], user_id,
            )
            return str(invite["org_id"]), str(invite["role"])

    # First login — bootstrap as owner of their own org
    await _bootstrap_owner(pool, user_id, email)
    return user_id, "owner"


async def _bootstrap_owner(pool, user_id: str, email: str) -> None:
    from config import get_settings
    plan = "enterprise" if get_settings().vpc_mode else "free"
    await pool.execute(
        """
        INSERT INTO codios.organizations (id, plan)
        VALUES ($1, $2)
        ON CONFLICT (id) DO NOTHING
        """,
        user_id, plan,
    )
    await pool.execute(
        """
        INSERT INTO codios.org_members (org_id, user_id, email, role, status, joined_at)
        VALUES ($1, $2, $3, 'owner', 'active', NOW())
        ON CONFLICT DO NOTHING
        """,
        user_id, user_id, email,
    )


# keep for backward compat (used by sso.py)
async def _ensure_org(org_id: str) -> None:
    from db import get_pool
    pool = await get_pool()
    await _bootstrap_owner(pool, org_id, "")
