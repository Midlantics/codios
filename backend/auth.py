import hashlib
from fastapi import Request, HTTPException
from jose import jwt, JWTError
from config import get_settings

_PREFIX = "codios_sk_"


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
    """Resolve org_id from Bearer token (Codios API key or Supabase JWT). Raises 401 if invalid."""
    token = _extract_token(request)
    if not token:
        raise HTTPException(status_code=401, detail="Authorization header required")

    if token.startswith(_PREFIX):
        org_id = await _resolve_api_key(token)
        if not org_id:
            raise HTTPException(status_code=401, detail="Invalid or revoked API key")
        return org_id

    payload = verify_token(token)
    sub = payload.get("sub")
    if not sub:
        raise HTTPException(status_code=401, detail="Token missing sub claim")

    # Auto-provision org on first login
    await _ensure_org(sub)
    return sub


async def _ensure_org(org_id: str) -> None:
    from db import get_pool
    from config import get_settings
    pool = await get_pool()
    plan = "enterprise" if get_settings().vpc_mode else "free"
    await pool.execute(
        """
        INSERT INTO codios.organizations (id, plan)
        VALUES ($1, $2)
        ON CONFLICT (id) DO NOTHING
        """,
        org_id, plan,
    )
