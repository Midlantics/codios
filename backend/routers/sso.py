"""
Enterprise SSO — OIDC 1.0 / OAuth 2.0 Authorization Code flow.

Supports any OIDC-compliant IdP: Okta, Azure AD, Google Workspace,
Ping Identity, Auth0, Keycloak.

VPC mode: configured via env vars (OIDC_ISSUER_URL, OIDC_CLIENT_ID, etc.)
SaaS mode: per-org config stored in codios.sso_configs table.

Flow:
  GET /sso/login              → redirect to IdP authorization endpoint
  GET /sso/callback?code=...  → exchange code → validate ID token → return JWT
  GET /sso/config             → get current SSO config (redacted secret)
  PUT /sso/config             → save SSO config (Pro plan required)
  DELETE /sso/config          → remove SSO config
  POST /sso/test              → test OIDC discovery without saving
"""
from __future__ import annotations

import hashlib
import os
import secrets
import time
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import RedirectResponse
from jose import jwt, JWTError
from pydantic import BaseModel

from auth import get_org_id
from config import get_settings
from db import get_pool
from routers.billing import require_feature

router = APIRouter(prefix="/sso")

_STATE_TTL = 600  # 10 minutes
_states: dict[str, dict] = {}  # in-memory state store (fine for single-instance VPC)


# ── OIDC discovery ─────────────────────────────────────────────────────────────

async def _discover(issuer_url: str) -> dict:
    url = issuer_url.rstrip("/") + "/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=10.0) as client:
        res = await client.get(url)
    if res.status_code != 200:
        raise HTTPException(502, f"OIDC discovery failed: {res.status_code} {url}")
    return res.json()


# ── Config helpers ────────────────────────────────────────────────────────────

async def _get_sso_config(org_id: str) -> dict | None:
    settings = get_settings()
    # VPC: prefer env vars
    if settings.vpc_mode:
        issuer = os.getenv("OIDC_ISSUER_URL", "")
        client_id = os.getenv("OIDC_CLIENT_ID", "")
        client_secret = os.getenv("OIDC_CLIENT_SECRET", "")
        if issuer and client_id and client_secret:
            return {
                "provider_name": os.getenv("OIDC_PROVIDER_NAME", "OIDC"),
                "issuer_url": issuer,
                "client_id": client_id,
                "client_secret": client_secret,
                "enabled": True,
            }
    pool = await get_pool()
    row = await pool.fetchrow(
        "SELECT * FROM codios.sso_configs WHERE org_id=$1 AND enabled=true",
        org_id,
    )
    if not row:
        return None
    d = dict(row)
    from services.encryption import decrypt
    d["client_secret"] = decrypt(d["client_secret"])
    return d


# ── Login ─────────────────────────────────────────────────────────────────────

@router.get("/login")
async def sso_login(request: Request, org_id: str | None = None):
    """
    Redirect the browser to the IdP. For VPC, org_id is optional (single org).
    For SaaS, pass ?org_id=<org_id> so we know which SSO config to use.
    """
    resolved_org = org_id or "vpc-default-org"
    config = await _get_sso_config(resolved_org)
    if not config:
        raise HTTPException(404, "SSO not configured for this organization")

    discovery = await _discover(config["issuer_url"])
    auth_endpoint = discovery["authorization_endpoint"]

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(16)
    _states[state] = {"org_id": resolved_org, "nonce": nonce, "ts": time.time()}

    settings = get_settings()
    redirect_uri = os.getenv("OIDC_REDIRECT_URI", f"{settings.app_url}/sso/callback")

    params = {
        "response_type": "code",
        "client_id":     config["client_id"],
        "redirect_uri":  redirect_uri,
        "scope":         "openid email profile",
        "state":         state,
        "nonce":         nonce,
    }
    return RedirectResponse(f"{auth_endpoint}?{urlencode(params)}")


# ── Callback ──────────────────────────────────────────────────────────────────

@router.get("/callback")
async def sso_callback(request: Request, code: str, state: str, error: str | None = None):
    if error:
        raise HTTPException(400, f"IdP error: {error}")

    state_data = _states.pop(state, None)
    if not state_data:
        raise HTTPException(400, "Invalid or expired state parameter")
    if time.time() - state_data["ts"] > _STATE_TTL:
        raise HTTPException(400, "SSO state expired — please try again")

    org_id = state_data["org_id"]
    config = await _get_sso_config(org_id)
    if not config:
        raise HTTPException(404, "SSO config not found")

    discovery = await _discover(config["issuer_url"])
    settings = get_settings()
    redirect_uri = os.getenv("OIDC_REDIRECT_URI", f"{settings.app_url}/sso/callback")

    # Exchange code for tokens
    async with httpx.AsyncClient(timeout=15.0) as client:
        res = await client.post(
            discovery["token_endpoint"],
            data={
                "grant_type":   "authorization_code",
                "code":         code,
                "redirect_uri": redirect_uri,
                "client_id":    config["client_id"],
                "client_secret": config["client_secret"],
            },
        )
    if res.status_code != 200:
        raise HTTPException(502, f"Token exchange failed: {res.text[:200]}")

    tokens = res.json()
    id_token = tokens.get("id_token")
    if not id_token:
        raise HTTPException(502, "IdP did not return an id_token")

    # Fetch JWKS and validate ID token
    async with httpx.AsyncClient(timeout=10.0) as client:
        jwks_res = await client.get(discovery["jwks_uri"])
    jwks = jwks_res.json()

    try:
        claims = jwt.decode(
            id_token,
            jwks,
            algorithms=["RS256", "ES256"],
            audience=config["client_id"],
            options={"verify_at_hash": False},
        )
    except JWTError as e:
        raise HTTPException(401, f"ID token validation failed: {e}")

    if claims.get("nonce") != state_data["nonce"]:
        raise HTTPException(401, "Nonce mismatch — possible replay attack")

    email   = claims.get("email", "")
    sub     = claims.get("sub", "")
    sso_uid = f"sso:{hashlib.sha256(f'{org_id}:{sub}'.encode()).hexdigest()[:16]}"

    # Ensure org exists
    pool = await get_pool()
    await pool.execute(
        "INSERT INTO codios.organizations (id) VALUES ($1) ON CONFLICT (id) DO NOTHING",
        org_id,
    )

    # Issue a Codios session JWT
    session_jwt = jwt.encode(
        {
            "sub":   sso_uid,
            "email": email,
            "org":   org_id,
            "iss":   "codios",
            "iat":   int(time.time()),
            "exp":   int(time.time()) + 8 * 3600,
        },
        settings.supabase_jwt_secret,
        algorithm="HS256",
    )

    # For VPC: redirect to dashboard with token in query param
    # (dashboard reads it and stores in localStorage / cookie)
    app_url = settings.app_url.rstrip("/")
    return RedirectResponse(f"{app_url}/auth/sso-done?token={session_jwt}&email={email}")


# ── Config management ─────────────────────────────────────────────────────────

class SSOConfigBody(BaseModel):
    provider_name: str = "OIDC"
    issuer_url:    str
    client_id:     str
    client_secret: str


@router.get("/config")
async def get_sso_config_endpoint(request: Request):
    org_id = await get_org_id(request)
    await require_feature(org_id, "sso")
    pool = await get_pool()
    row = await pool.fetchrow(
        "SELECT id, provider_name, issuer_url, client_id, enabled, created_at FROM codios.sso_configs WHERE org_id=$1",
        org_id,
    )
    if not row:
        return {"configured": False}
    return {**dict(row), "configured": True, "client_secret": "••••••••"}


@router.put("/config", status_code=200)
async def save_sso_config(body: SSOConfigBody, request: Request):
    org_id = await get_org_id(request)
    await require_feature(org_id, "sso")

    # Validate by running discovery
    await _discover(body.issuer_url)

    from services.encryption import encrypt, current_key_id
    stored_secret = encrypt(body.client_secret)

    pool = await get_pool()
    await pool.execute(
        """
        INSERT INTO codios.sso_configs (org_id, provider_name, issuer_url, client_id, client_secret, enc_key_id)
        VALUES ($1,$2,$3,$4,$5,$6)
        ON CONFLICT (org_id) DO UPDATE SET
          provider_name = EXCLUDED.provider_name,
          issuer_url    = EXCLUDED.issuer_url,
          client_id     = EXCLUDED.client_id,
          client_secret = EXCLUDED.client_secret,
          enc_key_id    = EXCLUDED.enc_key_id,
          updated_at    = NOW()
        """,
        org_id, body.provider_name, body.issuer_url, body.client_id, stored_secret, current_key_id(),
    )
    return {"ok": True}


@router.delete("/config", status_code=204)
async def delete_sso_config(request: Request):
    org_id = await get_org_id(request)
    await require_feature(org_id, "sso")
    pool = await get_pool()
    await pool.execute("DELETE FROM codios.sso_configs WHERE org_id=$1", org_id)


@router.post("/test")
async def test_sso_config(body: SSOConfigBody, request: Request):
    org_id = await get_org_id(request)
    await require_feature(org_id, "sso")
    try:
        discovery = await _discover(body.issuer_url)
        return {
            "ok":                  True,
            "issuer":              discovery.get("issuer"),
            "authorization_endpoint": discovery.get("authorization_endpoint"),
            "token_endpoint":      discovery.get("token_endpoint"),
            "scopes_supported":    discovery.get("scopes_supported", []),
        }
    except HTTPException as e:
        return {"ok": False, "error": e.detail}
