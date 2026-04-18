"""
FastAPI dependency for Codios contract enforcement.

Usage:
    import os
    from fastapi import FastAPI, Depends
    from codios.middleware.fastapi import require_contract

    app = FastAPI()
    PUBLIC_KEY = os.environ["CODIOS_PUBLIC_KEY"]

    @app.post("/transfer")
    async def transfer(
        body: TransferBody,
        contract = Depends(require_contract("transfer", PUBLIC_KEY)),
    ):
        # contract["issuer"]["did"]   — caller's DID
        # contract["expires_at"]      — expiry ISO timestamp
        # contract["resource_limits"] — {"max_calls": N, ...}
        return {"ok": True}

HTTP errors raised on failure:
    401 — missing header / invalid signature / expired
    403 — action not allowed / forbidden
    503 — CODIOS_PUBLIC_KEY not set
"""
from __future__ import annotations

from typing import Any

from fastapi import Header, HTTPException
from codios.contract import verify_contract, decode_contract


def require_contract(action: str | None = None, platform_public_key: str = ""):
    """
    FastAPI dependency factory for Codios contract enforcement.

    Args:
        action:               Action name to scope-check (e.g. "transfer"). Pass None
                              to verify signature + expiry only.
        platform_public_key:  Base64 Ed25519 public key (CODIOS_PUBLIC_KEY). If omitted,
                              reads from the CODIOS_PUBLIC_KEY environment variable at
                              request time.

    Returns:
        FastAPI dependency that injects the verified contract dict into your handler.
    """
    import os

    async def _dep(
        x_codios_contract: str | None = Header(default=None, alias="X-Codios-Contract"),
    ) -> dict[str, Any]:
        if not x_codios_contract:
            raise HTTPException(
                status_code=401,
                detail="Missing X-Codios-Contract header",
            )

        pub_key = platform_public_key or os.environ.get("CODIOS_PUBLIC_KEY", "")
        if not pub_key:
            raise HTTPException(status_code=503, detail="CODIOS_PUBLIC_KEY not configured")

        result = verify_contract(x_codios_contract, pub_key, action=action)

        if not result.valid:
            if result.reason == "action_not_allowed":
                raise HTTPException(status_code=403, detail=f"Action '{action}' not permitted by contract")
            raise HTTPException(status_code=401, detail=f"Contract rejected: {result.reason}")

        return result.payload  # type: ignore[return-value]

    return _dep
