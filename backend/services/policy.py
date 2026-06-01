"""
Policy evaluation for Codios contracts. 
 
Primary: pure-Python implementation of the Rego scope rules — ~0ms, no network.
Optional: delegate to OPA REST API if OPA_URL env var is set (e.g. for custom
  per-org Rego policies stored in the database).

The Python rules are the canonical fallback and match the Rego spec exactly.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Optional
import httpx

OPA_URL = os.getenv("OPA_URL", "")


async def evaluate(
    contract: dict,
    action: str,
    calls_used: int = 0,
    caller_did: Optional[str] = None,
) -> tuple[bool, Optional[str]]:
    """
    Evaluate whether action is permitted under contract.
    Returns (allowed, deny_reason). deny_reason is None when allowed.

    Uses OPA REST API if OPA_URL is set, otherwise falls back to Python rules.
    """
    if OPA_URL:
        return await _evaluate_opa(contract, action, calls_used, caller_did)
    return _evaluate_python(contract, action, calls_used, caller_did)


def _evaluate_python(
    contract: dict,
    action: str,
    calls_used: int,
    caller_did: Optional[str],
) -> tuple[bool, Optional[str]]:
    """
    Python implementation of base/scope.rego + base/identity.rego.
    Fail-fast order matches OPA deny_reason priority.
    """
    # 1. Expiry
    try:
        expires_at = datetime.fromisoformat(contract["expires_at"])
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < datetime.now(timezone.utc):
            return False, "contract_expired"
    except (KeyError, ValueError):
        return False, "invalid_contract"

    # 2. Forbidden actions
    if action in contract.get("forbidden_actions", []):
        return False, "action_explicitly_forbidden"

    # 3. Allowed actions (empty list = allow all)
    allowed = contract.get("allowed_actions", [])
    if allowed and action not in allowed:
        return False, "action_not_in_scope"

    # 4. Resource limits — call count
    limits = contract.get("resource_limits", {})
    max_calls = limits.get("max_calls")
    if max_calls is not None and calls_used >= int(max_calls):
        return False, "resource_limit_exceeded"

    # 5. Identity — caller DID must match contract issuer
    if caller_did and caller_did != contract.get("issuer", {}).get("did", ""):
        return False, "identity_mismatch"

    return True, None


async def _evaluate_opa(
    contract: dict,
    action: str,
    calls_used: int,
    caller_did: Optional[str],
) -> tuple[bool, Optional[str]]:
    """
    Delegate to OPA REST API. Falls back to Python rules if OPA is unreachable.
    Input shape matches base/scope.rego expectations.
    """
    policy_input = {
        "contract": contract,
        "action": action,
        "calls_used": calls_used,
        "caller_did": caller_did or "",
    }

    try:
        async with httpx.AsyncClient(timeout=0.5) as client:
            res = await client.post(
                f"{OPA_URL}/v1/data/codios/scope",
                json={"input": policy_input},
            )
            if not res.is_success:
                return False, "policy_engine_error"

            result = res.json().get("result", {})
            allow: bool = result.get("allow", False)
            deny_reason: Optional[str] = result.get("deny_reason") if not allow else None
            return allow, deny_reason

    except httpx.TimeoutException:
        # OPA timeout — fail closed, then log
        return False, "policy_engine_timeout"
    except Exception:
        # OPA unreachable — fall back to Python rules
        return _evaluate_python(contract, action, calls_used, caller_did)
