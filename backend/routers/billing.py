"""
Billing stubs for the open-source / VPC edition.

All organizations get the 'enterprise' plan — every feature is unlocked.
In the commercial SaaS edition (codios.midlantics.com) this module connects
to Stripe and gates features by subscription plan.
"""
from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/billing")

_PLAN_FEATURES: dict[str, list[str]] = {
    "enterprise": [
        "registry", "contracts", "audit", "alerts", "api_access",
        "custom_policies", "threat_detection", "csv_export",
        "sso", "sla", "audit_export",
    ],
}

_PLAN_LIMITS: dict[str, dict] = {
    "enterprise": {"max_agents": -1, "max_verifications_mo": -1, "audit_retention_days": -1},
}


async def get_plan(org_id: str) -> str:
    return "enterprise"


async def get_features(org_id: str) -> list[str]:
    return _PLAN_FEATURES["enterprise"]


async def require_feature(org_id: str, feature: str) -> None:
    pass  # all features unlocked in open-source edition


async def get_limits(org_id: str) -> dict:
    return _PLAN_LIMITS["enterprise"]


@router.get("/subscription")
async def get_subscription():
    return {"plan": "enterprise", "status": "active", "self_hosted": True}
