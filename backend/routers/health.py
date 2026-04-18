import time
from fastapi import APIRouter, Request, HTTPException
from auth import get_org_id
from config import get_settings

router = APIRouter()


@router.get("/health")
async def health():
    settings = get_settings()
    payload: dict = {"status": "ok", "service": "codios"}
    if settings.vpc_mode:
        from services.license import get_license
        lic = get_license()
        payload["license"] = {
            "valid":          lic.valid,
            "customer":       lic.customer or "Open Source",
            "days_remaining": lic.days_remaining,
        }
    return payload


@router.get("/license")
async def license_info(request: Request):
    """Returns full license details. Requires authentication."""
    await get_org_id(request)
    settings = get_settings()
    if not settings.vpc_mode:
        raise HTTPException(404, "License endpoint only available in VPC mode")

    from services.license import get_license
    lic = get_license()
    return {
        "valid":          lic.valid,
        "customer":       lic.customer,
        "org_id":         lic.org_id,
        "seats":          lic.seats,
        "features":       lic.features,
        "expires_at":     time.strftime("%Y-%m-%d", time.gmtime(lic.expires_at)) if lic.expires_at else None,
        "days_remaining": lic.days_remaining,
        "error":          lic.error or None,
    }
