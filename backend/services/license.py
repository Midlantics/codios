"""
License key system for Codios VPC edition.

License keys are Ed25519-signed JWT-like tokens (but base64url, not JWTs)
encoding the customer's org, expiry, seat limit, and allowed features.
Verification is fully offline — no phone-home required for air-gapped deployments.

Key format: codios_lic_<base64url(payload)>.<base64url(signature)>

Payload JSON:
  {
    "customer":  "Acme Corp",
    "org_id":    "acme-corp",       # must match VPC_ORG_ID env var
    "seats":     50,                # max agent count (-1 = unlimited)
    "features":  ["sso", "audit_export", "custom_policies"],
    "issued_at": 1745000000,
    "expires_at": 1776536000,       # unix timestamp
    "version":   1
  }

The LICENSE_PUBLIC_KEY (Midlantics signing key) is embedded below.
Customers never see the private key — only Midlantics can issue licenses.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import time
from dataclasses import dataclass, field
from functools import lru_cache

logger = logging.getLogger(__name__)

# Midlantics license signing public key (Ed25519, base64).
# Private key is held by Midlantics only — never shipped in this codebase.
# To rotate: update this constant and re-issue all customer licenses.
_LICENSE_PUBLIC_KEY_ENV = "CODIOS_LICENSE_PUBLIC_KEY"

# Fallback for open-source / dev use: no license required.
_DEV_MODE_ORG = "vpc-default-org"


@dataclass
class LicenseInfo:
    valid:      bool
    customer:   str       = ""
    org_id:     str       = ""
    seats:      int       = -1
    features:   list[str] = field(default_factory=list)
    expires_at: int       = 0
    error:      str       = ""

    @property
    def expired(self) -> bool:
        return self.expires_at > 0 and time.time() > self.expires_at

    @property
    def days_remaining(self) -> int:
        if self.expires_at <= 0:
            return 999999
        return max(0, int((self.expires_at - time.time()) / 86400))

    def has_feature(self, feature: str) -> bool:
        return not self.features or feature in self.features


def verify_license(license_key: str) -> LicenseInfo:
    """
    Verify a license key offline. Returns LicenseInfo with valid=True on success.
    If no license key is provided and VPC_MODE is true, returns a dev license
    (unlimited, all features, no expiry) so open-source self-hosters work out of the box.
    """
    if not license_key:
        return LicenseInfo(
            valid=True, customer="Open Source", org_id=_DEV_MODE_ORG,
            seats=-1, features=[], expires_at=0,
        )

    try:
        return _verify(license_key)
    except Exception as e:
        logger.warning("[license] Verification error: %s", e)
        return LicenseInfo(valid=False, error=str(e))


def _verify(license_key: str) -> LicenseInfo:
    if not license_key.startswith("codios_lic_"):
        return LicenseInfo(valid=False, error="Invalid license key format")

    body = license_key[len("codios_lic_"):]
    parts = body.split(".")
    if len(parts) != 2:
        return LicenseInfo(valid=False, error="Malformed license key")

    payload_b64, sig_b64 = parts

    # Decode payload
    try:
        payload_bytes = base64.urlsafe_b64decode(_pad(payload_b64))
        payload = json.loads(payload_bytes)
    except Exception:
        return LicenseInfo(valid=False, error="Cannot decode license payload")

    # Verify signature if public key is configured
    pub_key_b64 = os.getenv(_LICENSE_PUBLIC_KEY_ENV, "")
    if pub_key_b64:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from cryptography.exceptions import InvalidSignature

            pub_bytes = base64.b64decode(pub_key_b64)
            pub_key   = Ed25519PublicKey.from_public_bytes(pub_bytes)
            sig_bytes = base64.urlsafe_b64decode(_pad(sig_b64))
            pub_key.verify(sig_bytes, payload_bytes)
        except InvalidSignature:
            return LicenseInfo(valid=False, error="License signature invalid")
        except Exception as e:
            return LicenseInfo(valid=False, error=f"Signature check failed: {e}")
    else:
        logger.debug("[license] CODIOS_LICENSE_PUBLIC_KEY not set — skipping signature check")

    # Check expiry
    expires_at = int(payload.get("expires_at", 0))
    if expires_at and time.time() > expires_at:
        return LicenseInfo(valid=False, error="License key has expired")

    info = LicenseInfo(
        valid=True,
        customer=payload.get("customer", ""),
        org_id=payload.get("org_id", ""),
        seats=int(payload.get("seats", -1)),
        features=list(payload.get("features", [])),
        expires_at=expires_at,
    )

    if info.days_remaining <= 30:
        logger.warning("[license] License expires in %d days (customer: %s)", info.days_remaining, info.customer)

    return info


def _pad(s: str) -> str:
    return s + "=" * (-len(s) % 4)


@lru_cache(maxsize=1)
def get_license() -> LicenseInfo:
    key = os.getenv("CODIOS_LICENSE_KEY", "")
    info = verify_license(key)
    if info.valid:
        logger.info(
            "[license] Licensed to: %s | seats: %s | expires: %s | features: %s",
            info.customer or "Open Source",
            "unlimited" if info.seats == -1 else info.seats,
            "never" if not info.expires_at else time.strftime("%Y-%m-%d", time.gmtime(info.expires_at)),
            info.features or "all",
        )
    else:
        logger.error("[license] Invalid license: %s", info.error)
    return info
