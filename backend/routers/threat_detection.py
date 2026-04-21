"""
Threat Detection — analyse audit logs for behavioural anomalies.

Detects:
  off_hours_access     — verified calls between 22:00–06:00 UTC
  action_burst         — >20 calls from one agent in any 5-min window
  unknown_agent        — verified calls from an agent_id not in the org's registry
  repeated_denials     — same agent denied 5+ times in 10 min (may indicate probing)
  new_agent_spike      — agent registered < 1h ago generating > 10 calls
"""
from __future__ import annotations

from datetime import datetime, timezone
from fastapi import APIRouter, Request
from db import get_pool
from auth import get_org_id
from routers.billing import require_feature

router = APIRouter(prefix="/threats")


@router.get("")
async def get_threats(request: Request, hours: int = 24):
    org_id = await get_org_id(request)
    await require_feature(org_id, "threat_detection")
    pool = await get_pool()

    threats: list[dict] = []

    # ── 1. Off-hours access (22:00–06:00 UTC) ────────────────────────────────
    rows = await pool.fetch(
        """
        SELECT issuer_agent_id, COUNT(*) AS cnt,
               MIN(created_at) AS first_at, MAX(created_at) AS last_at
        FROM codios.audit_logs
        WHERE org_id = $1
          AND outcome = 'allowed'
          AND created_at >= NOW() - ($2 || ' hours')::INTERVAL
          AND (EXTRACT(HOUR FROM created_at AT TIME ZONE 'UTC') >= 22
               OR EXTRACT(HOUR FROM created_at AT TIME ZONE 'UTC') < 6)
        GROUP BY issuer_agent_id
        HAVING COUNT(*) > 0
        ORDER BY cnt DESC
        LIMIT 20
        """,
        org_id, str(hours),
    )
    for r in rows:
        threats.append({
            "type": "off_hours_access",
            "severity": "medium",
            "agent_id": r["issuer_agent_id"],
            "count": r["cnt"],
            "first_at": r["first_at"].isoformat() if r["first_at"] else None,
            "last_at":  r["last_at"].isoformat()  if r["last_at"]  else None,
            "description": f"Agent made {r['cnt']} verified call(s) between 22:00–06:00 UTC.",
        })

    # ── 2. Action burst (>20 calls in any 5-min window) ──────────────────────
    rows = await pool.fetch(
        """
        SELECT issuer_agent_id, COUNT(*) AS cnt,
               date_trunc('minute', created_at) - (EXTRACT(minute FROM created_at)::int % 5) * INTERVAL '1 minute' AS window_start
        FROM codios.audit_logs
        WHERE org_id = $1
          AND created_at >= NOW() - ($2 || ' hours')::INTERVAL
        GROUP BY issuer_agent_id, window_start
        HAVING COUNT(*) > 20
        ORDER BY cnt DESC
        LIMIT 10
        """,
        org_id, str(hours),
    )
    for r in rows:
        threats.append({
            "type": "action_burst",
            "severity": "high",
            "agent_id": r["issuer_agent_id"],
            "count": r["cnt"],
            "window_start": r["window_start"].isoformat() if r["window_start"] else None,
            "description": f"Agent made {r['cnt']} calls in a single 5-minute window.",
        })

    # ── 3. Unknown agent (issuer not in registry) ─────────────────────────────
    rows = await pool.fetch(
        """
        SELECT DISTINCT al.issuer_agent_id
        FROM codios.audit_logs al
        WHERE al.org_id = $1
          AND al.created_at >= NOW() - ($2 || ' hours')::INTERVAL
          AND al.issuer_agent_id IS NOT NULL
          AND al.issuer_agent_id != 'agt_platform'
          AND NOT EXISTS (
            SELECT 1 FROM codios.agents a
            WHERE a.id = al.issuer_agent_id AND a.org_id = $1
          )
        LIMIT 10
        """,
        org_id, str(hours),
    )
    for r in rows:
        threats.append({
            "type": "unknown_agent",
            "severity": "critical",
            "agent_id": r["issuer_agent_id"],
            "description": "Contract verified by an agent ID not registered in this org.",
        })

    # ── 4. Repeated denials (5+ in 10 min — probing indicator) ───────────────
    rows = await pool.fetch(
        """
        SELECT issuer_agent_id, COUNT(*) AS cnt,
               MIN(created_at) AS first_at
        FROM codios.audit_logs
        WHERE org_id = $1
          AND outcome = 'denied'
          AND created_at >= NOW() - ($2 || ' hours')::INTERVAL
        GROUP BY issuer_agent_id,
                 date_trunc('minute', created_at) - (EXTRACT(minute FROM created_at)::int % 10) * INTERVAL '1 minute'
        HAVING COUNT(*) >= 5
        ORDER BY cnt DESC
        LIMIT 10
        """,
        org_id, str(hours),
    )
    for r in rows:
        threats.append({
            "type": "repeated_denials",
            "severity": "high",
            "agent_id": r["issuer_agent_id"],
            "count": r["cnt"],
            "first_at": r["first_at"].isoformat() if r["first_at"] else None,
            "description": f"Agent denied {r['cnt']} times in a 10-minute window — possible contract probing.",
        })

    # ── 5. New agent spike (registered < 1h, > 10 calls) ─────────────────────
    rows = await pool.fetch(
        """
        SELECT a.id AS agent_id, a.name, COUNT(al.id) AS cnt
        FROM codios.agents a
        JOIN codios.audit_logs al ON al.issuer_agent_id = a.id
        WHERE a.org_id = $1
          AND a.created_at >= NOW() - INTERVAL '1 hour'
          AND al.created_at >= NOW() - INTERVAL '1 hour'
        GROUP BY a.id, a.name
        HAVING COUNT(al.id) > 10
        LIMIT 10
        """,
        org_id,
    )
    for r in rows:
        threats.append({
            "type": "new_agent_spike",
            "severity": "medium",
            "agent_id": r["agent_id"],
            "agent_name": r["name"],
            "count": r["cnt"],
            "description": f"Newly registered agent '{r['name']}' made {r['cnt']} calls within 1 hour of registration.",
        })

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "window_hours": hours,
        "threat_count": len(threats),
        "threats": sorted(threats, key=lambda t: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(t["severity"], 4)),
    }
