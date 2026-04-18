"""
Background scheduler — replaces Vercel Cron jobs.

Jobs:
  expire_contracts  — every 15 min: mark active contracts as expired
  check_anomalies   — every 1 min:  evaluate denial_spike alert rules, send emails
"""
from __future__ import annotations

import asyncio
import logging
import os
import smtplib
import ssl as ssl_mod
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timezone

import httpx

logger = logging.getLogger(__name__)

_RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
_RESEND_FROM    = os.getenv("RESEND_FROM", "Codios Alerts <alerts@mail.codios.midlantics.com>")
_APP_URL        = os.getenv("APP_URL", "https://codios.midlantics.com")

_SMTP_HOST      = os.getenv("SMTP_HOST", "")
_SMTP_PORT      = int(os.getenv("SMTP_PORT", "587"))
_SMTP_USER      = os.getenv("SMTP_USER", "")
_SMTP_PASSWORD  = os.getenv("SMTP_PASSWORD", "")

_expire_task:   asyncio.Task | None = None
_anomaly_task:  asyncio.Task | None = None


# ── Job: expire contracts ─────────────────────────────────────────────────────

async def _expire_contracts() -> None:
    from db import get_pool
    while True:
        await asyncio.sleep(15 * 60)
        try:
            pool = await get_pool()
            result = await pool.execute(
                """
                UPDATE codios.contracts
                SET status = 'expired'
                WHERE status = 'active' AND expires_at < NOW()
                """,
            )
            count = int(result.split()[-1]) if result else 0
            if count:
                logger.info("[scheduler] expired %d contracts", count)
        except Exception:
            logger.exception("[scheduler] expire_contracts error")


# ── Job: anomaly / denial spike detection ────────────────────────────────────

async def _check_anomalies() -> None:
    from db import get_pool
    while True:
        await asyncio.sleep(60)
        try:
            await _run_anomaly_check()
        except Exception:
            logger.exception("[scheduler] anomaly check error")


async def _run_anomaly_check() -> None:
    from db import get_pool
    pool = await get_pool()

    rows = await pool.fetch(
        """
        SELECT org_id, threshold, window_minutes, cooldown_minutes,
               last_fired_at, id AS rule_id, name, notify_emails
        FROM codios.alert_rules
        WHERE condition_type = 'denial_spike' AND enabled = TRUE
        """,
    )
    if not rows:
        return

    # Group by window_minutes → minimum threshold for that window
    window_map: dict[int, int] = {}
    for r in rows:
        prev = window_map.get(r["window_minutes"], 10**9)
        window_map[r["window_minutes"]] = min(prev, r["threshold"])

    now = datetime.now(timezone.utc)

    for window_minutes, min_threshold in window_map.items():
        since = datetime.fromtimestamp(
            now.timestamp() - window_minutes * 60, tz=timezone.utc
        ).isoformat()

        spikes = await pool.fetch(
            "SELECT * FROM codios.denial_spike_check($1, $2)",
            since, min_threshold,
        )

        for spike in spikes:
            org_id = spike["org_id"]
            denial_count = spike["denial_count"]
            agent_ids = list(spike["agent_ids"] or [])

            # Find all enabled rules for this org that match this window
            org_rules = [
                r for r in rows
                if r["org_id"] == org_id
                and r["window_minutes"] == window_minutes
                and r["threshold"] <= denial_count
            ]

            for rule in org_rules:
                # Cooldown check
                if rule["last_fired_at"]:
                    elapsed = (now - rule["last_fired_at"].replace(tzinfo=timezone.utc)).total_seconds()
                    if elapsed < rule["cooldown_minutes"] * 60:
                        continue

                if not rule["notify_emails"]:
                    continue

                sent = await _send_alert_email(
                    rule_name=rule["name"],
                    emails=list(rule["notify_emails"]),
                    org_id=org_id,
                    denial_count=denial_count,
                    agent_ids=agent_ids,
                    window_minutes=window_minutes,
                )

                if sent:
                    await pool.execute(
                        "UPDATE codios.alert_rules SET last_fired_at = $1 WHERE id = $2",
                        now, rule["rule_id"],
                    )
                    logger.info(
                        "[scheduler] alert fired: rule=%s org=%s denials=%d",
                        rule["rule_id"], org_id, denial_count,
                    )


async def _send_alert_email(
    rule_name: str,
    emails: list[str],
    org_id: str,
    denial_count: int,
    agent_ids: list[str],
    window_minutes: int,
) -> bool:
    subject = f"[Codios] Denial spike detected — {denial_count} denials in {window_minutes}min"
    html    = _build_email(rule_name, org_id, denial_count, agent_ids, window_minutes)

    if _RESEND_API_KEY:
        return await _send_via_resend(emails, subject, html)
    if _SMTP_HOST:
        return await asyncio.get_event_loop().run_in_executor(
            None, _send_via_smtp, emails, subject, html
        )
    logger.warning("[scheduler] No email transport configured (set RESEND_API_KEY or SMTP_HOST)")
    return False


async def _send_via_resend(emails: list[str], subject: str, html: str) -> bool:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            res = await client.post(
                "https://api.resend.com/emails",
                headers={"Authorization": f"Bearer {_RESEND_API_KEY}"},
                json={"from": _RESEND_FROM, "to": emails, "subject": subject, "html": html},
            )
        if res.status_code >= 400:
            logger.error("[scheduler] Resend error %d: %s", res.status_code, res.text)
            return False
        return True
    except Exception:
        logger.exception("[scheduler] Resend request failed")
        return False


def _send_via_smtp(emails: list[str], subject: str, html: str) -> bool:
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = _RESEND_FROM
        msg["To"]      = ", ".join(emails)
        msg.attach(MIMEText(html, "html", "utf-8"))

        context = ssl_mod.create_default_context()
        with smtplib.SMTP(_SMTP_HOST, _SMTP_PORT, timeout=15) as server:
            server.ehlo()
            server.starttls(context=context)
            if _SMTP_USER:
                server.login(_SMTP_USER, _SMTP_PASSWORD)
            server.sendmail(_RESEND_FROM, emails, msg.as_string())
        return True
    except Exception:
        logger.exception("[scheduler] SMTP send failed")
        return False


def _build_email(
    rule_name: str,
    org_id: str,
    denial_count: int,
    agent_ids: list[str],
    window_minutes: int,
) -> str:
    agents_line = ""
    if agent_ids:
        sample = ", ".join(agent_ids[:5])
        agents_line = f'<p style="margin:0 0 8px">Agents involved: <code style="background:#0f172a;padding:2px 6px;border-radius:4px;font-size:12px">{sample}</code></p>'

    detected_at = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:24px;background:#0f172a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif">
  <div style="max-width:520px;margin:0 auto">
    <div style="background:#1e293b;border:1px solid #334155;border-radius:12px;overflow:hidden">
      <div style="background:linear-gradient(135deg,#6d28d9,#7c3aed);padding:20px 24px">
        <p style="margin:0 0 4px;color:#e9d5ff;font-size:11px;font-weight:600;letter-spacing:0.08em;text-transform:uppercase">
          Codios Security Alert · {rule_name}
        </p>
        <h1 style="margin:0;color:#fff;font-size:18px;font-weight:700">Denial Spike Detected</h1>
      </div>
      <div style="padding:24px">
        <p style="margin:0 0 4px;color:#64748b;font-size:12px">
          Detected at {detected_at} · Org: <code style="font-size:11px">{org_id}</code>
        </p>
        <div style="margin:16px 0;padding:16px;background:#0f172a;border:1px solid #1e293b;border-radius:8px;color:#e2e8f0;font-size:14px;line-height:1.6">
          <p style="margin:0 0 8px"><b>{denial_count}</b> contract denials in the last <b>{window_minutes} minutes</b>.</p>
          {agents_line}
        </div>
        <a href="{_APP_URL}/dashboard/audit"
           style="display:inline-block;background:#7c3aed;color:#fff;padding:11px 22px;border-radius:8px;text-decoration:none;font-size:14px;font-weight:600">
          View Audit Log →
        </a>
      </div>
      <div style="padding:14px 24px;border-top:1px solid #1e293b">
        <p style="margin:0;color:#475569;font-size:12px">
          Codios by <a href="https://midlantics.com" style="color:#6d28d9">Midlantics</a> ·
          <a href="{_APP_URL}/dashboard/alerts" style="color:#6d28d9">Manage alerts</a>
        </p>
      </div>
    </div>
  </div>
</body>
</html>"""


# ── Lifecycle ─────────────────────────────────────────────────────────────────

def start_scheduler() -> None:
    global _expire_task, _anomaly_task
    _expire_task  = asyncio.create_task(_expire_contracts())
    _anomaly_task = asyncio.create_task(_check_anomalies())
    logger.info("[scheduler] started (expire=15min, anomaly=1min)")


async def stop_scheduler() -> None:
    for task in (_expire_task, _anomaly_task):
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
    logger.info("[scheduler] stopped")
