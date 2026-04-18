"""
Buffered async audit log writer.

Enforcement decisions are logged fire-and-forget so they never add latency
to the hot path. Events accumulate in a deque and are flushed to Supabase
in batches every FLUSH_INTERVAL seconds.

Usage:
    from services.audit_buffer import push_audit_event, start_flush_task, stop_flush_task

    # In lifespan startup:
    start_flush_task()

    # On each enforcement decision:
    push_audit_event(AuditEvent(...))

    # In lifespan shutdown:
    await stop_flush_task()
"""
from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

FLUSH_INTERVAL = 2.0  # seconds
MAX_BATCH = 100

_queue: deque = deque()
_task: Optional[asyncio.Task] = None


@dataclass
class AuditEvent:
    org_id: str
    action: str
    outcome: str                    # "allowed" | "denied" | "error"
    deny_reason: Optional[str] = None
    contract_id: Optional[str] = None
    issuer_agent_id: Optional[str] = None
    target_agent_id: Optional[str] = None
    payload_hash: Optional[str] = None
    ip_address: Optional[str] = None
    duration_ms: Optional[int] = None
    calls_count: Optional[int] = None
    metadata: dict = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def push_audit_event(event: AuditEvent) -> None:
    """Enqueue an audit event for async flush. Never blocks."""
    _queue.append(event)


def start_flush_task() -> None:
    global _task
    _task = asyncio.create_task(_flush_loop())


async def stop_flush_task() -> None:
    global _task
    if _task:
        _task.cancel()
        try:
            await _task
        except asyncio.CancelledError:
            pass
        _task = None
    await _flush_once()  # drain remaining events on shutdown


async def _flush_loop() -> None:
    while True:
        await asyncio.sleep(FLUSH_INTERVAL)
        await _flush_once()


async def _flush_once() -> None:
    if not _queue:
        return

    batch: list[AuditEvent] = []
    while _queue and len(batch) < MAX_BATCH:
        batch.append(_queue.popleft())

    if not batch:
        return

    try:
        from db import get_pool
        import json
        pool = await get_pool()
        await pool.executemany(
            """
            INSERT INTO codios.audit_logs
              (org_id, contract_id, issuer_agent_id, target_agent_id,
               action, outcome, deny_reason, payload_hash,
               ip_address, duration_ms, calls_count, metadata, created_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
            """,
            [
                (
                    e.org_id,
                    e.contract_id,
                    e.issuer_agent_id,
                    e.target_agent_id,
                    e.action,
                    e.outcome,
                    e.deny_reason,
                    e.payload_hash,
                    e.ip_address,
                    e.duration_ms,
                    e.calls_count,
                    json.dumps(e.metadata),
                    e.created_at,
                )
                for e in batch
            ],
        )
    except Exception as e:
        # Re-enqueue failed events (prepend so they're retried next flush)
        for event in reversed(batch):
            _queue.appendleft(event)
        print(f"[audit_buffer] Flush failed, {len(batch)} events re-queued: {e}")
