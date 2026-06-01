"""
Redis client for nonce caching and rate limiting.  
Falls back gracefully to None if REDIS_URL is not set or connection fails.
"""
from __future__ import annotations

import redis.asyncio as aioredis
from config import get_settings

_client: aioredis.Redis | None = None
_connect_attempted = False


async def get_redis() -> aioredis.Redis | None:
    """Return a Redis client, or None if unavailable (triggers Postgres fallback)."""
    global _client, _connect_attempted
    if _connect_attempted:
        return _client

    _connect_attempted = True
    url = get_settings().redis_url
    if not url:
        return None

    try:
        client = aioredis.from_url(url, decode_responses=True, socket_connect_timeout=2)
        await client.ping()
        _client = client
        print("Redis connected.")
    except Exception as e:
        print(f"Redis unavailable (will use Postgres fallback): {e}")
        _client = None

    return _client


async def close_redis() -> None:
    global _client, _connect_attempted
    if _client:
        await _client.aclose()
        _client = None
    _connect_attempted = False
