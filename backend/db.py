import asyncpg
from config import get_settings

_pool: asyncpg.Pool | None = None


async def get_pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        url = get_settings().database_url
        is_local = any(h in url for h in ("localhost", "127.0.0.1", "@postgres:", "@db:"))
        ssl: str | bool = False if is_local or "sslmode=disable" in url else "require"
        try:
            _pool = await asyncpg.create_pool(
                url,
                min_size=1,
                max_size=10,
                command_timeout=30,
                statement_cache_size=0,  # required for pgbouncer transaction mode
                ssl=ssl,
            )
        except Exception as e:
            raise RuntimeError(
                f"Database connection failed. Check DATABASE_URL.  Error: {e}"
            ) from e
    return _pool


async def close_pool() -> None:
    global _pool
    if _pool:
        await _pool.close()
        _pool = None
