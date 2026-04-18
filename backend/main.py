from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from config import get_settings
from db import get_pool, close_pool
from services.redis_client import get_redis, close_redis
from services.audit_buffer import start_flush_task, stop_flush_task
from services.scheduler import start_scheduler, stop_scheduler
from routers import health, agents, contracts, audit, keys, nonces, billing, enforce, policies, alert_rules, sso, team


async def _apply_schema() -> None:
    vpc = get_settings().vpc_mode
    schema_path = Path(__file__).parent / ("schema.local.sql" if vpc else "schema.sql")
    if not schema_path.exists():
        return
    sql = schema_path.read_text()
    pool = await get_pool()
    try:
        await pool.execute(sql)
        print("Codios schema applied.")
    except Exception as e:
        print(f"Schema apply warning (may already exist): {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await _apply_schema()
    if get_settings().vpc_mode:
        from services.license import get_license
        get_license()  # logs license status on startup
    await get_redis()  # warm up connection; None = no Redis, that's fine
    start_flush_task()
    start_scheduler()
    yield
    await stop_scheduler()
    await stop_flush_task()
    await close_redis()
    await close_pool()


settings = get_settings()

app = FastAPI(
    title="Codios — A2A Agent Security Layer",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.vpc_mode else None,
    redoc_url="/redoc" if settings.vpc_mode else None,
)

origins = [o.strip() for o in settings.allowed_origins.split(",")]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(agents.router)
app.include_router(contracts.router)
app.include_router(audit.router)
app.include_router(keys.router)
app.include_router(nonces.router)
app.include_router(billing.router)
app.include_router(enforce.router)
app.include_router(policies.router)
app.include_router(alert_rules.router)
app.include_router(sso.router)
app.include_router(team.router)
