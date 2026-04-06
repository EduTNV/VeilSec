from fastapi import APIRouter

from packages.infra.cache.redis import get_redis
from packages.infra.database.connection import engine
from packages.shared.settings import get_settings

router = APIRouter()
settings = get_settings()


@router.get("/health")
async def health():
    return {"status": "ok", "version": settings.version}


@router.get("/health/deep")
async def deep_health():
    checks = {}
    try:
        async with engine.connect() as conn:
            await conn.execute("SELECT 1")
        checks["database"] = "ok"
    except Exception:
        checks["database"] = "error"
    try:
        redis = await get_redis()
        await redis.ping()
        checks["redis"] = "ok"
    except Exception:
        checks["redis"] = "error"
    overall = "ok" if all(v == "ok" for v in checks.values()) else "degraded"
    from fastapi.responses import JSONResponse

    return JSONResponse(
        status_code=200 if overall == "ok" else 503, content={"status": overall, "checks": checks}
    )
