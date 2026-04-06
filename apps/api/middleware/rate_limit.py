from __future__ import annotations

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from packages.infra.cache.redis import get_redis

log = structlog.get_logger(__name__)
RATE_LIMITS = {"default": 60, "/auth/register": 5, "/auth/api-keys": 10, "/scans": 20}


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        redis = await get_redis()
        client_ip = request.client.host if request.client else "unknown"
        path = request.url.path
        limit = RATE_LIMITS.get(path, RATE_LIMITS["default"])
        key = f"ratelimit:{client_ip}:{path}"
        current = await redis.incr(key)
        if current == 1:
            await redis.expire(key, 60)
        if current > limit:
            log.warning("api.rate_limit.exceeded", ip=client_ip, path=path)
            return JSONResponse(
                status_code=429,
                content={
                    "error": "rate_limit_exceeded",
                    "detail": f"Limite de {limit} req/min atingido.",
                    "retry_after": 60,
                },
                headers={"Retry-After": "60"},
            )
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, limit - current))
        return response
