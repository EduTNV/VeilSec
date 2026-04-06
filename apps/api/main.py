from __future__ import annotations

from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from packages.infra.database.connection import engine
from packages.shared.logging import setup_logging
from packages.shared.settings import get_settings

from .middleware.audit import AuditMiddleware
from .middleware.rate_limit import RateLimitMiddleware
from .middleware.request_id import RequestIDMiddleware
from .middleware.security_headers import SecurityHeadersMiddleware
from .routes import auth, health, projects, reports, scans

settings = get_settings()
log = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging(settings.environment)
    log.info("api.starting", version=settings.version, env=settings.environment)
    yield
    log.info("api.shutting_down")
    await engine.dispose()


app = FastAPI(
    title="VeilSec API",
    version=settings.version,
    docs_url="/docs" if settings.is_development else None,
    redoc_url=None,
    openapi_url="/openapi.json" if settings.is_development else None,
    lifespan=lifespan,
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(AuditMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(RequestIDMiddleware)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422, content={"error": "validation_error", "detail": exc.errors()}
    )


@app.exception_handler(Exception)
async def generic_error_handler(request, exc: Exception):
    log.error(
        "api.unhandled_exception",
        error_type=type(exc).__name__,
        request_id=getattr(request.state, "request_id", None),
    )
    return JSONResponse(
        status_code=500, content={"error": "internal_error", "detail": "Erro interno do servidor."}
    )


app.include_router(health.router, tags=["Health"])
app.include_router(auth.router, prefix="/auth", tags=["Auth"])
app.include_router(projects.router, prefix="/projects", tags=["Projects"])
app.include_router(scans.router, prefix="/scans", tags=["Scans"])
app.include_router(reports.router, prefix="/reports", tags=["Reports"])
