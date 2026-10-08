import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

from app.config import settings
from app.db.session import init_db
from app.api.v1.investigations import router as investigations_router
from app.api.v1.providers import router as providers_router
from app.api.v1.health import router as health_router

# Configure structured logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
)
logger = logging.getLogger("threatlens")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting ThreatLens Threat Intelligence Engine...")
    logger.info(f"Execution Mode: {settings.PROVIDER_MODE.upper()}")
    # Initialize DB tables
    await init_db()
    logger.info("Database schema initialized.")
    yield
    logger.info("Shutting down ThreatLens Engine.")


app = FastAPI(
    title="ThreatLens API",
    description="Threat Intelligence and Infrastructure Hunting Platform",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS configuration for Frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Standardized error response handler
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": {
                "code": "VALIDATION_ERROR",
                "message": "Invalid request parameters.",
                "details": exc.errors(),
            }
        },
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.exception(f"Unhandled server error: {str(exc)}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": {
                "code": "INTERNAL_SERVER_ERROR",
                "message": str(exc),
                "details": {},
            }
        },
    )


# Include API Routers
app.include_router(investigations_router, prefix="/api/v1")
app.include_router(providers_router, prefix="/api/v1")
app.include_router(health_router, prefix="/api/v1")
