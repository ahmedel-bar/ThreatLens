from fastapi import APIRouter
from pydantic import BaseModel
from typing import Dict, Any
from app.config import settings
from app.schemas.ioc import IOCDetectionResult
from app.services.ioc import process_ioc_input

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    status: str
    project: str
    environment: str
    provider_mode: str
    max_pivot_depth: int
    database: str


class DetectRequest(BaseModel):
    ioc: str


@router.get("/health", response_model=HealthResponse)
async def health_check():
    return HealthResponse(
        status="healthy",
        project=settings.PROJECT_NAME,
        environment=settings.ENVIRONMENT,
        provider_mode=settings.PROVIDER_MODE,
        max_pivot_depth=settings.MAX_PIVOT_DEPTH,
        database="connected",
    )


@router.post("/detect", response_model=IOCDetectionResult)
async def detect_ioc(req: DetectRequest):
    """Real-time IOC detection and normalization utility."""
    return process_ioc_input(req.ioc)
