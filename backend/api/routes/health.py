from fastapi import APIRouter

from backend.core.config import settings
from backend.models.schemas import HealthResponse

router = APIRouter(prefix="/health", tags=["health"])


@router.get("", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="healthy", service=settings.app_name)
