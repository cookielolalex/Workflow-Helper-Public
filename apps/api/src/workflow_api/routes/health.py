from typing import Annotated

from fastapi import APIRouter, Depends

from ..config import Settings, get_settings
from ..models import HealthResponse

router = APIRouter(tags=["health"])
SettingsDependency = Annotated[Settings, Depends(get_settings)]


@router.get("/health", response_model=HealthResponse)
async def health(settings: SettingsDependency) -> HealthResponse:
    return HealthResponse(status="ok", service="workflow-helper-api", environment=settings.environment)
