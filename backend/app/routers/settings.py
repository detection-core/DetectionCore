"""
Settings router — proxies to scoring config for frontend Settings page.
Also exposes AI/ELK connection info (non-sensitive).
"""
from fastapi import APIRouter, Depends
from app.core.dependencies import get_current_admin
from app.models.admin_user import AdminUser
from app.schemas.base import ApiResponse
from app.config import settings

router = APIRouter(prefix="/settings", tags=["Settings"])


@router.get("", response_model=ApiResponse[dict])
async def get_settings(admin: AdminUser = Depends(get_current_admin)):
    """Return current platform settings (non-sensitive)."""
    from app.models.scoring_config import ScoringConfig
    config = await ScoringConfig.find_one()
    return ApiResponse.ok(data={
        "app_name": settings.app_name,
        "app_version": settings.app_version,
        "detectionhub_base_url": config.detectionhub_base_url if config else settings.detectionhub_base_url,
        "detectionhub_connected": bool(config.detectionhub_api_key if config else settings.detectionhub_api_key),
        "elk_host": config.elk_host if config else settings.elk_host,
        "elk_port": config.elk_port if config else settings.elk_port,
        "elk_use_ssl": config.elk_use_ssl if config else settings.elk_use_ssl,
        "ai_provider": config.ai_provider if config else settings.default_ai_provider,
        "ai_model": config.ai_model if config else settings.default_ai_model,
        "sync_cron": config.sync_cron if config else settings.sync_cron,
        "sync_enabled": config.sync_enabled if config else settings.sync_enabled,
        "client_name": config.client_name if config else None,
        "client_industry": config.client_industry if config else None,
    })
