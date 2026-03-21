"""
Settings router — proxies to scoring config for frontend Settings page.
Also exposes AI/ELK connection info (non-sensitive) and SIEM integration CRUD.
"""
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from beanie import PydanticObjectId
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timezone
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
        "detectionhub_connected": bool(settings.detectionhub_email and settings.detectionhub_password),
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


# ── SIEM Integration CRUD ──────────────────────────────────────────────────

class SIEMIntegrationUpdate(BaseModel):
    name: Optional[str] = None
    base_pipeline: Optional[str] = None
    is_default: Optional[bool] = None
    custom_field_mappings: Optional[dict[str, str]] = None
    logsource_field_overrides: Optional[dict[str, dict[str, str]]] = None


class SIEMIntegrationCreate(BaseModel):
    name: str
    siem_type: str
    base_pipeline: str = "none"
    is_default: bool = False
    custom_field_mappings: dict[str, str] = {}
    logsource_field_overrides: dict[str, dict[str, str]] = {}


@router.get("/siem-integrations", response_model=ApiResponse[list])
async def list_siem_integrations(admin: AdminUser = Depends(get_current_admin)):
    """List all SIEM integration configurations."""
    from app.models.siem_integration import SIEMIntegration
    integrations = await SIEMIntegration.find_all().to_list()
    return ApiResponse.ok(data=[_siem_out(s) for s in integrations])


@router.get("/siem-integrations/{integration_id}", response_model=ApiResponse[dict])
async def get_siem_integration(
    integration_id: str,
    admin: AdminUser = Depends(get_current_admin),
):
    """Get a single SIEM integration by ID."""
    from app.models.siem_integration import SIEMIntegration
    siem = await SIEMIntegration.get(PydanticObjectId(integration_id))
    if not siem:
        return JSONResponse(status_code=404, content={"success": False, "message": "SIEM integration not found"})
    return ApiResponse.ok(data=_siem_out(siem))


@router.put("/siem-integrations/{integration_id}", response_model=ApiResponse[dict])
async def update_siem_integration(
    integration_id: str,
    body: SIEMIntegrationUpdate,
    admin: AdminUser = Depends(get_current_admin),
):
    """Update a SIEM integration. If is_default=True, demotes all others first."""
    from app.models.siem_integration import SIEMIntegration
    from beanie.odm.operators.update.general import Set

    siem = await SIEMIntegration.get(PydanticObjectId(integration_id))
    if not siem:
        return JSONResponse(status_code=404, content={"success": False, "message": "SIEM integration not found"})

    update_data = body.model_dump(exclude_none=True)

    if update_data.get("is_default") is True:
        # Atomically demote all other defaults
        await SIEMIntegration.find(SIEMIntegration.is_default == True).update(
            Set({SIEMIntegration.is_default: False})
        )

    for field, value in update_data.items():
        setattr(siem, field, value)
    siem.updated_at = datetime.now(timezone.utc)
    await siem.save()

    return ApiResponse.ok(data=_siem_out(siem))


@router.post("/siem-integrations", response_model=ApiResponse[dict], status_code=201)
async def create_siem_integration(
    body: SIEMIntegrationCreate,
    admin: AdminUser = Depends(get_current_admin),
):
    """Create a new SIEM integration."""
    from app.models.siem_integration import SIEMIntegration
    from beanie.odm.operators.update.general import Set

    valid_siem_types = {"elasticsearch", "qradar", "crowdstrike", "splunk"}
    valid_pipelines = {"ecs_windows", "ecs_linux", "custom_only", "none"}

    if body.siem_type not in valid_siem_types:
        return JSONResponse(status_code=400, content={"success": False, "message": f"Invalid siem_type. Must be one of: {', '.join(valid_siem_types)}"})
    if body.base_pipeline not in valid_pipelines:
        return JSONResponse(status_code=400, content={"success": False, "message": f"Invalid base_pipeline. Must be one of: {', '.join(valid_pipelines)}"})

    if body.is_default:
        await SIEMIntegration.find(SIEMIntegration.is_default == True).update(
            Set({SIEMIntegration.is_default: False})
        )

    siem = SIEMIntegration(
        name=body.name,
        siem_type=body.siem_type,
        base_pipeline=body.base_pipeline,
        is_default=body.is_default,
        custom_field_mappings=body.custom_field_mappings,
        logsource_field_overrides=body.logsource_field_overrides,
    )
    await siem.insert()
    return ApiResponse.ok(data=_siem_out(siem), message="SIEM integration created")


def _siem_out(siem) -> dict:
    return {
        "id": str(siem.id),
        "name": siem.name,
        "siem_type": siem.siem_type,
        "is_default": siem.is_default,
        "base_pipeline": siem.base_pipeline,
        "custom_field_mappings": siem.custom_field_mappings,
        "logsource_field_overrides": siem.logsource_field_overrides,
        "updated_at": siem.updated_at.isoformat() if siem.updated_at else None,
    }
