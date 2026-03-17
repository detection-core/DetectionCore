from fastapi import APIRouter, Depends, BackgroundTasks
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timezone
from app.core.dependencies import get_current_admin
from app.models.admin_user import AdminUser
from app.models.scoring_config import ScoringConfig
from app.schemas.base import ApiResponse

router = APIRouter(prefix="/scoring", tags=["Scoring"])


class ScoringConfigOut(BaseModel):
    client_name: Optional[str]
    client_industry: Optional[str]
    client_regions: list[str]
    client_asset_types: list[str]
    threat_actor_watchlist: list[str]
    weight_log_availability: float
    weight_industry_match: float
    weight_region_match: float
    weight_severity: float
    weight_threat_actor: float
    weight_asset_type: float
    ai_provider: str
    ai_model: str
    detectionhub_base_url: str
    elk_host: str
    elk_port: int
    elk_use_ssl: bool
    sync_cron: str
    sync_enabled: bool


class ScoringConfigUpdate(BaseModel):
    client_name: Optional[str] = None
    client_industry: Optional[str] = None
    client_regions: Optional[list[str]] = None
    client_asset_types: Optional[list[str]] = None
    threat_actor_watchlist: Optional[list[str]] = None
    weight_log_availability: Optional[float] = None
    weight_industry_match: Optional[float] = None
    weight_region_match: Optional[float] = None
    weight_severity: Optional[float] = None
    weight_threat_actor: Optional[float] = None
    weight_asset_type: Optional[float] = None
    ai_provider: Optional[str] = None
    ai_model: Optional[str] = None
    detectionhub_api_key: Optional[str] = None
    detectionhub_base_url: Optional[str] = None
    elk_host: Optional[str] = None
    elk_port: Optional[int] = None
    elk_api_key: Optional[str] = None
    elk_username: Optional[str] = None
    elk_password: Optional[str] = None
    elk_use_ssl: Optional[bool] = None
    sync_cron: Optional[str] = None
    sync_enabled: Optional[bool] = None


@router.get("/config", response_model=ApiResponse[ScoringConfigOut])
async def get_config(admin: AdminUser = Depends(get_current_admin)):
    config = await ScoringConfig.find_one()
    if not config:
        config = ScoringConfig()
        await config.insert()
    return ApiResponse.ok(data=ScoringConfigOut(**config.model_dump()))


@router.put("/config", response_model=ApiResponse[ScoringConfigOut])
async def update_config(
    body: ScoringConfigUpdate,
    admin: AdminUser = Depends(get_current_admin),
):
    config = await ScoringConfig.find_one()
    if not config:
        config = ScoringConfig()

    for field, value in body.model_dump(exclude_none=True).items():
        setattr(config, field, value)

    # Validate weights sum to ~100
    weights = [
        config.weight_log_availability,
        config.weight_industry_match,
        config.weight_region_match,
        config.weight_severity,
        config.weight_threat_actor,
        config.weight_asset_type,
    ]
    total_weight = sum(weights)
    if abs(total_weight - 100.0) > 5.0:
        from app.core.exceptions import BadRequestError
        raise BadRequestError(f"Scoring weights must sum to 100 (currently {total_weight:.1f})")

    config.updated_at = datetime.now(timezone.utc)
    await config.save()
    return ApiResponse.ok(data=ScoringConfigOut(**config.model_dump()), message="Config updated")


@router.post("/recalculate-all", response_model=ApiResponse[dict])
async def recalculate_all_scores(
    background_tasks: BackgroundTasks,
    admin: AdminUser = Depends(get_current_admin),
):
    """Recalculate scores for all rules using current config."""
    background_tasks.add_task(_recalculate_all)
    return ApiResponse.ok(data={}, message="Score recalculation started in background")


async def _recalculate_all():
    from app.models.rule import DetectionRule, PipelineStatus
    from app.services.scoring_engine import score_rule
    from datetime import timezone
    import logging
    logger = logging.getLogger(__name__)

    count = 0
    async for rule in DetectionRule.find(
        DetectionRule.pipeline_status != PipelineStatus.FAILED
    ):
        try:
            scoring = await score_rule(rule)
            rule.scoring = scoring
            rule.updated_at = datetime.now(timezone.utc)
            await rule.save()
            count += 1
        except Exception as e:
            logger.error(f"Score recalc failed for {rule.id}: {e}")
    logger.info(f"Recalculated scores for {count} rules")
