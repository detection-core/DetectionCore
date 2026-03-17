from fastapi import APIRouter, Depends, BackgroundTasks
from app.core.dependencies import get_current_admin
from app.models.admin_user import AdminUser
from app.models.sync_job import SyncJob, SyncJobStatus
from app.schemas.base import ApiResponse, PaginatedResponse
from app.services.sync_service import run_sync
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

router = APIRouter(prefix="/sync", tags=["Sync"])


class SyncJobOut(BaseModel):
    id: str
    triggered_by: str
    status: str
    rules_pulled: int
    rules_new: int
    rules_updated: int
    rules_skipped: int
    errors: list[str]
    started_at: datetime
    completed_at: Optional[datetime]


@router.post("/trigger", response_model=ApiResponse[SyncJobOut])
async def trigger_sync(
    background_tasks: BackgroundTasks,
    today_only: bool = True,
    admin: AdminUser = Depends(get_current_admin),
):
    """Manually trigger a DetectionHub sync.

    - `today_only=true` (default): pull only rules created today.
    - `today_only=false`: pull all rules (full historical sync).
    """
    from app.models.sync_job import SyncTrigger
    job = SyncJob(triggered_by=SyncTrigger.MANUAL)
    await job.insert()
    background_tasks.add_task(run_sync, str(job.id), today_only)
    return ApiResponse.ok(
        data=_job_out(job),
        message=f"Sync started ({'today only' if today_only else 'all rules'})",
    )


@router.get("/jobs", response_model=ApiResponse[list[SyncJobOut]])
async def list_jobs(
    limit: int = 20,
    admin: AdminUser = Depends(get_current_admin),
):
    """List recent sync jobs."""
    jobs = await SyncJob.find_all().sort(-SyncJob.started_at).limit(limit).to_list()
    return ApiResponse.ok(data=[_job_out(j) for j in jobs])


@router.get("/jobs/{job_id}", response_model=ApiResponse[SyncJobOut])
async def get_job(job_id: str, admin: AdminUser = Depends(get_current_admin)):
    """Get a specific sync job by ID."""
    from beanie import PydanticObjectId
    from app.core.exceptions import NotFoundError
    job = await SyncJob.get(PydanticObjectId(job_id))
    if not job:
        raise NotFoundError("Sync job")
    return ApiResponse.ok(data=_job_out(job))


@router.get("/status", response_model=ApiResponse[dict])
async def sync_status(admin: AdminUser = Depends(get_current_admin)):
    """Get current sync configuration and last run info."""
    from app.config import settings
    from app.models.scoring_config import ScoringConfig
    config = await ScoringConfig.find_one()
    last_job = await SyncJob.find_all().sort(-SyncJob.started_at).first_or_none()
    return ApiResponse.ok(data={
        "sync_enabled": config.sync_enabled if config else settings.sync_enabled,
        "sync_cron": config.sync_cron if config else settings.sync_cron,
        "detectionhub_configured": bool(config.detectionhub_api_key if config else settings.detectionhub_api_key),
        "last_sync": last_job.started_at if last_job else None,
        "last_status": last_job.status if last_job else None,
    })


def _job_out(job: SyncJob) -> SyncJobOut:
    return SyncJobOut(
        id=str(job.id),
        triggered_by=job.triggered_by,
        status=job.status,
        rules_pulled=job.rules_pulled,
        rules_new=job.rules_new,
        rules_updated=job.rules_updated,
        rules_skipped=job.rules_skipped,
        errors=job.errors,
        started_at=job.started_at,
        completed_at=job.completed_at,
    )
