from beanie import Document
from pydantic import Field
from typing import Optional
from datetime import datetime, timezone
from enum import Enum


class SyncJobStatus(str, Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class SyncTrigger(str, Enum):
    MANUAL = "manual"
    SCHEDULED = "scheduled"


class SyncJob(Document):
    triggered_by: SyncTrigger = SyncTrigger.MANUAL
    status: SyncJobStatus = SyncJobStatus.RUNNING
    rules_pulled: int = 0
    rules_new: int = 0
    rules_updated: int = 0
    rules_skipped: int = 0
    errors: list[str] = []
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None

    class Settings:
        name = "sync_jobs"
        indexes = ["status", "started_at"]
