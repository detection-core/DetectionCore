from beanie import Document, Link
from pydantic import Field
from typing import Optional
from datetime import datetime, timezone
from enum import Enum
from app.models.rule import DetectionRule


class IntakeStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    IMPLEMENTED = "implemented"
    DEFERRED = "deferred"


class IntakeItem(Document):
    rule: Link[DetectionRule]
    score: float = 0.0  # Cached from rule scoring at queue time
    priority_rank: int = 0

    status: IntakeStatus = IntakeStatus.PENDING
    implementation_notes: Optional[str] = None
    tuning_notes: Optional[str] = None
    test_passed: bool = False
    assigned_to: Optional[str] = None
    assigned_at: Optional[datetime] = None

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Settings:
        name = "intake_items"
        indexes = ["score", "status", "priority_rank"]
