from beanie import Document
from pydantic import Field
from typing import Optional
from datetime import datetime, timezone


class LogSource(Document):
    category: str  # e.g., process_creation, network_connection
    product: str   # e.g., windows, linux
    service: Optional[str] = None  # e.g., sysmon, security

    elk_index_pattern: Optional[str] = None  # e.g., winlogbeat-*
    is_available: bool = True
    record_count: Optional[int] = None
    last_seen: Optional[datetime] = None
    notes: Optional[str] = None

    uploaded_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Settings:
        name = "log_sources"
        indexes = [
            [("category", 1), ("product", 1), ("service", 1)],
        ]

    @property
    def key(self) -> str:
        parts = [self.category, self.product]
        if self.service:
            parts.append(self.service)
        return "/".join(parts)
