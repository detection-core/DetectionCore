from beanie import Document
from pydantic import Field
from datetime import datetime, timezone
from typing import Literal


class SIEMIntegration(Document):
    name: str
    siem_type: Literal["elasticsearch", "qradar", "crowdstrike", "splunk"]
    is_default: bool = False
    base_pipeline: Literal["ecs_windows", "ecs_linux", "custom_only", "none"] = "none"
    custom_field_mappings: dict[str, str] = {}
    logsource_field_overrides: dict[str, dict[str, str]] = {}
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Settings:
        name = "siem_integrations"
