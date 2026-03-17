from beanie import Document
from pydantic import Field
from typing import Optional
from datetime import datetime, timezone


class ScoringConfig(Document):
    # Client context
    client_name: Optional[str] = None
    client_industry: Optional[str] = None
    client_regions: list[str] = []
    client_asset_types: list[str] = []
    threat_actor_watchlist: list[str] = []

    # Scoring weights (must sum to 100)
    weight_log_availability: float = 30.0
    weight_industry_match: float = 20.0
    weight_region_match: float = 15.0
    weight_severity: float = 20.0
    weight_threat_actor: float = 10.0
    weight_asset_type: float = 5.0

    # AI provider
    ai_provider: str = "gemini"  # gemini | openrouter
    ai_model: str = "gemini-2.0-flash"

    # DetectionHub connection
    detectionhub_api_key: Optional[str] = None
    detectionhub_base_url: str = "https://detectionhub.ai"

    # ELK connection
    elk_host: str = "localhost"
    elk_port: int = 9200
    elk_api_key: Optional[str] = None
    elk_username: Optional[str] = None
    elk_password: Optional[str] = None
    elk_use_ssl: bool = False

    # Sync schedule
    sync_cron: str = "0 6 * * *"
    sync_enabled: bool = True

    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Settings:
        name = "scoring_config"
