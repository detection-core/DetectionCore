from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional
from pathlib import Path

# Resolve .env relative to this file so it works regardless of CWD
_ENV_FILE = Path(__file__).resolve().parents[2] / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=str(_ENV_FILE), extra="ignore")

    # App
    app_name: str = "DetectionCore"
    app_version: str = "0.1.0"
    debug: bool = False

    # MongoDB
    mongodb_uri: str = "mongodb://localhost:27017"
    mongodb_db: str = "detectioncore"

    # JWT
    secret_key: str = "change-me-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 480  # 8 hours for on-prem analysts

    # Default admin (seeded on first run)
    admin_username: str = "admin"
    admin_password: str = "DetectionCore@2024!"
    admin_email: str = "admin@detectioncore.local"

    # DetectionHub
    detectionhub_base_url: str = "https://detectionhub.ai"
    detectionhub_email: Optional[str] = None
    detectionhub_password: Optional[str] = None

    # ELK
    elk_host: str = "localhost"
    elk_port: int = 9200
    elk_api_key: Optional[str] = None
    elk_username: Optional[str] = None
    elk_password: Optional[str] = None
    elk_use_ssl: bool = False
    elk_index_prefix: str = "detectioncore"
    kibana_url: Optional[str] = None  # e.g. http://localhost:5601 — defaults to http://{elk_host}:5601

    # AI Providers
    gemini_api_key: Optional[str] = None
    openrouter_api_key: Optional[str] = None
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    anthropic_api_key: Optional[str] = None
    default_ai_provider: str = "gemini"  # gemini | openrouter | anthropic
    default_ai_model: str = "gemini-2.0-flash"

    # Sync schedule (cron expression)
    sync_cron: str = "0 6 * * *"  # daily at 06:00
    sync_enabled: bool = True


settings = Settings()
