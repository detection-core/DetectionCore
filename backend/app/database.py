from beanie import init_beanie
from motor.motor_asyncio import AsyncIOMotorClient
from app.config import settings
import logging

logger = logging.getLogger(__name__)

client: AsyncIOMotorClient = None


async def init_db():
    global client
    from app.models.rule import DetectionRule
    from app.models.intake_item import IntakeItem
    from app.models.log_source import LogSource
    from app.models.sync_job import SyncJob
    from app.models.scoring_config import ScoringConfig
    from app.models.admin_user import AdminUser

    client = AsyncIOMotorClient(settings.mongodb_uri)
    await init_beanie(
        database=client[settings.mongodb_db],
        document_models=[
            DetectionRule,
            IntakeItem,
            LogSource,
            SyncJob,
            ScoringConfig,
            AdminUser,
        ],
    )
    logger.info(f"Connected to MongoDB: {settings.mongodb_db}")
    await _seed_defaults()


async def _seed_defaults():
    from app.models.admin_user import AdminUser
    from app.core.security import hash_password
    from app.models.scoring_config import ScoringConfig

    # Seed admin user
    existing = await AdminUser.find_one(AdminUser.username == settings.admin_username)
    if not existing:
        admin = AdminUser(
            username=settings.admin_username,
            email=settings.admin_email,
            password_hash=hash_password(settings.admin_password),
        )
        await admin.insert()
        logger.info("Seeded default admin user")

    # Seed scoring config singleton
    config = await ScoringConfig.find_one()
    if not config:
        config = ScoringConfig()
        await config.insert()
        logger.info("Seeded default scoring config")
    else:
        # Migrate stale base URL (old default was api.detectionhub.ai)
        if config.detectionhub_base_url == "https://api.detectionhub.ai":
            config.detectionhub_base_url = "https://detectionhub.ai"
            await config.save()
            logger.info("Migrated detectionhub_base_url to https://detectionhub.ai")


async def close_db():
    global client
    if client:
        client.close()
