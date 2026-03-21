from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.database import init_db, close_db
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Starting {settings.app_name} v{settings.app_version}")
    await init_db()
    app.state.reconvert_job = {
        "status": "idle",
        "total": 0,
        "done": 0,
        "errors": 0,
        "started_at": None,
        "finished_at": None,
    }
    _start_scheduler()
    yield
    await close_db()
    logger.info("Shutdown complete")


def _start_scheduler():
    if not settings.sync_enabled:
        return
    try:
        from apscheduler.schedulers.asyncio import AsyncIOScheduler
        from apscheduler.triggers.cron import CronTrigger
        from app.services.sync_service import run_sync
        from app.models.sync_job import SyncJob, SyncTrigger

        async def _scheduled_sync():
            job = SyncJob(triggered_by=SyncTrigger.SCHEDULED)
            await job.insert()
            await run_sync(str(job.id))

        scheduler = AsyncIOScheduler()
        cron_parts = settings.sync_cron.split()
        if len(cron_parts) == 5:
            minute, hour, day, month, day_of_week = cron_parts
            scheduler.add_job(
                _scheduled_sync,
                CronTrigger(
                    minute=minute, hour=hour,
                    day=day, month=month, day_of_week=day_of_week,
                ),
            )
        scheduler.start()
        logger.info(f"Scheduler started with cron: {settings.sync_cron}")
    except Exception as e:
        logger.warning(f"Scheduler could not start: {e}")


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="On-premises detection engineering platform",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict in production to frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
from app.routers import auth, sync, rules, intake, log_sources, elk, scoring, dashboard, settings as settings_router

app.include_router(auth.router)
app.include_router(sync.router)
app.include_router(rules.router)
app.include_router(intake.router)
app.include_router(log_sources.router)
app.include_router(elk.router)
app.include_router(scoring.router)
app.include_router(dashboard.router)
app.include_router(settings_router.router)


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "ok", "app": settings.app_name, "version": settings.app_version}
