"""
Orchestrates the DetectionHub sync and triggers the rule pipeline.
"""
import logging
from datetime import datetime, timezone
from app.services.detectionhub_client import DetectionHubClient
from app.models.sync_job import SyncJob, SyncJobStatus
from app.models.rule import DetectionRule, PipelineStatus, Severity
from app.services.pipeline_service import process_rule_async

logger = logging.getLogger(__name__)


def _map_severity(raw: str) -> Severity:
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "informational": Severity.INFORMATIONAL,
    }
    return mapping.get(str(raw).lower(), Severity.MEDIUM)


async def _get_client() -> DetectionHubClient:
    """
    Build DetectionHubClient preferring the API key stored in ScoringConfig (set via
    the Settings UI) and falling back to the .env value.
    """
    from app.models.scoring_config import ScoringConfig
    config = await ScoringConfig.find_one()
    api_key = (config.detectionhub_api_key if config else None) or None
    base_url = (config.detectionhub_base_url if config else None) or None
    return DetectionHubClient(base_url=base_url, api_key=api_key)


async def run_sync(job_id: str, today_only: bool = True):
    """Main sync coroutine — called as a background task.

    Args:
        today_only: If True, only pull rules created today (default).
                    If False, pull all rules.
    """
    from beanie import PydanticObjectId
    job = await SyncJob.get(PydanticObjectId(job_id))
    if not job:
        logger.error(f"Sync job {job_id} not found")
        return

    try:
        client = await _get_client()

        # Build date filter — default to today only
        start_date = None
        end_date = None
        if today_only:
            today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            start_date = today
            end_date = today
            logger.info(f"Syncing rules for date: {today}")

        raw_rules = await client.get_all_rules(
            start_date=start_date,
            end_date=end_date,
        )
        job.rules_pulled = len(raw_rules)

        for raw in raw_rules:
            try:
                await _upsert_rule(raw, job)
            except Exception as e:
                msg = f"Failed to upsert rule {raw.get('id', '?')}: {e}"
                logger.error(msg)
                job.errors.append(msg)

        job.status = SyncJobStatus.COMPLETED
        job.completed_at = datetime.now(timezone.utc)
        await job.save()
        logger.info(
            f"Sync completed: {job.rules_new} new, {job.rules_updated} updated, "
            f"{job.rules_skipped} skipped"
        )

    except Exception as e:
        logger.error(f"Sync failed: {e}")
        job.status = SyncJobStatus.FAILED
        job.errors.append(str(e))
        job.completed_at = datetime.now(timezone.utc)
        await job.save()


def _extract_metadata(raw: dict) -> dict:
    """Extract the nested metadata object safely."""
    return raw.get("metadata") or {}


def _parse_sigma_yaml(sigma_content: str) -> dict:
    """Parse Sigma YAML content, returning empty dict on failure."""
    try:
        import yaml
        return yaml.safe_load(sigma_content) or {}
    except Exception:
        return {}


def _extract_title_from_sigma(sigma_content: str) -> str | None:
    """Parse the title field directly from Sigma YAML content."""
    return _parse_sigma_yaml(sigma_content).get("title") or None


def _extract_tags_from_sigma(sigma_content: str) -> list[str]:
    """Parse tags list directly from Sigma YAML content."""
    tags = _parse_sigma_yaml(sigma_content).get("tags") or []
    return [str(t) for t in tags] if isinstance(tags, list) else []


def _extract_logsource_from_sigma(sigma_content: str) -> dict:
    """Parse logsource block directly from Sigma YAML content."""
    return _parse_sigma_yaml(sigma_content).get("logsource") or {}


def _extract_log_source(raw: dict) -> dict:
    """
    log_sources is a LIST of {category, product, service} objects.
    We take the first entry as the primary log source.
    """
    sources = raw.get("log_sources") or []
    if isinstance(sources, list) and sources:
        first = sources[0]
        return first if isinstance(first, dict) else {}
    return {}


async def _upsert_rule(raw: dict, job: SyncJob):
    """Insert or update a rule from a raw DetectionHub API response."""
    sigma_rule_id = raw.get("id") or raw.get("_id")
    if not sigma_rule_id:
        return

    meta = _extract_metadata(raw)
    sigma_content = raw.get("content") or ""
    sigma_parsed = _parse_sigma_yaml(sigma_content)
    title = meta.get("title") or sigma_parsed.get("title") or "Untitled Rule"
    description = meta.get("description") or sigma_parsed.get("description")
    severity = _map_severity(meta.get("level") or sigma_parsed.get("level") or "medium")
    tags = meta.get("tags") or sigma_parsed.get("tags") or []
    log_src = _extract_log_source(raw) or sigma_parsed.get("logsource") or {}

    existing = await DetectionRule.find_one(
        DetectionRule.sigma_rule_id == str(sigma_rule_id)
    )

    if existing:
        # Only re-process if content changed
        if existing.sigma_content == sigma_content:
            job.rules_skipped += 1
            return
        existing.sigma_content = sigma_content
        existing.title = title
        existing.description = description
        existing.severity = severity
        existing.tags = tags
        existing.mitre_technique_ids = _extract_mitre(tags)
        existing.pipeline_status = PipelineStatus.SYNCED  # Reset pipeline
        existing.updated_at = datetime.now(timezone.utc)
        await existing.save()
        job.rules_updated += 1
        await process_rule_async(str(existing.id))
    else:
        rule = DetectionRule(
            sigma_rule_id=str(sigma_rule_id),
            title=title,
            description=description,
            sigma_content=sigma_content,
            severity=severity,
            tags=tags,
            mitre_technique_ids=_extract_mitre(tags),
            mitre_tactic=_extract_tactic(tags),
            log_source_category=log_src.get("category"),
            log_source_product=log_src.get("product"),
            log_source_service=log_src.get("service"),
            reference_urls=_extract_refs(raw),
        )
        await rule.insert()
        job.rules_new += 1
        await process_rule_async(str(rule.id))


def _extract_mitre(tags: list[str]) -> list[str]:
    return [t.replace("attack.", "").upper() for t in tags if "attack.t" in t.lower()]


def _extract_tactic(tags: list[str]) -> str | None:
    tactic_tags = [
        t for t in tags
        if "attack." in t.lower() and not t.lower().replace("attack.", "").startswith("t")
    ]
    return tactic_tags[0].replace("attack.", "").replace("_", " ").title() if tactic_tags else None


def _extract_refs(raw: dict) -> list[str]:
    refs = []
    src = raw.get("threat_source") or {}
    if isinstance(src, dict) and src.get("url"):
        refs.append(src["url"])
    return refs
