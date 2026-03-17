"""
Orchestrates the full rule processing pipeline:
  SYNCED → CONVERTED → ENHANCED → TESTED → SCORED → QUEUED
"""
import logging
from datetime import datetime, timezone
from beanie import PydanticObjectId
from app.models.rule import DetectionRule, PipelineStatus
from app.models.intake_item import IntakeItem, IntakeStatus

logger = logging.getLogger(__name__)


async def process_rule_async(rule_id: str):
    """Full pipeline processing for a single rule (async background task)."""
    try:
        rule = await DetectionRule.get(PydanticObjectId(rule_id))
        if not rule:
            logger.error(f"Rule {rule_id} not found for pipeline processing")
            return

        # Stage 1: Convert SIGMA → ELK
        rule = await _stage_convert(rule)
        if rule.pipeline_status == PipelineStatus.FAILED:
            return

        # Stage 2: AI Enhancement
        rule = await _stage_enhance(rule)

        # Stage 3: Generate Unit Tests
        rule = await _stage_test(rule)

        # Stage 4: Enrich Metadata
        rule = await _stage_metadata(rule)

        # Stage 5: Score
        rule = await _stage_score(rule)

        # Stage 6: Add to In-Take Queue
        await _stage_queue(rule)

    except Exception as e:
        logger.error(f"Pipeline failed for rule {rule_id}: {e}")
        try:
            rule = await DetectionRule.get(PydanticObjectId(rule_id))
            if rule:
                rule.pipeline_status = PipelineStatus.FAILED
                rule.pipeline_error = str(e)
                rule.updated_at = datetime.now(timezone.utc)
                await rule.save()
        except Exception:
            pass


async def _stage_convert(rule: DetectionRule) -> DetectionRule:
    from app.services.sigma_converter import convert_sigma_to_elk
    try:
        result = convert_sigma_to_elk(rule.sigma_content)
        if result.success:
            rule.elk_query = result.elk_query
            rule.elk_rule_json = result.elk_rule_json
            rule.pipeline_status = PipelineStatus.CONVERTED
        else:
            rule.pipeline_status = PipelineStatus.FAILED
            rule.pipeline_error = f"Conversion failed: {result.error}"
        rule.updated_at = datetime.now(timezone.utc)
        await rule.save()
    except Exception as e:
        rule.pipeline_status = PipelineStatus.FAILED
        rule.pipeline_error = str(e)
        await rule.save()
    return rule


async def _stage_enhance(rule: DetectionRule) -> DetectionRule:
    if rule.pipeline_status == PipelineStatus.FAILED or not rule.elk_query:
        return rule
    from app.services.ai_enhancer import enhance_rule
    try:
        result = await enhance_rule(
            sigma_content=rule.sigma_content,
            elk_query=rule.elk_query,
            title=rule.title,
            severity=rule.severity,
            mitre_ids=rule.mitre_technique_ids,
        )
        if result.get("improved_query"):
            rule.elk_query = result["improved_query"]
            if rule.elk_rule_json:
                rule.elk_rule_json["query"] = result["improved_query"]
        rule.ai_enhancement_notes = result.get("enhancement_notes")
        rule.pipeline_status = PipelineStatus.ENHANCED
        rule.updated_at = datetime.now(timezone.utc)
        await rule.save()
    except Exception as e:
        logger.warning(f"Enhancement failed for {rule.id}, continuing: {e}")
        rule.pipeline_status = PipelineStatus.ENHANCED  # Non-blocking
        await rule.save()
    return rule


async def _stage_test(rule: DetectionRule) -> DetectionRule:
    if rule.pipeline_status == PipelineStatus.FAILED:
        return rule
    from app.services.unit_test_generator import generate_unit_tests
    try:
        tests = await generate_unit_tests(
            title=rule.title,
            sigma_content=rule.sigma_content,
            elk_query=rule.elk_query or "",
            severity=rule.severity,
            mitre_ids=rule.mitre_technique_ids,
        )
        rule.unit_tests = tests
        rule.pipeline_status = PipelineStatus.TESTED
        rule.updated_at = datetime.now(timezone.utc)
        await rule.save()
    except Exception as e:
        logger.warning(f"Test generation failed for {rule.id}, continuing: {e}")
        rule.pipeline_status = PipelineStatus.TESTED
        await rule.save()
    return rule


async def _stage_metadata(rule: DetectionRule) -> DetectionRule:
    if rule.pipeline_status == PipelineStatus.FAILED:
        return rule
    from app.services.metadata_enricher import enrich_metadata
    try:
        meta = await enrich_metadata(
            title=rule.title,
            sigma_content=rule.sigma_content,
            mitre_ids=rule.mitre_technique_ids,
            threat_actors=rule.threat_actors,
            targeted_industries=rule.targeted_industries,
        )
        if meta.get("verified_mitre_ids"):
            rule.mitre_technique_ids = meta["verified_mitre_ids"]
        if meta.get("mitre_tactic"):
            rule.mitre_tactic = meta["mitre_tactic"]
        if meta.get("detection_author"):
            rule.ai_metadata_author = meta["detection_author"]
        if meta.get("public_references"):
            rule.reference_urls = list(set(rule.reference_urls + meta["public_references"]))
        rule.updated_at = datetime.now(timezone.utc)
        await rule.save()
    except Exception as e:
        logger.warning(f"Metadata enrichment failed for {rule.id}, continuing: {e}")
    return rule


async def _stage_score(rule: DetectionRule) -> DetectionRule:
    if rule.pipeline_status == PipelineStatus.FAILED:
        return rule
    from app.services.scoring_engine import score_rule
    try:
        scoring = await score_rule(rule)
        rule.scoring = scoring
        rule.pipeline_status = PipelineStatus.SCORED
        rule.updated_at = datetime.now(timezone.utc)
        await rule.save()
    except Exception as e:
        logger.warning(f"Scoring failed for {rule.id}: {e}")
        rule.pipeline_status = PipelineStatus.SCORED
        await rule.save()
    return rule


async def _stage_queue(rule: DetectionRule):
    if rule.pipeline_status == PipelineStatus.FAILED:
        return
    try:
        # Check if already in queue
        existing = await IntakeItem.find_one(IntakeItem.rule.id == rule.id)
        if not existing:
            item = IntakeItem(
                rule=rule,
                score=rule.scoring.total_score,
            )
            await item.insert()

        rule.pipeline_status = PipelineStatus.QUEUED
        rule.updated_at = datetime.now(timezone.utc)
        await rule.save()
    except Exception as e:
        logger.error(f"Queue insert failed for {rule.id}: {e}")
