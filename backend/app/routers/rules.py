import asyncio
from fastapi import APIRouter, Depends, Query, BackgroundTasks, Request
from beanie import PydanticObjectId
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timezone
from app.core.dependencies import get_current_admin
from app.core.exceptions import NotFoundError
from app.models.admin_user import AdminUser
from app.models.rule import DetectionRule, PipelineStatus, Severity, UnitTest, ScoringResult, ELKDeployment
from app.schemas.base import ApiResponse, PaginatedResponse

router = APIRouter(prefix="/rules", tags=["Rules"])


class UnitTestOut(BaseModel):
    test_id: str
    test_type: str
    command: str
    description: str
    expected_alert_fired: bool
    last_run_result: str
    last_run_at: Optional[datetime]


class ScoringOut(BaseModel):
    total_score: float
    log_availability: float
    industry_match: float
    region_match: float
    severity_score: float
    threat_actor_score: float
    asset_type_score: float
    manually_overridden: bool


class ELKDeploymentOut(BaseModel):
    deployed: bool
    rule_id_elk: Optional[str]
    deployed_at: Optional[datetime]
    last_error: Optional[str]


class RuleSummaryOut(BaseModel):
    id: str
    sigma_rule_id: str
    title: str
    severity: str
    pipeline_status: str
    mitre_technique_ids: list[str]
    log_source_category: Optional[str]
    log_source_product: Optional[str]
    log_source_available: bool
    log_source_match_type: Optional[str]
    total_score: float
    threat_actors: list[str]
    targeted_industries: list[str]
    synced_at: datetime
    updated_at: datetime


class RuleDetailOut(RuleSummaryOut):
    description: Optional[str]
    sigma_content: str
    elk_query: Optional[str]
    elk_rule_json: Optional[dict]
    unit_tests: list[UnitTestOut]
    scoring: ScoringOut
    elk_deployment: ELKDeploymentOut
    ai_enhancement_notes: Optional[str]
    pipeline_error: Optional[str]
    reference_urls: list[str]


@router.get("", response_model=ApiResponse[PaginatedResponse[RuleSummaryOut]])
async def list_rules(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    status: Optional[PipelineStatus] = None,
    severity: Optional[Severity] = None,
    search: Optional[str] = None,
    min_score: Optional[float] = None,
    admin: AdminUser = Depends(get_current_admin),
):
    """List all rules with filters and pagination."""
    query_conditions = []
    if status:
        query_conditions.append(DetectionRule.pipeline_status == status)
    if severity:
        query_conditions.append(DetectionRule.severity == severity)

    base_query = DetectionRule.find(*query_conditions)
    if search:
        base_query = DetectionRule.find(
            {"$or": [
                {"title": {"$regex": search, "$options": "i"}},
                {"description": {"$regex": search, "$options": "i"}},
                {"mitre_technique_ids": {"$elemMatch": {"$regex": search, "$options": "i"}}},
            ]},
            *query_conditions,
        )

    total = await base_query.count()
    rules = (
        await base_query
        .sort(-DetectionRule.scoring.total_score)
        .skip((page - 1) * page_size)
        .limit(page_size)
        .to_list()
    )
    if min_score is not None:
        rules = [r for r in rules if r.scoring.total_score >= min_score]

    return ApiResponse.ok(data=PaginatedResponse(
        items=[_rule_summary(r) for r in rules],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    ))


async def _run_reconvert_job(app):
    """Background task: re-convert all rules using current default SIEM config."""
    import logging
    logger = logging.getLogger(__name__)
    from app.services.sigma_converter import convert_sigma_to_elk
    from app.models.siem_integration import SIEMIntegration

    try:
        siem = await SIEMIntegration.find_one(SIEMIntegration.is_default == True)
        siem_config = siem.model_dump() if siem else None

        # Count eligible rules
        # Skip only rules actively mid-pipeline (race condition risk).
        # QUEUED = placed in analyst intake queue (final pipeline state) — safe to reconvert.
        skip_statuses = {PipelineStatus.CONVERTED, PipelineStatus.ENHANCED, PipelineStatus.TESTED}
        all_rules = await DetectionRule.find(DetectionRule.sigma_content != None).to_list()
        eligible = [r for r in all_rules if r.sigma_content and r.pipeline_status not in skip_statuses]

        logger.info(f"Reconvert job: {len(eligible)} eligible rules, siem_config base_pipeline={siem_config.get('base_pipeline') if siem_config else None}")
        app.state.reconvert_job["total"] = len(eligible)

        for rule in eligible:
            try:
                result = convert_sigma_to_elk(rule.sigma_content, siem_config=siem_config)
                if result.success:
                    rule.elk_query = result.elk_query
                    rule.elk_rule_json = result.elk_rule_json
                    rule.updated_at = datetime.now(timezone.utc)
                    await rule.save()
                    app.state.reconvert_job["done"] += 1
                    logger.info(f"Reconvert OK rule {rule.id}: {result.elk_query[:80] if result.elk_query else '(empty)'}")
                else:
                    app.state.reconvert_job["errors"] += 1
                    logger.warning(f"Reconvert failed for rule {rule.id}: {result.error}")
            except Exception as e:
                app.state.reconvert_job["errors"] += 1
                logger.warning(f"Reconvert exception for rule {rule.id}: {e}")

        app.state.reconvert_job["status"] = "done"
        app.state.reconvert_job["finished_at"] = datetime.now(timezone.utc).isoformat()
    except Exception as e:
        logger.error(f"Reconvert job failed: {e}")
        app.state.reconvert_job["status"] = "error"
        app.state.reconvert_job["finished_at"] = datetime.now(timezone.utc).isoformat()


@router.post("/reconvert-all", response_model=ApiResponse[dict])
async def reconvert_all(request: Request, admin: AdminUser = Depends(get_current_admin)):
    """Start async background job to re-convert all rules with current SIEM field mapping."""
    job = request.app.state.reconvert_job
    if job.get("status") == "running":
        return ApiResponse(success=False, message="A reconvert job is already running", data=job)

    now = datetime.now(timezone.utc).isoformat()
    request.app.state.reconvert_job = {
        "status": "running",
        "total": 0,
        "done": 0,
        "errors": 0,
        "started_at": now,
        "finished_at": None,
    }
    asyncio.create_task(_run_reconvert_job(request.app))
    return ApiResponse.ok(data=request.app.state.reconvert_job, message="Reconvert job started")


@router.get("/reconvert-status", response_model=ApiResponse[dict])
async def reconvert_status(request: Request, admin: AdminUser = Depends(get_current_admin)):
    """Poll current state of the reconvert background job."""
    return ApiResponse.ok(data=request.app.state.reconvert_job)


@router.get("/{rule_id}", response_model=ApiResponse[RuleDetailOut])
async def get_rule(rule_id: str, admin: AdminUser = Depends(get_current_admin)):
    """Get full rule details including SIGMA, ELK query, tests, and scoring."""
    rule = await DetectionRule.get(PydanticObjectId(rule_id))
    if not rule:
        raise NotFoundError("Rule")
    return ApiResponse.ok(data=_rule_detail(rule))


@router.get("/{rule_id}/sigma", response_model=ApiResponse[str])
async def get_sigma(rule_id: str, admin: AdminUser = Depends(get_current_admin)):
    """Get raw SIGMA YAML content."""
    rule = await DetectionRule.get(PydanticObjectId(rule_id))
    if not rule:
        raise NotFoundError("Rule")
    return ApiResponse.ok(data=rule.sigma_content)


@router.get("/{rule_id}/elk", response_model=ApiResponse[dict])
async def get_elk(rule_id: str, admin: AdminUser = Depends(get_current_admin)):
    """Get converted ELK query and full alert rule JSON."""
    rule = await DetectionRule.get(PydanticObjectId(rule_id))
    if not rule:
        raise NotFoundError("Rule")
    return ApiResponse.ok(data={"query": rule.elk_query, "rule_json": rule.elk_rule_json})


@router.get("/{rule_id}/unit-tests", response_model=ApiResponse[list[UnitTestOut]])
async def get_unit_tests(rule_id: str, admin: AdminUser = Depends(get_current_admin)):
    """Get generated attack simulation unit tests for a rule."""
    rule = await DetectionRule.get(PydanticObjectId(rule_id))
    if not rule:
        raise NotFoundError("Rule")
    return ApiResponse.ok(data=[_test_out(t) for t in rule.unit_tests])


@router.post("/{rule_id}/reprocess", response_model=ApiResponse[RuleSummaryOut])
async def reprocess_rule(
    rule_id: str,
    background_tasks: BackgroundTasks,
    admin: AdminUser = Depends(get_current_admin),
):
    """Re-run the full pipeline for a rule."""
    rule = await DetectionRule.get(PydanticObjectId(rule_id))
    if not rule:
        raise NotFoundError("Rule")
    rule.pipeline_status = PipelineStatus.SYNCED
    rule.updated_at = datetime.now(timezone.utc)
    await rule.save()
    from app.services.pipeline_service import process_rule_async
    background_tasks.add_task(process_rule_async, rule_id)
    return ApiResponse.ok(data=_rule_summary(rule), message="Reprocessing started")


@router.post("/backfill-titles", response_model=ApiResponse[dict])
async def backfill_titles(admin: AdminUser = Depends(get_current_admin)):
    """Fix rules missing title, MITRE, and log source by parsing from Sigma YAML content."""
    from app.services.sync_service import _parse_sigma_yaml, _extract_mitre, _extract_tactic
    fixed = 0
    async for rule in DetectionRule.find_all():
        changed = False
        sigma = _parse_sigma_yaml(rule.sigma_content or "")
        if not sigma:
            continue

        if rule.title == "Untitled Rule" and sigma.get("title"):
            rule.title = sigma["title"]
            changed = True

        if not rule.mitre_technique_ids:
            tags = sigma.get("tags") or []
            mitre_ids = _extract_mitre(tags)
            if mitre_ids:
                rule.mitre_technique_ids = mitre_ids
                rule.tags = tags
                rule.mitre_tactic = _extract_tactic(tags)
                changed = True

        logsource = sigma.get("logsource") or {}
        if not rule.log_source_category and logsource.get("category"):
            rule.log_source_category = logsource.get("category")
            changed = True
        if not rule.log_source_product and logsource.get("product"):
            rule.log_source_product = logsource.get("product")
            changed = True
        if not rule.log_source_service and logsource.get("service"):
            rule.log_source_service = logsource.get("service")
            changed = True

        if changed:
            await rule.save()
            fixed += 1

    return ApiResponse.ok(data={"fixed": fixed}, message=f"Fixed {fixed} rules")


def _rule_summary(rule: DetectionRule) -> RuleSummaryOut:
    return RuleSummaryOut(
        id=str(rule.id),
        sigma_rule_id=rule.sigma_rule_id,
        title=rule.title,
        severity=rule.severity,
        pipeline_status=rule.pipeline_status,
        mitre_technique_ids=rule.mitre_technique_ids,
        log_source_category=rule.log_source_category,
        log_source_product=rule.log_source_product,
        log_source_available=rule.log_source_available,
        log_source_match_type=rule.log_source_match_type,
        total_score=rule.scoring.total_score,
        threat_actors=rule.threat_actors,
        targeted_industries=rule.targeted_industries,
        synced_at=rule.synced_at,
        updated_at=rule.updated_at,
    )


def _rule_detail(rule: DetectionRule) -> RuleDetailOut:
    return RuleDetailOut(
        **_rule_summary(rule).__dict__,
        description=rule.description,
        sigma_content=rule.sigma_content,
        elk_query=rule.elk_query,
        elk_rule_json=rule.elk_rule_json,
        unit_tests=[_test_out(t) for t in rule.unit_tests],
        scoring=ScoringOut(**rule.scoring.model_dump()),
        elk_deployment=ELKDeploymentOut(**rule.elk_deployment.model_dump()),
        ai_enhancement_notes=rule.ai_enhancement_notes,
        pipeline_error=rule.pipeline_error,
        reference_urls=rule.reference_urls,
    )


def _test_out(t: UnitTest) -> UnitTestOut:
    return UnitTestOut(
        test_id=t.test_id,
        test_type=t.test_type,
        command=t.command,
        description=t.description,
        expected_alert_fired=t.expected_alert_fired,
        last_run_result=t.last_run_result,
        last_run_at=t.last_run_at,
    )
