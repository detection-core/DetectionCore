from fastapi import APIRouter, Depends
from app.core.dependencies import get_current_admin
from app.models.admin_user import AdminUser
from app.models.rule import DetectionRule, PipelineStatus, Severity
from app.models.intake_item import IntakeItem, IntakeStatus
from app.models.log_source import LogSource
from app.schemas.base import ApiResponse
from collections import Counter, defaultdict

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/summary", response_model=ApiResponse[dict])
async def get_summary(admin: AdminUser = Depends(get_current_admin)):
    """Overall KPIs for the dashboard."""
    total_rules = await DetectionRule.count()
    converted_statuses = [
        s.value for s in [
            PipelineStatus.CONVERTED, PipelineStatus.ENHANCED, PipelineStatus.TESTED,
            PipelineStatus.SCORED, PipelineStatus.QUEUED, PipelineStatus.IMPLEMENTED
        ]
    ]
    converted = await DetectionRule.find(
        {"pipeline_status": {"$in": converted_statuses}}
    ).count()
    implemented = await DetectionRule.find(
        {"pipeline_status": PipelineStatus.IMPLEMENTED.value}
    ).count()
    in_queue = await IntakeItem.count()
    test_passed = await IntakeItem.find({"test_passed": True}).count()
    elk_deployed = await DetectionRule.find(
        {"elk_deployment.deployed": True}
    ).count()
    failed = await DetectionRule.find(
        {"pipeline_status": PipelineStatus.FAILED.value}
    ).count()

    return ApiResponse.ok(data={
        "total_rules": total_rules,
        "converted_rules": converted,
        "implemented_rules": implemented,
        "in_queue": in_queue,
        "test_passed": test_passed,
        "elk_deployed": elk_deployed,
        "failed_pipeline": failed,
        "conversion_rate": round(converted / total_rules * 100, 1) if total_rules else 0,
        "implementation_rate": round(implemented / total_rules * 100, 1) if total_rules else 0,
        "test_pass_rate": round(test_passed / in_queue * 100, 1) if in_queue else 0,
    })


@router.get("/pipeline-funnel", response_model=ApiResponse[list[dict]])
async def get_pipeline_funnel(admin: AdminUser = Depends(get_current_admin)):
    """Count of rules at each pipeline stage."""
    stages = [
        PipelineStatus.SYNCED, PipelineStatus.CONVERTED, PipelineStatus.ENHANCED,
        PipelineStatus.TESTED, PipelineStatus.SCORED, PipelineStatus.QUEUED,
        PipelineStatus.IMPLEMENTED, PipelineStatus.FAILED,
    ]
    result = []
    for stage in stages:
        count = await DetectionRule.find(DetectionRule.pipeline_status == stage).count()
        result.append({"stage": stage.value, "count": count})
    return ApiResponse.ok(data=result)


@router.get("/severity-distribution", response_model=ApiResponse[list[dict]])
async def get_severity_distribution(admin: AdminUser = Depends(get_current_admin)):
    """Count of rules by severity."""
    result = []
    for severity in Severity:
        count = await DetectionRule.find(DetectionRule.severity == severity).count()
        result.append({"severity": severity.value, "count": count})
    return ApiResponse.ok(data=result)


@router.get("/mitre-coverage", response_model=ApiResponse[list[dict]])
async def get_mitre_coverage(admin: AdminUser = Depends(get_current_admin)):
    """MITRE technique coverage — top 20 techniques by rule count."""
    technique_counts: Counter = Counter()
    async for rule in DetectionRule.find_all():
        for tid in rule.mitre_technique_ids:
            technique_counts[tid] += 1
    top = technique_counts.most_common(20)
    return ApiResponse.ok(data=[{"technique_id": t, "count": c} for t, c in top])


@router.get("/log-source-gaps", response_model=ApiResponse[list[dict]])
async def get_log_source_gaps(admin: AdminUser = Depends(get_current_admin)):
    """Rules blocked due to missing log sources."""
    gap_counts: Counter = Counter()
    async for rule in DetectionRule.find({"log_source_available": False}):
        key = "/".join(filter(None, [rule.log_source_category, rule.log_source_product, rule.log_source_service]))
        if key:
            gap_counts[key] += 1
    return ApiResponse.ok(data=[
        {"log_source": k, "blocked_rules": c}
        for k, c in gap_counts.most_common(20)
    ])


@router.get("/score-distribution", response_model=ApiResponse[list[dict]])
async def get_score_distribution(admin: AdminUser = Depends(get_current_admin)):
    """Score distribution in 10-point buckets."""
    buckets = defaultdict(int)
    async for rule in DetectionRule.find_all():
        bucket = int(rule.scoring.total_score // 10) * 10
        buckets[f"{bucket}-{bucket+9}"] += 1
    return ApiResponse.ok(data=[
        {"range": k, "count": v}
        for k, v in sorted(buckets.items())
    ])
