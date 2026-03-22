from datetime import datetime, timezone
from statistics import median
from fastapi import APIRouter, Depends
from app.core.dependencies import get_current_admin
from app.models.admin_user import AdminUser
from app.models.rule import DetectionRule, PipelineStatus, Severity
from app.models.intake_item import IntakeItem, IntakeStatus
from app.models.log_source import LogSource
from app.data.mitre_attack import TACTICS, TECHNIQUES
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


@router.get("/mitre-matrix", response_model=ApiResponse[dict])
async def get_mitre_matrix(admin: AdminUser = Depends(get_current_admin)):
    """Full MITRE ATT&CK matrix with per-technique rule coverage and sub-technique rollup."""
    # Count rules per technique (including sub-techniques) and implemented rules
    technique_rule_count: Counter = Counter()
    technique_impl_count: Counter = Counter()
    async for rule in DetectionRule.find_all():
        for tid in rule.mitre_technique_ids:
            t_upper = tid.upper()
            technique_rule_count[t_upper] += 1
            if rule.pipeline_status == PipelineStatus.IMPLEMENTED:
                technique_impl_count[t_upper] += 1

    # Build parent-level aggregated counts (roll up sub-techniques into parents)
    parent_rule_count: Counter = Counter()
    parent_impl_count: Counter = Counter()
    sub_detail: dict[str, list[dict]] = defaultdict(list)

    for tid, count in technique_rule_count.items():
        tech = TECHNIQUES.get(tid)
        if not tech:
            continue
        parent_id = tech.get("parent")
        if parent_id:
            # Sub-technique — aggregate into parent
            parent_rule_count[parent_id] += count
            parent_impl_count[parent_id] += technique_impl_count.get(tid, 0)
            sub_detail[parent_id].append({
                "technique_id": tid,
                "name": tech["name"],
                "rule_count": count,
                "implemented_count": technique_impl_count.get(tid, 0),
            })
        else:
            # Parent technique — count directly
            parent_rule_count[tid] += count
            parent_impl_count[tid] += technique_impl_count.get(tid, 0)

    # Build response grouped by tactics
    tactic_list = []
    covered_techniques = set()
    all_parent_ids = {tid for tid, tech in TECHNIQUES.items() if "parent" not in tech}

    for tactic in sorted(TACTICS, key=lambda t: t["order"]):
        tactic_id = tactic["id"]
        techniques_in_tactic = []
        for tid, tech in TECHNIQUES.items():
            if "parent" in tech:
                continue  # Skip sub-techniques at top level
            if tactic_id in tech.get("tactic_ids", []):
                rc = parent_rule_count.get(tid, 0)
                ic = parent_impl_count.get(tid, 0)
                if rc > 0:
                    covered_techniques.add(tid)
                techniques_in_tactic.append({
                    "technique_id": tid,
                    "name": tech["name"],
                    "rule_count": rc,
                    "implemented_count": ic,
                    "subtechniques": sorted(sub_detail.get(tid, []), key=lambda s: s["technique_id"]),
                })
        techniques_in_tactic.sort(key=lambda t: t["technique_id"])
        tactic_list.append({
            "tactic_id": tactic_id,
            "tactic_name": tactic["name"],
            "techniques": techniques_in_tactic,
        })

    total_parent = len(all_parent_ids)
    covered = len(covered_techniques)
    return ApiResponse.ok(data={
        "tactics": tactic_list,
        "summary": {
            "total_techniques": total_parent,
            "covered_techniques": covered,
            "coverage_percent": round(covered / total_parent * 100, 1) if total_parent else 0,
        },
    })


@router.get("/detection-report", response_model=ApiResponse[dict])
async def get_detection_report(admin: AdminUser = Depends(get_current_admin)):
    """Comprehensive detection posture report."""
    rules = await DetectionRule.find_all().to_list()
    total = len(rules)

    # Rules summary
    by_status: Counter = Counter()
    by_severity: Counter = Counter()
    deployed = 0
    failed = 0
    scores = []
    for r in rules:
        by_status[r.pipeline_status.value] += 1
        by_severity[r.severity.value] += 1
        if r.elk_deployment.deployed:
            deployed += 1
        if r.pipeline_status == PipelineStatus.FAILED:
            failed += 1
        scores.append(r.scoring.total_score)

    # MITRE summary
    technique_rule_count: Counter = Counter()
    for r in rules:
        for tid in r.mitre_technique_ids:
            t_upper = tid.upper()
            parent_id = TECHNIQUES.get(t_upper, {}).get("parent", t_upper)
            technique_rule_count[parent_id] += 1

    all_parents = {tid for tid, t in TECHNIQUES.items() if "parent" not in t}
    covered_techs = {tid for tid in technique_rule_count if tid in all_parents}

    # Per-tactic coverage
    tactics_coverage = []
    for tactic in sorted(TACTICS, key=lambda t: t["order"]):
        tactic_techs = {tid for tid, t in TECHNIQUES.items() if "parent" not in t and tactic["id"] in t.get("tactic_ids", [])}
        covered_in_tactic = tactic_techs & covered_techs
        tactics_coverage.append({
            "tactic": tactic["name"],
            "covered": len(covered_in_tactic),
            "total": len(tactic_techs),
        })

    # Top uncovered techniques (sorted by those with most sub-techniques, i.e. most impactful gaps)
    uncovered = []
    for tid in all_parents:
        if tid not in covered_techs:
            tech = TECHNIQUES[tid]
            tactic_names = [t["name"] for t in TACTICS if t["id"] in tech.get("tactic_ids", [])]
            uncovered.append({
                "technique_id": tid,
                "name": tech["name"],
                "tactic": ", ".join(tactic_names),
            })
    uncovered.sort(key=lambda x: x["technique_id"])
    top_uncovered = uncovered[:10]

    # Log source summary
    all_sources = await LogSource.find_all().to_list()
    available_sources = sum(1 for s in all_sources if s.is_available)
    unavailable_sources = len(all_sources) - available_sources
    rules_covered = sum(1 for r in rules if r.log_source_available)
    rules_uncovered = sum(1 for r in rules if (r.log_source_category or r.log_source_product) and not r.log_source_available)

    # Top log source gaps
    gap_counts: Counter = Counter()
    for r in rules:
        if not r.log_source_available and (r.log_source_category or r.log_source_product):
            key = "/".join(filter(None, [r.log_source_category, r.log_source_product, r.log_source_service]))
            if key:
                gap_counts[key] += 1
    top_gaps = [{"source": k, "blocked_rules": c} for k, c in gap_counts.most_common(10)]

    # Score summary
    avg_score = round(sum(scores) / len(scores), 1) if scores else 0
    med_score = round(median(scores), 1) if scores else 0
    above_70 = sum(1 for s in scores if s >= 70)
    score_buckets = defaultdict(int)
    for s in scores:
        bucket = int(s // 10) * 10
        score_buckets[f"{bucket}-{bucket+9}"] += 1
    distribution = [{"range": k, "count": v} for k, v in sorted(score_buckets.items())]

    return ApiResponse.ok(data={
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "rules_summary": {
            "total": total,
            "by_status": dict(by_status),
            "by_severity": dict(by_severity),
            "deployed_to_elk": deployed,
            "failed": failed,
        },
        "mitre_summary": {
            "techniques_covered": len(covered_techs),
            "techniques_total": len(all_parents),
            "coverage_percent": round(len(covered_techs) / len(all_parents) * 100, 1) if all_parents else 0,
            "tactics_coverage": tactics_coverage,
            "top_uncovered": top_uncovered,
        },
        "log_source_summary": {
            "total_sources": len(all_sources),
            "available": available_sources,
            "unavailable": unavailable_sources,
            "rules_covered": rules_covered,
            "rules_uncovered": rules_uncovered,
            "top_gaps": top_gaps,
        },
        "score_summary": {
            "average_score": avg_score,
            "median_score": med_score,
            "rules_above_70": above_70,
            "distribution": distribution,
        },
    })
