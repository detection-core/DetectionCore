from fastapi import APIRouter, Depends, Query, BackgroundTasks
from beanie import PydanticObjectId
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timezone
from app.core.dependencies import get_current_admin
from app.core.exceptions import NotFoundError
from app.models.admin_user import AdminUser
from app.models.intake_item import IntakeItem, IntakeStatus
from app.models.rule import DetectionRule
from app.schemas.base import ApiResponse, PaginatedResponse

router = APIRouter(prefix="/intake", tags=["In-Take Queue"])


class IntakeItemOut(BaseModel):
    id: str
    rule_id: str
    rule_title: str
    rule_severity: str
    score: float
    priority_rank: int
    status: str
    implementation_notes: Optional[str]
    tuning_notes: Optional[str]
    test_passed: bool
    assigned_to: Optional[str]
    elk_deployed: bool
    mitre_technique_ids: list[str]
    log_source_product: Optional[str]
    updated_at: datetime


class IntakePatchRequest(BaseModel):
    status: Optional[IntakeStatus] = None
    implementation_notes: Optional[str] = None
    tuning_notes: Optional[str] = None
    test_passed: Optional[bool] = None
    assigned_to: Optional[str] = None
    score_override: Optional[float] = None


@router.get("", response_model=ApiResponse[PaginatedResponse[IntakeItemOut]])
async def list_intake(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    status: Optional[IntakeStatus] = None,
    min_score: Optional[float] = None,
    admin: AdminUser = Depends(get_current_admin),
):
    """Get the In-Take Queue sorted by score (highest priority first)."""
    conditions = []
    if status:
        conditions.append(IntakeItem.status == status)

    base = IntakeItem.find(*conditions)
    total = await base.count()
    items = (
        await base
        .sort(-IntakeItem.score)
        .skip((page - 1) * page_size)
        .limit(page_size)
        .to_list()
    )

    results = []
    for item in items:
        if min_score is not None and item.score < min_score:
            continue
        rule = await DetectionRule.get(item.rule.ref.id)
        results.append(_item_out(item, rule))

    return ApiResponse.ok(data=PaginatedResponse(
        items=results,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    ))


@router.get("/{item_id}", response_model=ApiResponse[IntakeItemOut])
async def get_intake_item(item_id: str, admin: AdminUser = Depends(get_current_admin)):
    item = await IntakeItem.get(PydanticObjectId(item_id))
    if not item:
        raise NotFoundError("Intake item")
    rule = await DetectionRule.get(item.rule.ref.id)
    return ApiResponse.ok(data=_item_out(item, rule))


@router.patch("/{item_id}", response_model=ApiResponse[IntakeItemOut])
async def update_intake_item(
    item_id: str,
    body: IntakePatchRequest,
    admin: AdminUser = Depends(get_current_admin),
):
    """Update analyst notes, status, test pass flag on a queue item."""
    item = await IntakeItem.get(PydanticObjectId(item_id))
    if not item:
        raise NotFoundError("Intake item")

    if body.status is not None:
        item.status = body.status
    if body.implementation_notes is not None:
        item.implementation_notes = body.implementation_notes
    if body.tuning_notes is not None:
        item.tuning_notes = body.tuning_notes
    if body.test_passed is not None:
        item.test_passed = body.test_passed
    if body.assigned_to is not None:
        item.assigned_to = body.assigned_to
    if body.score_override is not None:
        item.score = body.score_override
        # Also update the rule's scoring
        rule = await DetectionRule.get(item.rule.ref.id)
        if rule:
            rule.scoring.manually_overridden = True
            rule.scoring.override_value = body.score_override
            rule.scoring.total_score = body.score_override
            await rule.save()

    item.updated_at = datetime.now(timezone.utc)
    await item.save()

    rule = await DetectionRule.get(item.rule.ref.id)

    # If marked as implemented, update rule pipeline status
    if item.status == IntakeStatus.IMPLEMENTED and rule:
        from app.models.rule import PipelineStatus
        rule.pipeline_status = PipelineStatus.IMPLEMENTED
        rule.updated_at = datetime.now(timezone.utc)
        await rule.save()

    return ApiResponse.ok(data=_item_out(item, rule), message="Updated")


@router.post("/{item_id}/deploy-to-elk", response_model=ApiResponse[dict])
async def deploy_to_elk(
    item_id: str,
    admin: AdminUser = Depends(get_current_admin),
):
    """Deploy the rule to ELK and update deployment status."""
    item = await IntakeItem.get(PydanticObjectId(item_id))
    if not item:
        raise NotFoundError("Intake item")

    rule = await DetectionRule.get(item.rule.ref.id)
    if not rule or not rule.elk_rule_json:
        raise NotFoundError("ELK rule JSON not available — run pipeline first")

    from app.services.elk_client import ELKClient
    client = ELKClient()
    result = await client.deploy_rule(rule.elk_rule_json, str(rule.id))

    rule.elk_deployment.deployed = result.get("deployed", False)
    if result.get("rule_id_elk"):
        rule.elk_deployment.rule_id_elk = result["rule_id_elk"]
    if result.get("error"):
        rule.elk_deployment.last_error = result["error"]
    if result.get("deployed"):
        rule.elk_deployment.deployed_at = datetime.now(timezone.utc)
    rule.updated_at = datetime.now(timezone.utc)
    await rule.save()

    return ApiResponse.ok(data=result, message="Deployed to ELK" if result.get("deployed") else "Deployment failed")


def _item_out(item: IntakeItem, rule: Optional[DetectionRule]) -> IntakeItemOut:
    return IntakeItemOut(
        id=str(item.id),
        rule_id=str(item.rule.ref.id) if item.rule else "",
        rule_title=rule.title if rule else "Unknown",
        rule_severity=rule.severity if rule else "medium",
        score=item.score,
        priority_rank=item.priority_rank,
        status=item.status,
        implementation_notes=item.implementation_notes,
        tuning_notes=item.tuning_notes,
        test_passed=item.test_passed,
        assigned_to=item.assigned_to,
        elk_deployed=rule.elk_deployment.deployed if rule else False,
        mitre_technique_ids=rule.mitre_technique_ids if rule else [],
        log_source_product=rule.log_source_product if rule else None,
        updated_at=item.updated_at,
    )
