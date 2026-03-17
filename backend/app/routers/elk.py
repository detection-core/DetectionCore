from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Optional
from app.core.dependencies import get_current_admin
from app.models.admin_user import AdminUser
from app.schemas.base import ApiResponse

router = APIRouter(prefix="/elk", tags=["ELK"])


class ELKConnectionTest(BaseModel):
    connected: bool
    cluster_name: Optional[str] = None
    version: Optional[str] = None
    status: Optional[str] = None
    error: Optional[str] = None


class UnitTestRunRequest(BaseModel):
    rule_id: str
    test_id: str


class UnitTestRunResult(BaseModel):
    test_id: str
    passed: bool
    hits: int
    error: Optional[str] = None


@router.get("/status", response_model=ApiResponse[ELKConnectionTest])
async def elk_status(admin: AdminUser = Depends(get_current_admin)):
    """Test ELK connection and return cluster info."""
    from app.services.elk_client import ELKClient
    client = ELKClient()
    result = await client.test_connection()
    return ApiResponse.ok(data=ELKConnectionTest(**result))


@router.get("/indices", response_model=ApiResponse[list[dict]])
async def list_elk_indices(admin: AdminUser = Depends(get_current_admin)):
    """List available ELK indices (useful for log source discovery)."""
    from app.services.elk_client import ELKClient
    client = ELKClient()
    indices = await client.list_indices()
    return ApiResponse.ok(data=indices)


@router.post("/run-test", response_model=ApiResponse[UnitTestRunResult])
async def run_unit_test(
    body: UnitTestRunRequest,
    admin: AdminUser = Depends(get_current_admin),
):
    """
    Execute a unit test against ELK.
    Searches for alerts that would have fired based on the ELK query.
    Note: The attack command itself must be executed manually on the target host.
    This endpoint checks whether the ELK query matches recent events.
    """
    from beanie import PydanticObjectId
    from app.models.rule import DetectionRule
    from app.services.elk_client import ELKClient
    from app.core.exceptions import NotFoundError
    from datetime import datetime, timezone

    rule = await DetectionRule.get(PydanticObjectId(body.rule_id))
    if not rule:
        raise NotFoundError("Rule")

    test = next((t for t in rule.unit_tests if t.test_id == body.test_id), None)
    if not test:
        raise NotFoundError("Unit test")

    if not rule.elk_query:
        return ApiResponse.ok(data=UnitTestRunResult(
            test_id=body.test_id,
            passed=False,
            hits=0,
            error="No ELK query available — run pipeline first",
        ))

    # Determine index patterns from rule
    indices = rule.elk_rule_json.get("index", ["*"]) if rule.elk_rule_json else ["*"]
    index_pattern = ",".join(indices)

    client = ELKClient()
    result = await client.search(index=index_pattern, query=rule.elk_query, size=5)
    hits = result.get("hits", 0)

    # Update test result
    from app.models.rule import TestResult
    test.last_run_at = datetime.now(timezone.utc)
    test.last_run_result = TestResult.PASSED if hits > 0 else TestResult.FAILED
    test.last_run_output = f"{hits} matching events found"
    rule.updated_at = datetime.now(timezone.utc)
    await rule.save()

    return ApiResponse.ok(data=UnitTestRunResult(
        test_id=body.test_id,
        passed=hits > 0,
        hits=hits,
        error=result.get("error"),
    ))
