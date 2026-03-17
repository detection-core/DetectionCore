from fastapi import APIRouter, Depends, UploadFile, File, HTTPException
from beanie import PydanticObjectId
from pydantic import BaseModel
from typing import Optional
from app.core.dependencies import get_current_admin
from app.core.exceptions import NotFoundError
from app.models.admin_user import AdminUser
from app.models.log_source import LogSource
from app.schemas.base import ApiResponse

router = APIRouter(prefix="/log-sources", tags=["Log Sources"])


class LogSourceOut(BaseModel):
    id: str
    category: str
    product: str
    service: Optional[str]
    elk_index_pattern: Optional[str]
    is_available: bool
    record_count: Optional[int]
    notes: Optional[str]


class LogSourceUpdateRequest(BaseModel):
    is_available: Optional[bool] = None
    elk_index_pattern: Optional[str] = None
    notes: Optional[str] = None


@router.get("", response_model=ApiResponse[list[LogSourceOut]])
async def list_log_sources(admin: AdminUser = Depends(get_current_admin)):
    """List all uploaded log sources."""
    sources = await LogSource.find_all().to_list()
    return ApiResponse.ok(data=[_out(s) for s in sources])


@router.post("/upload", response_model=ApiResponse[dict])
async def upload_log_sources(
    file: UploadFile = File(...),
    admin: AdminUser = Depends(get_current_admin),
):
    """
    Upload log sources from CSV or JSON.

    CSV format: category,product,service,elk_index_pattern,is_available,notes
    JSON format: [{"category": "...", "product": "...", ...}]
    """
    content = await file.read()
    text = content.decode("utf-8")
    records = []

    filename = file.filename or ""
    if filename.endswith(".json"):
        import json
        records = json.loads(text)
    elif filename.endswith(".csv"):
        import csv, io
        reader = csv.DictReader(io.StringIO(text))
        records = list(reader)
    else:
        raise HTTPException(status_code=400, detail="Only .json and .csv files supported")

    inserted = 0
    updated = 0
    for rec in records:
        category = rec.get("category", "").strip()
        product = rec.get("product", "").strip()
        if not category or not product:
            continue

        service = (rec.get("service") or "").strip() or None
        existing = await LogSource.find_one(
            LogSource.category == category,
            LogSource.product == product,
            LogSource.service == service,
        )
        if existing:
            existing.is_available = str(rec.get("is_available", "true")).lower() not in ("false", "0", "no")
            existing.elk_index_pattern = rec.get("elk_index_pattern") or existing.elk_index_pattern
            existing.notes = rec.get("notes") or existing.notes
            await existing.save()
            updated += 1
        else:
            src = LogSource(
                category=category,
                product=product,
                service=service,
                elk_index_pattern=rec.get("elk_index_pattern"),
                is_available=str(rec.get("is_available", "true")).lower() not in ("false", "0", "no"),
                notes=rec.get("notes"),
            )
            await src.insert()
            inserted += 1

    # Refresh log source availability on all rules
    await _refresh_rule_log_availability()

    return ApiResponse.ok(
        data={"inserted": inserted, "updated": updated},
        message=f"Uploaded {inserted + updated} log sources",
    )


@router.put("/{source_id}", response_model=ApiResponse[LogSourceOut])
async def update_log_source(
    source_id: str,
    body: LogSourceUpdateRequest,
    admin: AdminUser = Depends(get_current_admin),
):
    source = await LogSource.get(PydanticObjectId(source_id))
    if not source:
        raise NotFoundError("Log source")
    if body.is_available is not None:
        source.is_available = body.is_available
    if body.elk_index_pattern is not None:
        source.elk_index_pattern = body.elk_index_pattern
    if body.notes is not None:
        source.notes = body.notes
    await source.save()
    return ApiResponse.ok(data=_out(source))


@router.delete("/{source_id}", response_model=ApiResponse[None])
async def delete_log_source(source_id: str, admin: AdminUser = Depends(get_current_admin)):
    source = await LogSource.get(PydanticObjectId(source_id))
    if not source:
        raise NotFoundError("Log source")
    await source.delete()
    return ApiResponse.ok(message="Deleted")


async def _refresh_rule_log_availability():
    """Update log_source_available on all rules based on current log source table."""
    from app.models.rule import DetectionRule
    sources = {s.key: s.is_available async for s in LogSource.find_all()}
    async for rule in DetectionRule.find_all():
        parts = [p for p in [rule.log_source_category, rule.log_source_product, rule.log_source_service] if p]
        key = "/".join(parts)
        available = sources.get(key, False)
        if rule.log_source_available != available:
            rule.log_source_available = available
            await rule.save()


def _out(s: LogSource) -> LogSourceOut:
    return LogSourceOut(
        id=str(s.id),
        category=s.category,
        product=s.product,
        service=s.service,
        elk_index_pattern=s.elk_index_pattern,
        is_available=s.is_available,
        record_count=s.record_count,
        notes=s.notes,
    )
