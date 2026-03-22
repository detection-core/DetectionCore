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


@router.post("/auto-discover", response_model=ApiResponse[dict])
async def auto_discover_log_sources(admin: AdminUser = Depends(get_current_admin)):
    """Scan all rules, extract unique logsource combos, insert missing entries as unavailable."""
    from app.models.rule import DetectionRule

    # Collect unique (category, product, service) tuples from rules
    unique_combos: set[tuple[str, str, str | None]] = set()
    async for rule in DetectionRule.find_all():
        if rule.log_source_category and rule.log_source_product:
            unique_combos.add((rule.log_source_category, rule.log_source_product, rule.log_source_service))

    inserted = 0
    skipped = 0
    for cat, prod, svc in unique_combos:
        existing = await LogSource.find_one(
            LogSource.category == cat,
            LogSource.product == prod,
            LogSource.service == svc,
        )
        if existing:
            skipped += 1
        else:
            src = LogSource(category=cat, product=prod, service=svc, is_available=False)
            await src.insert()
            inserted += 1

    # Refresh rule matching with the new entries
    await _refresh_rule_log_availability()

    return ApiResponse.ok(
        data={"inserted": inserted, "skipped": skipped, "total_unique": len(unique_combos)},
        message=f"Discovered {len(unique_combos)} unique log sources, inserted {inserted} new entries",
    )


@router.get("/coverage-summary", response_model=ApiResponse[dict])
async def get_coverage_summary(admin: AdminUser = Depends(get_current_admin)):
    """Return aggregated match statistics for rule log source coverage."""
    from app.models.rule import DetectionRule

    total = 0
    exact = 0
    partial = 0
    product = 0
    unmatched = 0

    async for rule in DetectionRule.find_all():
        if not rule.log_source_category and not rule.log_source_product:
            continue
        total += 1
        match rule.log_source_match_type:
            case "exact":
                exact += 1
            case "partial":
                partial += 1
            case "product":
                product += 1
            case _:
                unmatched += 1

    return ApiResponse.ok(data={
        "total_unique_in_rules": total,
        "exact_matches": exact,
        "partial_matches": partial,
        "product_matches": product,
        "unmatched": unmatched,
    })


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
    if body.is_available is not None:
        await _refresh_rule_log_availability()
    return ApiResponse.ok(data=_out(source))


@router.delete("/{source_id}", response_model=ApiResponse[None])
async def delete_log_source(source_id: str, admin: AdminUser = Depends(get_current_admin)):
    source = await LogSource.get(PydanticObjectId(source_id))
    if not source:
        raise NotFoundError("Log source")
    await source.delete()
    await _refresh_rule_log_availability()
    return ApiResponse.ok(message="Deleted")


async def _refresh_rule_log_availability():
    """Update log_source_available and log_source_match_type on all rules using hierarchical matching.

    Three-tier fallback: exact (category/product/service) → partial (category/product) → product-only.
    OR logic: if ANY log source entry for a key is available, the match resolves as available.
    """
    from app.models.rule import DetectionRule

    # Build lookup dicts from all LogSource entries (one query)
    exact_keys: dict[str, bool] = {}       # "category/product/service" → is_available
    cat_product_keys: dict[str, bool] = {}  # "category/product" → is_available (OR'd)
    product_keys: dict[str, bool] = {}      # "product" → is_available (OR'd)

    async for s in LogSource.find_all():
        # Exact key
        exact_keys[s.key] = exact_keys.get(s.key, False) or s.is_available
        # Category+product key
        cp_key = f"{s.category}/{s.product}"
        cat_product_keys[cp_key] = cat_product_keys.get(cp_key, False) or s.is_available
        # Product-only key
        product_keys[s.product] = product_keys.get(s.product, False) or s.is_available

    async for rule in DetectionRule.find_all():
        if not rule.log_source_category and not rule.log_source_product:
            # No log source fields — clear match info
            new_available = False
            new_match_type = None
        else:
            # Build the rule's exact key
            parts = [p for p in [rule.log_source_category, rule.log_source_product, rule.log_source_service] if p]
            rule_key = "/".join(parts)
            cp_key = "/".join(p for p in [rule.log_source_category, rule.log_source_product] if p)

            # Three-tier fallback
            if rule_key in exact_keys:
                new_available = exact_keys[rule_key]
                new_match_type = "exact"
            elif cp_key in cat_product_keys and rule.log_source_service:
                # Rule has a service but no exact match; fall back to category+product
                new_available = cat_product_keys[cp_key]
                new_match_type = "partial"
            elif rule.log_source_product and rule.log_source_product in product_keys:
                # Product-only fallback
                new_available = product_keys[rule.log_source_product]
                new_match_type = "product"
            else:
                new_available = False
                new_match_type = None

        if rule.log_source_available != new_available or rule.log_source_match_type != new_match_type:
            rule.log_source_available = new_available
            rule.log_source_match_type = new_match_type
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
