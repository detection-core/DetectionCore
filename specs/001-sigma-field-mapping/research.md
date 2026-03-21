# Research: Sigma Field Mapping & Multi-SIEM Pipeline

**Branch**: `001-sigma-field-mapping` | **Date**: 2026-03-21

---

## Decision 1: pySigma Processing Pipeline — how field mapping works

**Decision**: Use `pySigma-pipeline-windows` (provides `ecs_windows()`) for Windows ECS mappings, with `FieldMappingTransformation` chained on top for custom overrides.

**Rationale**:
- `ecs_windows()` returns a `ProcessingPipeline` covering 80+ Sigma → ECS field mappings (e.g. `CommandLine → process.command_line`, `Image → process.executable`).
- Pipelines are composable with `+`: `ecs_windows() + custom_pipeline` applies base mappings first, then overrides.
- `FieldMappingTransformation({"SigmaField": "target.field"})` wrapped in a `ProcessingItem` is the pySigma standard for custom field mapping.
- `LuceneBackend(processing_pipeline=pipeline)` applies the pipeline at conversion time.

**Alternatives considered**:
- Hardcoding mappings as a dict in the codebase — rejected: too brittle, not extensible, misses logsource-scoped logic.
- Using pySigma-pipeline-ecs (generic) — rejected: windows-specific pipeline has better coverage for Winlogbeat.

**How to chain custom mappings**:
```python
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import FieldMappingTransformation

custom = ProcessingPipeline([
    ProcessingItem(
        identifier="custom_global",
        transformation=FieldMappingTransformation({"SigmaField": "target.field"})
    )
])
pipeline = ecs_windows() + custom   # base first, custom overrides second
```

---

## Decision 2: pySigma import guard — graceful fallback

**Decision**: Wrap `from sigma.pipelines.windows import ecs_windows` in a try/except. If `pySigma-pipeline-windows` is not installed, fall back to `base_pipeline = "none"` and log a warning.

**Rationale**: Matches the existing pattern in `sigma_converter.py` which already guards the main pySigma import with a fallback converter. No hard failure; rules still flow to Intake Queue.

---

## Decision 3: Async background job for Reconvert All

**Decision**: Use `asyncio.create_task()` with in-memory progress state stored on `app.state`.

**Rationale**:
- This is a single-server on-prem deployment with no distributed workers.
- The project already uses APScheduler (in-process) for background jobs — in-process async tasks are consistent.
- `app.state.reconvert_job = {"status": "running", "total": N, "done": M, "errors": K}` is the simplest progress store.
- The UI polls `GET /rules/reconvert-status` while `status == "running"` (same pattern as rule reprocess polling in `RuleDetail.tsx`).
- No Redis, Celery, or external queue needed.

**Alternatives considered**:
- FastAPI `BackgroundTasks` — simpler, but no built-in way to query progress. Rejected.
- APScheduler one-time job — possible, but adds a scheduling layer where none is needed. Rejected.

---

## Decision 4: SIEMIntegration — one-default enforcement

**Decision**: When setting `is_default = True` on an integration, atomically unset `is_default` on all others using `await SIEMIntegration.find(SIEMIntegration.is_default == True).update(Set({SIEMIntegration.is_default: False}))` before saving the new default.

**Rationale**: Beanie has no unique-partial-index helper exposed in Python. The safest approach is an explicit "demote all, then promote one" sequence in the PUT endpoint. Acceptable for low-write admin settings.

---

## Decision 5: Logsource-scoped field override key format

**Decision**: Use `"{product}/{category}"` string keys in `logsource_field_overrides` dict (e.g. `"windows/process_creation"`). Match against `rule.log_source_product + "/" + rule.log_source_category` at conversion time.

**Rationale**: Matches how Sigma logsource is structured. Simple string key avoids nested sub-documents; easy to display and edit in a settings UI table.

---

## Decision 6: Field discovery — flattening nested Elasticsearch mappings

**Decision**: Use `client.indices.get_mapping(index=pattern)` and recursively flatten `properties` and `fields` into dot-notation strings.

**Rationale**: Elasticsearch returns nested dicts like `{"process": {"properties": {"command_line": {"type": "keyword"}}}}`. A recursive flattener converts this to `["process.command_line (keyword)", ...]`. Standard approach — no external library needed.

---

## Decision 7: Seeding default SIEMIntegration on startup

**Decision**: In `database.py:_seed_defaults()`, check `await SIEMIntegration.find_one(SIEMIntegration.is_default == True)`. If None, create one with `base_pipeline = "ecs_windows"` and connection details from `settings`.

**Rationale**: Matches the existing `_seed_defaults()` pattern used for admin user and scoring config. Idempotent — only runs once. Existing users get field mapping automatically on upgrade without any manual setup.

---

## Decision 8: sigma_converter.py signature change — backward compatible

**Decision**: Add `siem_config: dict | None = None` as an optional parameter to `convert_sigma_to_elk()`. Default `None` means no pipeline (existing behaviour preserved).

**Rationale**: Any call site that doesn't pass `siem_config` continues to work. Only `pipeline_service.py:_stage_convert` and the reconvert endpoint pass a config. No breaking change.
