# Implementation Plan: Sigma Field Mapping & Multi-SIEM Pipeline

**Branch**: `001-sigma-field-mapping` | **Date**: 2026-03-21 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/001-sigma-field-mapping/spec.md`

---

## Summary

Add ECS field name translation to the Sigma → Elasticsearch conversion pipeline so that deployed Windows detection rules match real events in Winlogbeat data streams. Introduce a `SIEMIntegration` configuration model that lets users select a base mapping pipeline (ECS Windows/Linux/custom/none), define custom field overrides, and run a bulk async "Reconvert All" background job. Phase 2 adds a Settings UI section and a field discovery endpoint for browsing live Elasticsearch fields.

**Core problem**: `sigma_converter.py` creates `LuceneBackend()` with no processing pipeline. Windows Sigma fields (`CommandLine`, `Image`) pass through unchanged; Winlogbeat stores them as `process.command_line`, `process.executable` — deployed rules match zero events.

---

## Technical Context

**Language/Version**: Python 3.11 (backend), TypeScript 5 + React 18 (frontend)
**Primary Dependencies**: FastAPI, Beanie ODM (MongoDB), pySigma, `pySigma-pipeline-windows` (new), React Query, Tailwind CSS
**Storage**: MongoDB via Beanie ODM — new `siem_integrations` collection; in-memory `app.state.reconvert_job` for job progress
**Testing**: Manual API testing + end-to-end rule conversion verification
**Target Platform**: On-premises, single-server Docker deployment
**Performance Goals**: `reconvert-all` job must be non-blocking (async); field discovery must respond within ELK round-trip time
**Constraints**: No server restart on config changes; graceful fallback if `pySigma-pipeline-windows` not installed; implemented rules must NOT be auto-redeployed to Kibana
**Scale/Scope**: Potentially thousands of rules for reconvert; single default integration per deployment in Phase 1

---

## Constitution Check

The project constitution (`constitution.md`) contains only placeholder template text — no project-specific principles have been ratified. No gates apply.

**Post-design re-check**: No violations introduced. The design adds one new MongoDB collection, uses existing Beanie patterns, adds one in-memory state object, and extends two existing services with optional parameters.

---

## Project Structure

### Documentation (this feature)

```text
specs/001-sigma-field-mapping/
├── plan.md              ← this file
├── research.md          ← Phase 0 decisions
├── data-model.md        ← entity definitions
├── quickstart.md        ← developer verification guide
├── contracts/
│   └── api-contracts.md ← endpoint contracts
└── tasks.md             ← Phase 2 output (/speckit.tasks)
```

### Source Code (files to create/modify)

```text
backend/
├── requirements.txt                          MODIFY — add pySigma-pipeline-windows
├── app/
│   ├── database.py                           MODIFY — register SIEMIntegration, seed default
│   ├── models/
│   │   └── siem_integration.py               CREATE — SIEMIntegration Beanie document
│   ├── services/
│   │   ├── sigma_converter.py                MODIFY — add _build_processing_pipeline(), siem_config param
│   │   ├── pipeline_service.py               MODIFY — load SIEMIntegration in _stage_convert
│   │   └── elk_client.py                     MODIFY — add get_field_names()
│   └── routers/
│       ├── rules.py                          MODIFY — add /reconvert-all + /reconvert-status
│       ├── settings.py                       MODIFY — add SIEM integration CRUD endpoints
│       └── elk.py                            MODIFY — add /fields endpoint

frontend/
├── src/
│   ├── api/
│   │   └── endpoints.ts                      MODIFY — add reconvert + SIEM + fields endpoints
│   └── pages/
│       └── Settings.tsx                      MODIFY — add SIEM Integration section
```

**Structure Decision**: Web application (Option 2). Backend follows existing FastAPI + Beanie service/router structure. Frontend follows existing React Query + Tailwind page pattern.

---

## Complexity Tracking

No constitution violations. No unusual complexity.

---

## Phase 0: Research

See [research.md](./research.md) for all decisions. Key resolutions:

| Unknown | Resolution |
|---------|-----------|
| How to chain pySigma custom mappings with base pipeline | `ecs_windows() + ProcessingPipeline([FieldMappingTransformation(...)])` |
| Async background job approach | `asyncio.create_task()` + `app.state.reconvert_job` dict |
| One-default enforcement for SIEMIntegration | Atomically demote all in PUT endpoint before saving new default |
| Logsource override key format | `"{product}/{category}"` strings, e.g. `"windows/process_creation"` |
| Field discovery | `get_mapping()` + recursive dot-notation flattener |
| Seeding on startup | Extend existing `_seed_defaults()` in `database.py` |

---

## Phase 1: Design & Contracts

### Data Model

See [data-model.md](./data-model.md). Summary:
- **New**: `SIEMIntegration` Beanie document in `siem_integrations` collection
- **Modified**: No schema changes to `DetectionRule`
- **In-memory**: `app.state.reconvert_job` for background job progress

### API Contracts

See [contracts/api-contracts.md](./contracts/api-contracts.md). New endpoints:

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/rules/reconvert-all` | Start async reconvert background job |
| GET | `/api/rules/reconvert-status` | Poll job progress |
| GET | `/api/settings/siem-integrations` | List all SIEM integrations |
| GET | `/api/settings/siem-integrations/{id}` | Get one integration |
| PUT | `/api/settings/siem-integrations/{id}` | Update integration config |
| POST | `/api/settings/siem-integrations` | Create new integration |
| GET | `/api/elk/fields?index=<pattern>` | Field discovery from Elasticsearch |

### Implementation Sequence

#### Step 1 — Install dependency + model
1. Add `pySigma-pipeline-windows>=2.0.0` to `backend/requirements.txt`
2. Create `backend/app/models/siem_integration.py` with the `SIEMIntegration` Beanie document
3. Register in `database.py:document_models` list
4. Extend `_seed_defaults()` to create a default `SIEMIntegration` if none exists

#### Step 2 — sigma_converter.py: add pipeline building
Add `_build_processing_pipeline(siem_config: dict | None) -> ProcessingPipeline | None`:
- `base_pipeline == "ecs_windows"` → try `from sigma.pipelines.windows import ecs_windows; pipeline = ecs_windows()`, fallback to `None` on ImportError (log warning)
- `base_pipeline == "ecs_linux"` → return `None` (placeholder; log info "Linux pipeline not yet installed")
- `base_pipeline == "custom_only"` → empty pipeline
- `base_pipeline == "none"` or `siem_config is None` → return `None`
- If `custom_field_mappings` non-empty → build `FieldMappingTransformation`, chain with `+`
- If `logsource_field_overrides` non-empty → build per-logsource transformations with `ProcessingItemAppliedCondition` or filter by logsource; chain last

Change signature: `def convert_sigma_to_elk(sigma_yaml: str, siem_config: dict | None = None) -> SigmaConversionResult`
Pass pipeline to backend: `LuceneBackend(processing_pipeline=pipeline)`

#### Step 3 — pipeline_service.py: wire in SIEM config
In `_stage_convert()`:
```python
from app.models.siem_integration import SIEMIntegration
siem = await SIEMIntegration.find_one(SIEMIntegration.is_default == True)
siem_config = siem.model_dump() if siem else None
result = convert_sigma_to_elk(rule.sigma_content, siem_config=siem_config)
```

#### Step 4 — rules.py: reconvert-all endpoints
Add two endpoints following the `backfill-titles` pattern:
- `POST /rules/reconvert-all` — checks for running job (409 if running), starts `asyncio.create_task(_run_reconvert_job(app))`
- `GET /rules/reconvert-status` — returns `app.state.reconvert_job`

`_run_reconvert_job(app)` logic:
1. Set `app.state.reconvert_job = {"status": "running", "total": 0, "done": 0, "errors": 0, ...}`
2. Load default `SIEMIntegration` once
3. `async for rule in DetectionRule.find(DetectionRule.sigma_content != None):` (skip mid-pipeline: status in `{queued, converted, enhanced, tested}`)
4. Re-run `convert_sigma_to_elk(rule.sigma_content, siem_config)`
5. Update `rule.elk_query` and `rule.elk_rule_json`; save; increment `done` or `errors`
6. On completion: set `status = "done"`, `finished_at`

Initialize `app.state.reconvert_job` to `{"status": "idle", ...}` in `main.py` lifespan.

#### Step 5 — settings.py: SIEM integration CRUD
Add to existing settings router:
- `GET /settings/siem-integrations` — `await SIEMIntegration.find_all().to_list()`
- `GET /settings/siem-integrations/{id}` — `await SIEMIntegration.get(id)`
- `PUT /settings/siem-integrations/{id}` — partial update, handle default promotion atomically
- `POST /settings/siem-integrations` — create new

#### Step 6 — elk_client.py: field discovery
Add `get_field_names(index_pattern: str) -> list[dict]`:
- Call `self.client.indices.get_mapping(index=index_pattern)`
- Recursively flatten `properties` to dot-notation: `{"name": "process.command_line", "type": "keyword"}`
- Exclude fields starting with `_`
- Return `[]` if no indices match (not an error)

Add `GET /elk/fields?index=<pattern>` endpoint in `elk.py`.

#### Step 7 — Frontend: endpoints.ts additions
```typescript
export const reconvertAllRules = () => api.post("/rules/reconvert-all");
export const getReconvertStatus = () => api.get("/rules/reconvert-status");
export const getSiemIntegrations = () => api.get("/settings/siem-integrations");
export const getSiemIntegration = (id: string) => api.get(`/settings/siem-integrations/${id}`);
export const updateSiemIntegration = (id: string, data: Record<string, unknown>) =>
  api.put(`/settings/siem-integrations/${id}`, data);
export const createSiemIntegration = (data: Record<string, unknown>) =>
  api.post("/settings/siem-integrations", data);
export const getElkFields = (index: string) => api.get("/elk/fields", { params: { index } });
```

#### Step 8 — Frontend: Settings.tsx SIEM Integration section
Add new `<Section title="SIEM Integration">` after the existing ELK section:
- **Base pipeline dropdown**: `ecs_windows | ecs_linux | custom_only | none`
- **Custom field mappings table**: key-value rows with add/delete; inputs for Sigma field → target field
- **Logsource overrides table**: key (product/category) + nested field mapping rows
- **Reconvert All button**: triggers `reconvertAllRules()`, then polls `getReconvertStatus()` every 2s, shows progress bar and completion count
- **Field discovery panel**: index pattern text input → "Browse Fields" button → results list

Use existing `Section`, `Field` component patterns and `useMutation` / `useQuery` / `useQueryClient` patterns from the existing Settings page.

---

## Verification

1. Install `pySigma-pipeline-windows`, restart server
2. Reprocess a Windows rule → verify `elk_query` contains `process.command_line` (not `CommandLine`)
3. `POST /rules/reconvert-all` → verify immediate non-blocking response
4. Poll `/rules/reconvert-status` → verify progress increments
5. After completion, spot-check updated rules in DB
6. Deploy a reconverted rule to Kibana → verify it matches Winlogbeat events
7. Set `base_pipeline: "none"` via API → verify fields pass through unchanged
8. Add a custom mapping → verify it overrides the base pipeline in the next conversion
9. Test field discovery against a real `winlogbeat-*` data stream
10. Verify fresh DB seeds a default ELK `SIEMIntegration` on startup
