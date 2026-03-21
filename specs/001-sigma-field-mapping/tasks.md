# Tasks: Sigma Field Mapping & Multi-SIEM Pipeline

**Input**: Design documents from `/specs/001-sigma-field-mapping/`
**Prerequisites**: plan.md ✓, spec.md ✓, research.md ✓, data-model.md ✓, contracts/api-contracts.md ✓, quickstart.md ✓

**Tests**: Not requested in spec — no test tasks generated.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (US1–US5)

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Install the new dependency and confirm the environment is ready.

- [X] T001 Add `pySigma-pipeline-windows>=2.0.0` to `backend/requirements.txt` and install it into `backend/.venv` with `.venv/Scripts/pip install pySigma-pipeline-windows`

**Checkpoint**: `python -c "from sigma.pipelines.windows import ecs_windows; print('ok')"` runs without error inside the venv.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core infrastructure that MUST be complete before any user story can be implemented. Creates the `SIEMIntegration` model and wires it into startup.

**⚠️ CRITICAL**: No user story work can begin until this phase is complete.

- [X] T002 Create `backend/app/models/siem_integration.py` — define `SIEMIntegration` Beanie document with fields: `name`, `siem_type` (elasticsearch|qradar|crowdstrike|splunk), `is_default`, `base_pipeline` (ecs_windows|ecs_linux|custom_only|none), `custom_field_mappings: dict[str,str]`, `logsource_field_overrides: dict[str, dict[str,str]]`, `updated_at`; Settings class with `name = "siem_integrations"`
- [X] T003 Register `SIEMIntegration` in `backend/app/database.py` — add to the `document_models` list passed to `init_beanie()`
- [X] T004 Extend `_seed_defaults()` in `backend/app/database.py` — if no `SIEMIntegration` with `is_default == True` exists, create one with `name="Default ELK"`, `siem_type="elasticsearch"`, `is_default=True`, `base_pipeline="ecs_windows"`, `custom_field_mappings={}`, `logsource_field_overrides={}`
- [X] T005 Initialize `app.state.reconvert_job` in `backend/app/main.py` lifespan startup — set to `{"status": "idle", "total": 0, "done": 0, "errors": 0, "started_at": None, "finished_at": None}`

**Checkpoint**: Server starts without errors; MongoDB `siem_integrations` collection exists with one seeded document.

---

## Phase 3: User Story 1 - Automatic ECS Field Mapping for Windows Rules (Priority: P1) 🎯 MVP

**Goal**: Windows Sigma rules convert using ECS field names (`process.command_line`, not `CommandLine`) so deployed rules match real Winlogbeat events. Admin can trigger async "Reconvert All" bulk job to update all existing rules.

**Independent Test**: Convert a `process_creation` Windows rule via the pipeline and verify `elk_query` contains `process.command_line`. Then call `POST /api/rules/reconvert-all` and poll `/api/rules/reconvert-status` until `status == "done"`.

### Implementation for User Story 1

- [X] T006 [US1] Add `_build_processing_pipeline(siem_config: dict | None) -> ProcessingPipeline | None` to `backend/app/services/sigma_converter.py` — implement the four `base_pipeline` branches: `ecs_windows` (try-import `ecs_windows()`, fallback to None with warning on ImportError), `ecs_linux` (return None + log info), `custom_only` (empty ProcessingPipeline), `none`/None (return None). Handle `custom_field_mappings` chaining with `+` operator and `FieldMappingTransformation`. Handle `logsource_field_overrides` as logsource-scoped transformations chained last.
- [X] T007 [US1] Update `convert_sigma_to_elk` signature in `backend/app/services/sigma_converter.py` — add `siem_config: dict | None = None` parameter; call `_build_processing_pipeline(siem_config)` and pass the result to `LuceneBackend(processing_pipeline=pipeline)`
- [X] T008 [US1] Update `_stage_convert()` in `backend/app/services/pipeline_service.py` — load `await SIEMIntegration.find_one(SIEMIntegration.is_default == True)`, call `siem_config = siem.model_dump() if siem else None`, pass to `convert_sigma_to_elk(rule.sigma_content, siem_config=siem_config)`
- [X] T009 [US1] Add async background job function `_run_reconvert_job(app)` in `backend/app/routers/rules.py` — sets `app.state.reconvert_job` to running, iterates all `DetectionRule` documents where `sigma_content` is non-empty (skip rules with status in `queued`, `converted`, `enhanced`, `tested`), calls `convert_sigma_to_elk(rule.sigma_content, siem_config)`, updates `rule.elk_query` and `rule.elk_rule_json`, saves, increments `done` or `errors`; sets `status = "done"` and `finished_at` on completion; sets `status = "error"` on unhandled exception
- [X] T010 [US1] Add `POST /rules/reconvert-all` endpoint in `backend/app/routers/rules.py` — returns `409` if `app.state.reconvert_job["status"] == "running"`, otherwise resets job state and starts `asyncio.create_task(_run_reconvert_job(request.app))`; returns current job state immediately
- [X] T011 [US1] Add `GET /rules/reconvert-status` endpoint in `backend/app/routers/rules.py` — returns `app.state.reconvert_job` dict wrapped in `ApiResponse`
- [X] T012 [P] [US1] Add `reconvertAllRules` and `getReconvertStatus` functions to `frontend/src/api/endpoints.ts`
- [X] T013 [US1] Add "Reconvert All Rules" button to `frontend/src/pages/Settings.tsx` inside a new `<Section title="SIEM Integration">` — button calls `reconvertAllRules()`, then polls `getReconvertStatus()` every 2s while `status == "running"`, shows spinner and `{done}/{total} rules updated`, stops polling at `status == "done"` or `"error"`, displays final count on completion

**Checkpoint**: Reprocess a Windows `process_creation` rule — `elk_query` must contain `process.command_line` (not `CommandLine`). `POST /api/rules/reconvert-all` returns immediately; `GET /api/rules/reconvert-status` shows progress; status reaches `"done"` with correct counts.

---

## Phase 4: User Story 3 - SIEM Integration Configuration Management (Priority: P2)

> **Note**: Implemented before US2 because US2's custom mapping UI requires these CRUD endpoints to persist changes.

**Goal**: Authenticated users can view and update SIEM integration configuration (base pipeline, custom mappings) via Settings UI and API, without server restarts.

**Independent Test**: `GET /api/settings/siem-integrations` returns the seeded default. `PUT /api/settings/siem-integrations/{id}` with `{"base_pipeline": "none"}` succeeds. Subsequent rule conversion uses `none` pipeline (fields pass through unchanged).

### Implementation for User Story 3

- [X] T014 [P] [US3] Add `GET /settings/siem-integrations` endpoint in `backend/app/routers/settings.py` — returns `await SIEMIntegration.find_all().to_list()` wrapped in `ApiResponse`
- [X] T015 [P] [US3] Add `GET /settings/siem-integrations/{id}` endpoint in `backend/app/routers/settings.py` — returns single integration by ID; `404` if not found
- [X] T016 [US3] Add `PUT /settings/siem-integrations/{id}` endpoint in `backend/app/routers/settings.py` — accepts partial update body; if `is_default=True`, atomically demote all others (`await SIEMIntegration.find(SIEMIntegration.is_default == True).update(Set({SIEMIntegration.is_default: False}))`), then save updated doc with `updated_at = datetime.now(UTC)`; `404` if not found
- [X] T017 [US3] Add `POST /settings/siem-integrations` endpoint in `backend/app/routers/settings.py` — creates new integration; validates `siem_type` and `base_pipeline` values; returns `201` with created doc
- [X] T018 [P] [US3] Add `getSiemIntegrations`, `getSiemIntegration`, `updateSiemIntegration`, `createSiemIntegration` functions to `frontend/src/api/endpoints.ts`
- [X] T019 [US3] Expand the SIEM Integration section in `frontend/src/pages/Settings.tsx` — add `useQuery` to load the default SIEM integration, base pipeline `<select>` dropdown (ecs_windows | ecs_linux | custom_only | none), Save button calling `updateSiemIntegration`, success toast

**Checkpoint**: Change base pipeline to `none` via UI → save → reprocess a rule → `elk_query` contains raw Sigma field names. Change back to `ecs_windows` → reprocess → ECS field names return.

---

## Phase 5: User Story 2 - Custom Field Mapping Overrides (Priority: P2)

**Goal**: Users can add, edit, and delete custom global field mapping overrides and per-logsource overrides in the Settings UI, which are applied during rule conversion.

**Independent Test**: Add custom mapping `Hashes → file.hash.sha256` via Settings UI → save → reconvert a rule using `Hashes` field → `elk_query` contains `file.hash.sha256`.

### Implementation for User Story 2

- [X] T020 [US2] Verify `_build_processing_pipeline()` in `backend/app/services/sigma_converter.py` correctly chains `custom_field_mappings` — if not complete from T006, implement: build a `ProcessingPipeline` from `custom_field_mappings` dict using `FieldMappingTransformation`, chain after base pipeline with `+`; implement logsource-scoped overrides using `logsource_field_overrides` keyed as `"{product}/{category}"`, match against rule's logsource and chain as highest-priority transformations
- [X] T021 [P] [US2] Add custom field mapping table to SIEM Integration section in `frontend/src/pages/Settings.tsx` — key-value rows showing `sigma_field → target_field`, Add Row button (new empty row), Delete button per row, inline editing; updates `form.custom_field_mappings` state as a dict
- [X] T022 [P] [US2] Add per-logsource overrides table to SIEM Integration section in `frontend/src/pages/Settings.tsx` — rows showing `product/category` key + nested field mapping pairs, Add/Delete controls; updates `form.logsource_field_overrides` state as a nested dict
- [X] T023 [US2] Wire custom mappings save in `frontend/src/pages/Settings.tsx` — ensure Save button includes `custom_field_mappings` and `logsource_field_overrides` in the `updateSiemIntegration` call body

**Checkpoint**: Add `Hashes → file.hash.sha256` in Settings UI → save → `PUT /settings/siem-integrations/{id}` persists the mapping → reconvert a rule with `Hashes` field → `elk_query` contains `file.hash.sha256`.

---

## Phase 6: User Story 4 - Field Discovery from Elasticsearch (Priority: P3)

**Goal**: Users can browse actual field names from a selected Elasticsearch data stream in the Settings UI to identify correct target field names when building custom mappings.

**Independent Test**: Call `GET /api/elk/fields?index=winlogbeat-*` — response contains `process.command_line` and `event.action` in the `fields` array with their types. Elasticsearch unreachable → `503`.

### Implementation for User Story 4

- [X] T024 [US4] Add `get_field_names(index_pattern: str) -> list[dict]` method to `backend/app/services/elk_client.py` — call `self.client.indices.get_mapping(index=index_pattern)`, recursively flatten nested `properties` to dot-notation `[{"name": "process.command_line", "type": "keyword"}, ...]`, exclude fields starting with `_`, return `[]` (not error) when pattern matches no indices; raise exception on connection failure
- [X] T025 [US4] Add `GET /elk/fields` endpoint to `backend/app/routers/elk.py` — query param `index` (required), call `elk_client.get_field_names(index)`, return `{"index_pattern": index, "fields": [...]}` wrapped in `ApiResponse`; return `503` with clear message if Elasticsearch is unreachable
- [X] T026 [P] [US4] Add `getElkFields(index: string)` function to `frontend/src/api/endpoints.ts`
- [X] T027 [US4] Add field discovery panel to SIEM Integration section in `frontend/src/pages/Settings.tsx` — text input for index pattern (default `winlogbeat-*`), "Browse Fields" button calling `getElkFields()`, scrollable results list showing `field.name (type)`, "no fields found" empty state, error state when Elasticsearch unreachable

**Checkpoint**: Select `winlogbeat-*` in the field discovery panel → results list shows `process.command_line (keyword)`, `@timestamp (date)`, etc. Enter an invalid pattern → "no fields found" message. Stop Elasticsearch → `503` error shown in panel, other settings remain functional.

---

## Phase 7: User Story 5 - Multi-SIEM Extensibility Foundation (Priority: P3)

**Goal**: Verify the `SIEMIntegration` model supports multiple records of different types simultaneously without breaking the default ELK integration.

**Independent Test**: Create a second `SIEMIntegration` with `siem_type="qradar"` and `is_default=false` via `POST /settings/siem-integrations` → both records exist in DB → ELK integration remains default → rule conversion still uses ELK config.

### Implementation for User Story 5

- [X] T028 [US5] Verify `POST /settings/siem-integrations` (T017) accepts `siem_type: "qradar"` without error and stores the record — confirm no schema validation rejects unknown-but-valid siem_types; all four enum values must be accepted
- [X] T029 [US5] Verify default-promotion logic in `PUT /settings/siem-integrations/{id}` (T016) — when a non-ELK integration is set as default, the ELK integration's `is_default` is set to `false`; when ELK is restored as default, no other integration has `is_default=true`

**Checkpoint**: Two integrations of different types coexist in DB. Setting one as default automatically demotes the other. Rule conversion always uses whichever integration has `is_default == True`.

---

## Phase 8: Polish & Cross-Cutting Concerns

**Purpose**: Final hardening and verification pass.

- [X] T030 [P] Update `CLAUDE.md` — add `SIEMIntegration` to the Key Files table, document `app.state.reconvert_job` pattern, note `pySigma-pipeline-windows` install requirement in Development Commands
- [X] T031 [P] Add `getElkFields` and SIEM integration endpoints to the API Route Prefixes table in `CLAUDE.md`
- [ ] T032 Run the full acceptance checklist from `specs/001-sigma-field-mapping/quickstart.md` — verify all 11 items pass end-to-end

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — start immediately
- **Foundational (Phase 2)**: Depends on Phase 1 — BLOCKS all user stories
- **US1 (Phase 3)**: Depends on Phase 2 — P1 MVP, implement first
- **US3 (Phase 4)**: Depends on Phase 2 — can start in parallel with US1 after Phase 2
- **US2 (Phase 5)**: Depends on US1 (T006–T007 sigma_converter) AND US3 (T016 CRUD PUT endpoint) — implement after both
- **US4 (Phase 6)**: Depends on Phase 2 only — independent, can start any time after Foundation
- **US5 (Phase 7)**: Depends on US3 (T017 POST endpoint) — verify after Phase 4
- **Polish (Phase 8)**: Depends on all stories complete

### User Story Dependencies

- **US1 (P1)**: Only depends on Foundational (Phase 2)
- **US3 (P2)**: Only depends on Foundational (Phase 2) — can run in parallel with US1
- **US2 (P2)**: Depends on US1 (sigma_converter already extended) + US3 (CRUD endpoints exist to save mappings)
- **US4 (P3)**: Only depends on Foundational (Phase 2) — fully independent
- **US5 (P3)**: Depends on US3 (POST endpoint from T017)

### Within Each User Story

- Backend model/service changes before endpoint changes
- Endpoints before frontend API functions
- Frontend API functions before UI integration
- Commit after each phase checkpoint

### Parallel Opportunities

- T002, T005 can run in parallel (different files in Phase 2)
- T014, T015, T018 can run in parallel (GET endpoints + frontend functions in Phase 4)
- T021, T022 can run in parallel (different UI tables in Phase 5)
- T024, T026 can run in parallel (backend service + frontend function in Phase 6)
- T030, T031 can run in parallel (CLAUDE.md edits in different sections in Phase 8)
- US1 (Phase 3) and US3 (Phase 4) can run in parallel once Phase 2 is done
- US4 (Phase 6) can run in parallel with US2 (Phase 5)

---

## Parallel Example: US1 + US3 (after Phase 2)

```
After Phase 2 complete, two tracks run simultaneously:

Track A (US1 — core conversion):
  T006 → T007 → T008 → T009 → T010 → T011 → T012 (parallel) → T013

Track B (US3 — CRUD + settings):
  T014 (parallel) + T015 (parallel) + T018 (parallel) → T016 → T017 → T019
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup (T001)
2. Complete Phase 2: Foundational (T002–T005)
3. Complete Phase 3: User Story 1 (T006–T013)
4. **STOP and VALIDATE**: Windows rules convert with ECS field names; Reconvert All job runs async
5. Deploy and confirm rules match Winlogbeat events in production

### Incremental Delivery

1. Phase 1–2: Foundation → server starts with seeded SIEMIntegration
2. Phase 3 (US1): ECS conversion works → rules match events → **MVP deployed**
3. Phase 4 (US3): Settings CRUD → admins can change pipeline mode without file edits
4. Phase 5 (US2): Custom mappings → non-standard log sources now mapable
5. Phase 6 (US4): Field discovery → faster, error-free custom mapping creation
6. Phase 7 (US5): Extensibility verified → multi-SIEM foundation confirmed
7. Phase 8: Polish

---

## Notes

- [P] tasks operate on different files and have no incomplete task dependencies
- [Story] label maps each task to its user story for traceability
- US1 is the entire MVP — complete it first and validate before continuing
- US3 should be done before US2 since the Settings UI save for custom mappings calls the PUT endpoint
- US4 is fully isolated — can be done any time after Phase 2 by a second developer
- Commit and test after each phase checkpoint
- `asyncio.create_task()` in T009–T010 requires the app event loop to be running — ensure `_run_reconvert_job` is defined as `async def`
- All Beanie queries use filter expressions (`Model.field == value`), not kwargs — see CLAUDE.md
