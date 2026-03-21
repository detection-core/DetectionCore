# Plan: Field Mapping & Multi-SIEM Conversion Pipeline

## Context

Sigma rules use generic field names (e.g., `CommandLine`, `Image`, `ParentImage`) but Elasticsearch data streams (Winlogbeat 9.3.1) use ECS field names (e.g., `process.command_line`, `process.executable`). Currently, `sigma_converter.py` line 36 creates `LuceneBackend()` with **no processing pipeline**, so field names pass through unchanged — deployed rules match zero events in ELK.

This design must also account for:
- **Multi-platform rules** — Windows, Linux, macOS, cloud (Azure, AWS) each have their own field naming conventions
- **Future SIEM integrations** — QRadar, CrowdStrike, Splunk (pySigma has separate backends for each)
- **Custom/manual field mappings** — detection engineers may need to override mappings for non-standard log sources
- **Detection engineer review** — the existing Intake Queue flow provides a manual checkpoint for rules that can't be auto-mapped

## Spec File

This plan will produce `.spec-kit/tasks/08-field-mapping-multi-siem.md` to be appended alongside existing task specs.

---

## Architecture: SIEM Integration Abstraction

Instead of hardcoding ELK-only logic, introduce a `SIEMIntegration` model that represents a configured SIEM target. Phase 1 ships with ELK only, but the schema supports adding QRadar/CrowdStrike later without restructuring.

```
SIEMIntegration (MongoDB document)
├── name: str                          # "Primary ELK", "QRadar Prod"
├── siem_type: str                     # "elasticsearch" | "qradar" | "crowdstrike" | "splunk"
├── connection_config: dict            # host, port, creds (type-specific)
├── is_default: bool                   # one default per type
├── base_pipeline: str                 # "ecs_windows" | "ecs_linux" | "custom_only" | "none"
├── custom_field_mappings: dict        # {"SigmaField": "target.field.name"}
├── logsource_field_overrides: dict    # {"windows/process_creation": {"Image": "process.exe"}}
└── updated_at: datetime
```

For Phase 1, the existing ELK settings in `.env` seed a default `SIEMIntegration` of type `elasticsearch`. The `sigma_converter.py` receives the integration config and selects the right pySigma backend + pipeline.

---

## Phase 1: Core Field Mapping (ELK)

### Step 1 — Install pySigma pipeline packages

**File:** `backend/requirements.txt`
```
pySigma-pipeline-windows==2.0.0
```
(Linux pipeline `pySigma-pipeline-linux` can be added when Linux rules are in scope)

### Step 2 — Create SIEMIntegration model

**File:** `backend/app/models/siem_integration.py` (new)

```python
class SIEMIntegration(Document):
    name: str = "Default ELK"
    siem_type: str = "elasticsearch"          # elasticsearch | qradar | crowdstrike | splunk
    connection_config: dict = {}              # host, port, creds — type-specific
    is_default: bool = True

    # Field mapping config
    base_pipeline: str = "ecs_windows"        # "ecs_windows" | "ecs_linux" | "custom_only" | "none"
    custom_field_mappings: dict[str, str] = {} # Global overrides: {"SigmaField": "elk.field.name"}
    logsource_field_overrides: dict[str, dict[str, str]] = {}
        # Per-logsource: {"windows/process_creation": {"Hashes": "file.hash.md5"}}

    updated_at: datetime

    class Settings:
        name = "siem_integrations"
```

### Step 3 — Register model and seed defaults

**File:** `backend/app/database.py`
- Import `SIEMIntegration` and add to `document_models` list
- In `_seed_defaults()`, seed a default ELK integration if none exists (using existing `.env` ELK settings)

### Step 4 — Build processing pipeline in sigma_converter.py

**File:** `backend/app/services/sigma_converter.py`

Add `_build_processing_pipeline(siem_config: dict | None)`:
1. Read `base_pipeline` from config:
   - `"ecs_windows"` → `from sigma.pipelines.windows import ecs_windows; pipeline = ecs_windows()`
   - `"ecs_linux"` → placeholder, return None for now (add when `pySigma-pipeline-linux` is installed)
   - `"custom_only"` → empty pipeline, only apply custom mappings
   - `"none"` → return None (raw Sigma field names — for manual review)
2. If `custom_field_mappings` is non-empty, build `FieldMappingTransformation` and chain with `+`
3. Return the pipeline

Change `convert_sigma_to_elk` signature to accept siem_config:
```python
def convert_sigma_to_elk(sigma_yaml: str, siem_config: dict | None = None) -> SigmaConversionResult:
    pipeline = _build_processing_pipeline(siem_config)
    backend = LuceneBackend(processing_pipeline=pipeline)
    ...
```

**Future multi-SIEM:** When QRadar is added, this function would select the backend based on `siem_type` (e.g., `QRadarBackend` from `pySigma-backend-qradar`). The pipeline + backend selection is the only part that changes per SIEM.

### Step 5 — Pass config from pipeline_service.py

**File:** `backend/app/services/pipeline_service.py` (line 55-72)

In `_stage_convert`, load the default `SIEMIntegration` and pass to converter:
```python
from app.models.siem_integration import SIEMIntegration
siem = await SIEMIntegration.find_one(SIEMIntegration.is_default == True)
siem_config = siem.model_dump() if siem else None
result = convert_sigma_to_elk(rule.sigma_content, siem_config=siem_config)
```

### Step 6 — Add /rules/reconvert-all endpoint

**File:** `backend/app/routers/rules.py`

New `POST /rules/reconvert-all` (follow existing `backfill-titles` pattern):
1. Load default `SIEMIntegration` once
2. Iterate all `DetectionRule` docs with `sigma_content`
3. Re-run `convert_sigma_to_elk(rule.sigma_content, siem_config)`
4. Update `elk_query` and `elk_rule_json`, save
5. Return count of reconverted rules

**File:** `frontend/src/api/endpoints.ts`
- Add `reconvertAllRules` function

---

## Phase 2: Settings UI & Field Discovery

### Step 7 — SIEM integration CRUD endpoints

**File:** `backend/app/routers/settings.py` (add to existing)

- `GET /settings/siem-integrations` — list all integrations
- `GET /settings/siem-integrations/{id}` — get one (with field mappings)
- `PUT /settings/siem-integrations/{id}` — update (base_pipeline, custom mappings)
- `POST /settings/siem-integrations` — create new (future: for QRadar, etc.)

### Step 8 — Field discovery from Elasticsearch

**File:** `backend/app/services/elk_client.py`
- Add `get_field_names(index_pattern: str) -> list[dict]` using `client.indices.get_mapping()`
- Flatten nested mapping properties to dot-notation field list with types

**File:** `backend/app/routers/elk.py`
- Add `GET /elk/fields?index=winlogbeat-*` endpoint

### Step 9 — Frontend Settings section

**File:** `frontend/src/pages/Settings.tsx`
- Add "SIEM Integrations" section:
  - Base pipeline dropdown (ECS Windows / ECS Linux / Custom Only / None)
  - Custom field mapping overrides table (Sigma Field → ELK Field, add/edit/delete)
  - "Reconvert All Rules" button
  - Field discovery: select a data stream → shows available ELK fields for reference

---

## How Non-Standard/Manual Fields Are Handled

For rules whose log sources don't have pre-built pipelines (custom apps, proprietary formats):

1. **`base_pipeline = "none"`** — fields pass through unchanged
2. **`custom_field_mappings`** — detection engineer adds manual mappings in Settings UI
3. **`logsource_field_overrides`** — scoped overrides per logsource combination
4. **Intake Queue review** — if a rule can't be auto-mapped, it still enters the queue at `QUEUED` status. The detection engineer reviews the ELK Query tab, manually adjusts if needed, then deploys. This is the existing workflow and remains the fallback.
5. **Field discovery** (Phase 2) — the UI shows actual ELK fields next to Sigma fields, so engineers can quickly identify mismatches

---

## How Future SIEMs Are Added

When QRadar/CrowdStrike support is needed:

1. Install the pySigma backend: `pip install pySigma-backend-qradar`
2. Create a new `SIEMIntegration` document with `siem_type: "qradar"`
3. In `sigma_converter.py`, add a branch in `_build_processing_pipeline()` for the new backend type
4. The same `custom_field_mappings` pattern works — each SIEM integration has its own field overrides
5. Deploy endpoint would call QRadar's API instead of Kibana's

No model restructuring needed — `SIEMIntegration` already supports multiple instances of different types.

---

## Files to Modify / Create

| File | Change |
|------|--------|
| `backend/requirements.txt` | Add `pySigma-pipeline-windows` |
| `backend/app/models/siem_integration.py` | **New** — SIEMIntegration document |
| `backend/app/database.py` | Register model, seed default ELK integration |
| `backend/app/services/sigma_converter.py` | Build pipeline from config, pass to LuceneBackend |
| `backend/app/services/pipeline_service.py` | Load SIEMIntegration, pass to converter |
| `backend/app/routers/rules.py` | Add `/rules/reconvert-all` endpoint |
| `frontend/src/api/endpoints.ts` | Add reconvert endpoint |
| `.spec-kit/tasks/08-field-mapping-multi-siem.md` | **New** — task spec |
| `backend/app/routers/settings.py` | SIEM integration CRUD (Phase 2) |
| `backend/app/services/elk_client.py` | Field discovery method (Phase 2) |
| `backend/app/routers/elk.py` | Fields endpoint (Phase 2) |
| `frontend/src/pages/Settings.tsx` | SIEM integration UI (Phase 2) |

---

## Spec-Kit Task File: `.spec-kit/tasks/08-field-mapping-multi-siem.md`

Create this file during implementation:

```markdown
# Task 08: Field Mapping & Multi-SIEM Conversion Pipeline

## Goal
Ensure Sigma rules are converted with correct field names that match the target SIEM's actual field schema. Introduce a SIEM integration abstraction that supports ELK (Phase 1) and future SIEMs (QRadar, CrowdStrike, Splunk).

## Problem
sigma_converter.py creates LuceneBackend() with no processing pipeline. Sigma field names (CommandLine, Image, ParentImage) pass through unchanged, but Winlogbeat/ECS uses different names (process.command_line, process.executable). Deployed rules match zero events.

## User Stories
- As an admin, Sigma rules are automatically converted with correct ECS field names for my ELK stack
- As an admin, I can configure which field mapping pipeline to use (ECS Windows, ECS Linux, custom, or none)
- As an admin, I can add custom field mapping overrides for non-standard log sources
- As an admin, I can reconvert all existing rules after changing field mappings
- As an admin, I can discover actual field names from my Elasticsearch indices
- As a detection engineer, rules with unmappable fields still enter the Intake Queue for manual review

## Data Model: SIEMIntegration
name, siem_type (elasticsearch|qradar|crowdstrike|splunk), connection_config, is_default
base_pipeline (ecs_windows|ecs_linux|custom_only|none)
custom_field_mappings: {SigmaField: target.field}
logsource_field_overrides: {"product/category": {SigmaField: target.field}}
updated_at

## API Endpoints
- POST /rules/reconvert-all
- GET /settings/siem-integrations
- PUT /settings/siem-integrations/{id}
- POST /settings/siem-integrations
- GET /elk/fields?index=<pattern>

## Files to Create / Modify
- backend/app/models/siem_integration.py (new)
- backend/app/services/sigma_converter.py (add pipeline building)
- backend/app/services/pipeline_service.py (load SIEM config)
- backend/app/routers/rules.py (reconvert-all endpoint)
- backend/app/routers/settings.py (SIEM CRUD)
- backend/app/services/elk_client.py (field discovery)
- backend/app/routers/elk.py (fields endpoint)
- backend/app/database.py (register model, seed)
- backend/requirements.txt (pySigma-pipeline-windows)
- frontend/src/pages/Settings.tsx (SIEM integration UI)
- frontend/src/api/endpoints.ts (new endpoints)

## Done When
- Windows Sigma rules convert with ECS field names (process.command_line, not CommandLine)
- POST /rules/reconvert-all updates all existing rules
- Deployed rules match events in winlogbeat-* data streams
- Detection engineer can add custom field overrides via Settings UI
- Rules with unmapped fields still flow through to Intake Queue for manual review
- SIEMIntegration model supports future SIEM types without restructuring
```

---

## Verification

1. Install pipeline package, restart server
2. Reprocess a single Windows rule → verify `elk_query` contains ECS fields (`process.command_line` not `CommandLine`)
3. `POST /rules/reconvert-all` → verify all rules updated
4. Deploy a reconverted rule to Kibana → verify it matches Winlogbeat events
5. Set `base_pipeline: "none"` via API → verify fields pass through unchanged (for manual review workflow)
6. Add a custom mapping → verify it overrides the base pipeline
