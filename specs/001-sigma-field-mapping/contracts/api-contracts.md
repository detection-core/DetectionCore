# API Contracts: Sigma Field Mapping & Multi-SIEM Pipeline

**Branch**: `001-sigma-field-mapping` | **Date**: 2026-03-21

All endpoints follow the existing `ApiResponse[T]` wrapper pattern. All paths are prefixed `/api` by the FastAPI app.

---

## Rules Router (`/api/rules`)

### POST /api/rules/reconvert-all

Starts an asynchronous background job that re-runs Sigma conversion for every rule with `sigma_content`, using the current default SIEM integration's field mapping configuration.

**Auth**: Required
**Request body**: None

**Response** `200 OK`:
```json
{
  "success": true,
  "data": {
    "status": "running",
    "total": 412,
    "done": 0,
    "errors": 0,
    "started_at": "2026-03-21T10:05:00Z",
    "finished_at": null
  },
  "message": "Reconvert job started"
}
```

**Response** `409 Conflict` — job already running:
```json
{
  "success": false,
  "message": "A reconvert job is already running",
  "data": { "status": "running", "total": 412, "done": 87, ... }
}
```

**Behaviour**:
- Returns `409` if `app.state.reconvert_job.status == "running"`.
- Starts `asyncio.create_task(_run_reconvert_job(app))` — non-blocking.
- Job updates `app.state.reconvert_job` incrementally.
- Rules actively mid-pipeline (status in `queued`, `converted`, `enhanced`, `tested`) are skipped.
- Does **not** redeploy to Kibana.

---

### GET /api/rules/reconvert-status

Returns the current state of the reconvert background job.

**Auth**: Required
**Request body**: None

**Response** `200 OK`:
```json
{
  "success": true,
  "data": {
    "status": "running" | "idle" | "done" | "error",
    "total": 412,
    "done": 200,
    "errors": 3,
    "started_at": "2026-03-21T10:05:00Z",
    "finished_at": null
  }
}
```

**Behaviour**: UI polls this every 2 seconds while `status == "running"`. Stops polling at `done` or `error`.

---

## Settings Router (`/api/settings`)

### GET /api/settings/siem-integrations

Returns all SIEM integration records.

**Auth**: Required

**Response** `200 OK`:
```json
{
  "success": true,
  "data": [
    {
      "id": "64f...",
      "name": "Primary ELK",
      "siem_type": "elasticsearch",
      "is_default": true,
      "base_pipeline": "ecs_windows",
      "custom_field_mappings": {},
      "logsource_field_overrides": {},
      "updated_at": "2026-03-21T10:00:00Z"
    }
  ]
}
```

---

### GET /api/settings/siem-integrations/{id}

Returns a single SIEM integration by ID.

**Auth**: Required

**Response** `200 OK`: Single integration object (same shape as list item above).
**Response** `404 Not Found`: Integration not found.

---

### PUT /api/settings/siem-integrations/{id}

Updates a SIEM integration. Partial updates supported — only supplied fields are changed.

**Auth**: Required
**Request body** (all fields optional):
```json
{
  "name": "Primary ELK",
  "base_pipeline": "ecs_windows",
  "is_default": true,
  "custom_field_mappings": {
    "Hashes": "file.hash.sha256",
    "CommandLine": "process.command_line"
  },
  "logsource_field_overrides": {
    "windows/process_creation": {
      "Image": "process.executable"
    }
  }
}
```

**Response** `200 OK`: Updated integration object.
**Response** `404 Not Found`: Integration not found.

**Behaviour**:
- If `is_default: true`, atomically demotes all other integrations to `is_default: false` before saving.
- `updated_at` is set to UTC now on every save.
- `siem_type` and `connection_config` are intentionally not updatable via this endpoint in Phase 1 (ELK connection is managed via existing ELK settings).

---

### POST /api/settings/siem-integrations

Creates a new SIEM integration record.

**Auth**: Required
**Request body** (required fields):
```json
{
  "name": "QRadar Prod",
  "siem_type": "qradar",
  "base_pipeline": "none",
  "is_default": false
}
```

**Response** `201 Created`: New integration object with generated `id`.
**Response** `400 Bad Request`: Invalid `siem_type` or `base_pipeline` value.

---

## ELK Router (`/api/elk`)

### GET /api/elk/fields

Returns available field names and types from a specified Elasticsearch index pattern.

**Auth**: Required
**Query params**:
- `index` (required): Index pattern, e.g. `winlogbeat-*`

**Response** `200 OK`:
```json
{
  "success": true,
  "data": {
    "index_pattern": "winlogbeat-*",
    "fields": [
      {"name": "process.command_line", "type": "keyword"},
      {"name": "process.executable", "type": "keyword"},
      {"name": "event.action", "type": "keyword"},
      {"name": "@timestamp", "type": "date"}
    ]
  }
}
```

**Response** `200 OK` (no fields found):
```json
{
  "success": true,
  "data": {
    "index_pattern": "winlogbeat-*",
    "fields": []
  },
  "message": "No fields found for pattern 'winlogbeat-*'"
}
```

**Response** `503 Service Unavailable`: Elasticsearch unreachable.

**Behaviour**:
- Uses `get_mapping(index=pattern)` and flattens to dot-notation.
- Excludes internal fields starting with `_`.
- Returns `fields: []` (not an error) when the pattern matches no indices.
