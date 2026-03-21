# Data Model: Sigma Field Mapping & Multi-SIEM Pipeline

**Branch**: `001-sigma-field-mapping` | **Date**: 2026-03-21

---

## New Entity: SIEMIntegration (MongoDB Collection: `siem_integrations`)

Represents a configured target SIEM platform with its field mapping configuration.

### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | ObjectId | auto | Beanie document ID |
| `name` | str | yes | Human-readable label, e.g. "Primary ELK" |
| `siem_type` | str | yes | Enum: `elasticsearch` \| `qradar` \| `crowdstrike` \| `splunk` |
| `is_default` | bool | yes | Exactly one document must have `is_default = True` at all times |
| `base_pipeline` | str | yes | Enum: `ecs_windows` \| `ecs_linux` \| `custom_only` \| `none` |
| `custom_field_mappings` | dict[str, str] | no | Global overrides: `{"SigmaField": "target.field"}` |
| `logsource_field_overrides` | dict[str, dict[str, str]] | no | Per-logsource overrides: `{"windows/process_creation": {"Hashes": "file.hash.md5"}}` |
| `updated_at` | datetime | auto | Last modification timestamp (UTC) |

### Invariants

- **Exactly one default**: `is_default = True` on one document at all times. Setting a new default atomically demotes all others.
- **Valid siem_type**: Must be one of the four enumerated values. Phase 1 only creates `elasticsearch` integrations.
- **Valid base_pipeline**: Must be one of the four enumerated values. `ecs_linux` is valid but has no backing package in Phase 1 (falls back to `none` gracefully with a warning).
- **Mapping key format**: Keys in `logsource_field_overrides` must be `"{product}/{category}"` strings. Empty string keys are not permitted.

### Precedence at conversion time

1. **logsource_field_overrides** for the rule's `{product}/{category}` — highest precedence
2. **custom_field_mappings** — global overrides
3. **base_pipeline** — built-in ECS mapping (lowest precedence, applied first, overridden by above)

---

## Modified Entity: DetectionRule (existing — no schema change)

`DetectionRule` gains no new fields. The `elk_query` and `elk_rule_json` fields are updated in place when "Reconvert All" runs or a rule is reprocessed.

Relevant existing fields:

| Field | Type | Notes |
|-------|------|-------|
| `sigma_content` | str | Sigma YAML source — present on all synced rules; `reconvert-all` targets rules where this is non-empty |
| `elk_query` | str | Lucene query string — updated by reconvert |
| `elk_rule_json` | dict | Full Kibana rule JSON — updated by reconvert |
| `log_source_product` | str | e.g. `windows` — used to select logsource override key |
| `log_source_category` | str | e.g. `process_creation` — used with product to form override key |
| `pipeline_status` | str | Status enum — reconvert updates `elk_query`/`elk_rule_json` only; status is not changed by reconvert |

---

## In-Memory Structure: Reconvert Job State (app.state)

Not persisted to MongoDB — resets on server restart. Stored at `app.state.reconvert_job`.

```python
{
    "status": "idle" | "running" | "done" | "error",
    "total": int,       # total rules with sigma_content
    "done": int,        # rules processed so far
    "errors": int,      # rules that failed reconversion
    "started_at": str,  # ISO datetime
    "finished_at": str | None
}
```

Initial state (on startup): `{"status": "idle", "total": 0, "done": 0, "errors": 0, "started_at": None, "finished_at": None}`

---

## API Response Shapes

### SIEMIntegration (read)
```json
{
  "id": "64f...",
  "name": "Primary ELK",
  "siem_type": "elasticsearch",
  "is_default": true,
  "base_pipeline": "ecs_windows",
  "custom_field_mappings": {"Hashes": "file.hash.sha256"},
  "logsource_field_overrides": {
    "windows/process_creation": {"Image": "process.executable"}
  },
  "updated_at": "2026-03-21T10:00:00Z"
}
```

### Reconvert Job Status (read)
```json
{
  "status": "running",
  "total": 412,
  "done": 87,
  "errors": 0,
  "started_at": "2026-03-21T10:05:00Z",
  "finished_at": null
}
```

### Field Discovery Result (read)
```json
{
  "index_pattern": "winlogbeat-*",
  "fields": [
    {"name": "process.command_line", "type": "keyword"},
    {"name": "process.executable", "type": "keyword"},
    {"name": "@timestamp", "type": "date"}
  ]
}
```

---

## Entity Relationships

```
SIEMIntegration (1)
    └── used by → sigma_converter._build_processing_pipeline()
                      └── produces ProcessingPipeline
                              └── passed to → LuceneBackend
                                      └── converts → DetectionRule.elk_query

DetectionRule (many)
    └── sigma_content → reconvert-all job → elk_query + elk_rule_json updated
```
