# Quickstart: Sigma Field Mapping & Multi-SIEM Pipeline

**Branch**: `001-sigma-field-mapping` | **Date**: 2026-03-21

---

## For developers implementing this feature

### 1. Install the pySigma Windows pipeline package

```bash
cd backend
.venv/Scripts/pip install pySigma-pipeline-windows
```

Add to `backend/requirements.txt`:
```
pySigma-pipeline-windows>=2.0.0
```

> **Note**: uvicorn runs from `backend/.venv` — install there, not globally.

---

### 2. Verify the pipeline works locally

Open a Python shell in the backend venv:
```python
from sigma.pipelines.windows import ecs_windows
p = ecs_windows()
print(p)  # Should print a ProcessingPipeline with many FieldMappingTransformation entries
```

---

### 3. Run a manual conversion test

After implementing `sigma_converter.py` changes, test with a Windows rule:
```bash
cd backend
python -c "
from app.services.sigma_converter import convert_sigma_to_elk
import yaml

sigma = '''
title: Test Process
status: test
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: powershell
  condition: selection
'''
siem_config = {'base_pipeline': 'ecs_windows', 'custom_field_mappings': {}, 'logsource_field_overrides': {}}
result = convert_sigma_to_elk(sigma, siem_config=siem_config)
print(result.elk_query)
# Expected: process.command_line:*powershell* (NOT CommandLine:*powershell*)
"
```

---

### 4. Start the dev server and trigger reconvert

```bash
cd backend
.venv/Scripts/uvicorn app.main:app --reload --port 8080
```

Then test the background job:
```bash
# Start the job
curl -X POST http://localhost:8080/api/rules/reconvert-all \
  -H "Authorization: Bearer <token>"

# Poll progress
curl http://localhost:8080/api/rules/reconvert-status \
  -H "Authorization: Bearer <token>"
```

---

### 5. Verify field discovery

```bash
curl "http://localhost:8080/api/elk/fields?index=winlogbeat-*" \
  -H "Authorization: Bearer <token>"
```

Expected: List of dot-notation fields like `process.command_line`, `event.action`, etc.

---

### 6. Test SIEM integration settings

```bash
# List integrations
curl http://localhost:8080/api/settings/siem-integrations \
  -H "Authorization: Bearer <token>"

# Update base pipeline
curl -X PUT http://localhost:8080/api/settings/siem-integrations/<id> \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"base_pipeline": "none"}'
```

---

## Acceptance verification checklist

After implementation, verify these end-to-end:

- [ ] A Windows `process_creation` rule converts with `process.command_line` (not `CommandLine`) in `elk_query`
- [ ] `POST /rules/reconvert-all` returns `{"status": "running"}` immediately (non-blocking)
- [ ] `GET /rules/reconvert-status` reflects progress while job runs
- [ ] After job completes, `status` is `"done"` with correct `total` and `errors` counts
- [ ] Setting `base_pipeline: "none"` causes field names to pass through unchanged
- [ ] Custom mapping `Hashes → file.hash.sha256` is reflected in next conversion
- [ ] A rule with unmappable fields still reaches `QUEUED` status (not `FAILED`)
- [ ] `GET /elk/fields?index=winlogbeat-*` returns dot-notation field list
- [ ] Elasticsearch unreachable → `GET /elk/fields` returns 503, other settings routes unaffected
- [ ] On fresh DB, a default `SIEMIntegration` is seeded automatically
- [ ] Two simultaneous `POST /rules/reconvert-all` calls → second returns `409`
