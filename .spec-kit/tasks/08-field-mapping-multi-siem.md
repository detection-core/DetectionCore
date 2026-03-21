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
```
name, siem_type (elasticsearch|qradar|crowdstrike|splunk), connection_config, is_default
base_pipeline (ecs_windows|ecs_linux|custom_only|none)
custom_field_mappings: {SigmaField: target.field}
logsource_field_overrides: {"product/category": {SigmaField: target.field}}
updated_at
```

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
