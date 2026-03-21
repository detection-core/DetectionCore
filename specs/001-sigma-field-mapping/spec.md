# Feature Specification: Sigma Field Mapping & Multi-SIEM Conversion Pipeline

**Feature Branch**: `001-sigma-field-mapping`
**Created**: 2026-03-21
**Status**: Draft
**Input**: Field Mapping and Multi-SIEM Conversion Pipeline

## Clarifications

### Session 2026-03-21

- Q: Is "Reconvert All Rules" synchronous (blocks until complete) or asynchronous (background job with progress)? → A: Asynchronous — starts a background job; UI polls for progress/completion
- Q: Are "administrator" and "detection engineer" separate access roles or informal labels for the same user? → A: Same role — any authenticated user can access both SIEM integration settings and field discovery
- Q: Which rules does "Reconvert All Rules" include — by pipeline status? → A: All rules with Sigma content, regardless of status (including implemented and failed)
- Q: Does "Reconvert All" auto-redeploy implemented rules to Kibana, or require manual re-deploy? → A: Manual re-deploy only — reconvert updates the stored query; the user must explicitly re-deploy via the existing workflow

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Automatic ECS Field Mapping for Windows Rules (Priority: P1)

As an administrator, when Sigma rules are converted for deployment to an ELK stack, the field names in the resulting detection query automatically match what Winlogbeat/ECS actually stores in Elasticsearch — so that deployed rules find real events instead of matching nothing.

Today, a Windows Sigma rule referencing `CommandLine` is deployed to Kibana as-is. Winlogbeat stores this field as `process.command_line`. The rule fires zero alerts because the field name never matches.

**Why this priority**: Without this fix, every deployed Windows detection rule silently fails. This is the core value of the entire feature and must ship first.

**Independent Test**: Convert a Windows process-creation Sigma rule and verify the output query uses `process.command_line` instead of `CommandLine`, then deploy it and confirm it matches events in a `winlogbeat-*` data stream.

**Acceptance Scenarios**:

1. **Given** a Windows Sigma rule with field `CommandLine`, **When** it is converted for ELK, **Then** the output query uses `process.command_line`
2. **Given** a Windows Sigma rule with field `Image`, **When** it is converted, **Then** the output uses `process.executable`
3. **Given** a Linux Sigma rule and no Linux pipeline is configured, **When** it is converted, **Then** the rule is still processed (fields pass through unchanged) and enters the Intake Queue for manual review — it does not fail
4. **Given** rules that have already been stored with unmapped field names, **When** an administrator triggers "Reconvert All Rules", **Then** all existing rules are updated with the correct mapped field names

---

### User Story 2 - Custom Field Mapping Overrides (Priority: P2)

As an authenticated user, I can define custom field name overrides in the Settings UI for log sources that don't follow a standard naming convention — such as proprietary SIEMs, internal applications, or custom-parsed logs — so that rules covering those sources also produce valid queries.

**Why this priority**: Standard pipelines cover Windows and major platforms, but every organisation has some non-standard sources. Without custom overrides, those rules are permanently broken until manually edited one by one.

**Independent Test**: Add a custom mapping `Hashes → file.hash.sha256` in Settings, reconvert a rule that uses `Hashes`, and verify the converted query contains `file.hash.sha256`.

**Acceptance Scenarios**:

1. **Given** no custom mapping exists, **When** a rule uses a Sigma field not covered by the base pipeline, **Then** the field passes through unchanged and the rule appears in the Intake Queue for review
2. **Given** an admin adds a custom mapping `CustomField → custom.ecs.field`, **When** any rule referencing `CustomField` is converted, **Then** the output uses `custom.ecs.field`
3. **Given** a per-log-source override is defined for `windows/process_creation: {Hashes: file.hash.md5}`, **When** a process-creation rule is converted, **Then** the scoped override takes priority over the global custom mapping
4. **Given** an admin deletes a custom mapping, **When** affected rules are reconverted, **Then** those fields revert to the base pipeline behaviour

---

### User Story 3 - SIEM Integration Configuration Management (Priority: P2)

As an administrator, I can view and manage SIEM integration configurations — choosing which base field mapping pipeline applies (e.g., ECS Windows, ECS Linux, Custom Only, or None) — without needing to edit configuration files or restart the system.

**Why this priority**: Different deployments use different log shippers and schemas. Admins need a UI to switch between mapping modes without engineering involvement.

**Independent Test**: Via the Settings UI, change the base pipeline from "ECS Windows" to "None", reconvert a rule, and verify field names pass through unchanged.

**Acceptance Scenarios**:

1. **Given** an existing ELK integration, **When** an admin opens Settings > SIEM Integrations, **Then** the current configuration is displayed including base pipeline selection and custom field mappings
2. **Given** an admin changes the base pipeline to "None", **When** rules are converted, **Then** Sigma field names pass through unchanged
3. **Given** multiple SIEM integrations exist, **When** one is marked as default, **Then** conversions use that integration's configuration
4. **Given** an admin saves changes to a SIEM integration, **Then** the change takes effect for all subsequent conversions without a server restart

---

### User Story 4 - Field Discovery from Elasticsearch (Priority: P3)

As an authenticated user, I can browse the actual field names present in a selected Elasticsearch data stream directly from the Settings UI — so I can identify the correct target field name when creating custom mappings.

**Why this priority**: Without field discovery, engineers must look up field names manually in Kibana or documentation. Discovery speeds up custom mapping creation and reduces errors.

**Independent Test**: Select `winlogbeat-*` in the field discovery panel and verify that known ECS fields like `process.command_line` appear in the results.

**Acceptance Scenarios**:

1. **Given** an Elasticsearch connection is configured, **When** an admin selects a data stream in the field discovery panel, **Then** a list of available field names and their types is shown
2. **Given** a nested field like `process.command_line`, **When** displayed in discovery results, **Then** it appears in dot-notation form (not nested JSON)
3. **Given** no matching data stream exists for the selected pattern, **When** field discovery is triggered, **Then** a clear "no fields found" message is shown rather than an error

---

### User Story 5 - Multi-SIEM Extensibility Foundation (Priority: P3)

As a platform administrator, the SIEM integration model is designed so that future integrations (QRadar, CrowdStrike, Splunk) can be added by configuring a new integration record — without restructuring existing data or breaking current ELK deployments.

**Why this priority**: This is an architectural quality requirement. It doesn't deliver immediate user value but prevents costly rework when a second SIEM is added.

**Independent Test**: Verify that a second SIEM integration record can be created with a different type alongside the existing ELK integration, and that the ELK integration continues to function as default.

**Acceptance Scenarios**:

1. **Given** an ELK integration is the default, **When** a new integration with a different SIEM type is created, **Then** the ELK integration remains default and unaffected
2. **Given** the integration data model, **When** a new SIEM type needs to be supported in future, **Then** no existing integration records require migration or restructuring

---

### Edge Cases

- What happens when a Sigma rule has fields that are partially mapped (some fields mapped, some not)? The rule converts with mapped fields in ECS format and unmapped fields pass through unchanged — the rule still reaches the Intake Queue for human review.
- What happens when "Reconvert All Rules" is triggered while a rule is actively mid-pipeline (e.g. being enhanced by AI)? Rules in an actively running pipeline stage are skipped for that job run to avoid partial overwrites; they will be reconverted on the next manual trigger.
- What happens if the base pipeline package is not installed on the server? The system falls back gracefully to "none" mode, logs a warning, and the rule enters the Intake Queue for manual review — no hard failure.
- What happens when a custom mapping conflicts with the base pipeline? The custom mapping takes precedence; the more specific logsource-scoped override takes highest priority over global custom mappings.
- What happens to implemented rules (live in Kibana) after "Reconvert All"? Their stored query is updated with correct field names, but the live Kibana rule is not touched automatically. The user must review the updated query via the existing Intake Queue workflow and re-deploy manually.
- What happens when Elasticsearch is unreachable during field discovery? A clear error message is shown; field discovery is the only affected panel — all other settings remain functional.
- What happens when there are thousands of rules and "Reconvert All" is triggered? The operation runs as an async background job; the UI shows progress and does not block. The user can navigate away and return — the job continues independently.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST apply ECS Windows field mappings automatically when converting Sigma rules for an integration configured with the "ECS Windows" base pipeline
- **FR-002**: The system MUST support four base pipeline modes: ECS Windows, ECS Linux, Custom Only, and None
- **FR-003**: Administrators MUST be able to define global custom field mapping overrides (Sigma field → target field) that apply across all rule conversions
- **FR-004**: Administrators MUST be able to define per-log-source field mapping overrides that take precedence over global custom mappings for their specific log source
- **FR-005**: The system MUST provide a "Reconvert All Rules" action that starts an asynchronous background job re-running conversion for all rules that have Sigma content, regardless of their current pipeline status (including implemented and failed rules); the job updates stored queries only and MUST NOT automatically redeploy rules to Kibana; the UI MUST poll and display job progress and a final count of updated rules
- **FR-006**: Detection rules with fields that cannot be mapped MUST still progress to the Intake Queue for manual review — unmapped fields must not cause conversion failure
- **FR-007**: The system MUST store SIEM integration configuration persistently so all changes survive server restarts
- **FR-008**: Administrators MUST be able to view and update SIEM integration settings through the application UI without editing server files
- **FR-009**: The system MUST support multiple SIEM integration records of different types simultaneously, with exactly one designated as default
- **FR-010**: The system MUST provide a field discovery capability that lists available field names and types from a selected Elasticsearch data stream
- **FR-011**: The conversion pipeline MUST automatically use the default SIEM integration's field mapping configuration when processing all rules
- **FR-012**: The system MUST seed a default ELK integration automatically on first run using existing connection settings, requiring no manual setup for current users

### Key Entities

- **SIEM Integration**: Represents a configured security platform target. Has a name, type (ELK/QRadar/CrowdStrike/Splunk), a base field mapping pipeline selection, global custom field overrides, per-log-source field overrides, and a default flag. Exactly one integration is the active default at any time.
- **Base Pipeline**: A named field mapping profile that translates Sigma's generic field names to the target platform's schema. Built-in options cover Windows ECS and Linux ECS; "Custom Only" applies only manual overrides; "None" passes fields through unchanged.
- **Custom Field Mapping**: An administrator-defined mapping from a Sigma field name to a platform-specific field name. Can be global (applies to all rules) or scoped to a specific log source type (higher precedence).
- **Detection Rule**: An existing entity (Sigma rule + converted query). Rules store the converted query and are re-converted when field mapping configuration changes via "Reconvert All Rules".

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Deployed Windows detection rules match real events in Winlogbeat data streams — zero false negatives caused by field name mismatches on standard Windows log sources after conversion
- **SC-002**: 100% of existing stored Windows rules are updated with correct target field names after a single "Reconvert All Rules" operation
- **SC-003**: An administrator can configure custom field overrides and reconvert all rules entirely through the UI — no server restarts or file edits required
- **SC-004**: Any authenticated user can identify the correct target field name for a custom mapping within 60 seconds using the field discovery panel
- **SC-005**: Adding a second SIEM integration type in future requires zero changes to existing integration records and no database migrations
- **SC-006**: Rules with partially or fully unmappable fields reach the Intake Queue for manual review in 100% of cases — none are silently dropped or marked as failed

## Assumptions

- Phase 1 targets ELK (Elasticsearch/Kibana) with Winlogbeat using ECS field naming. Linux and macOS pipelines are out of scope for Phase 1 but the model accommodates them.
- A single default SIEM integration per deployment is sufficient for Phase 1. Multi-target fan-out (deploying the same rule to multiple SIEMs simultaneously) is out of scope.
- The "Reconvert All Rules" action is a manual admin-triggered asynchronous background job. It is not triggered automatically on configuration change. The UI polls for progress and displays a completion count.
- Field discovery is read-only — it does not modify index mappings or create new fields.
- Custom field mappings are stored centrally per SIEM integration. Per-rule manual edits remain handled via the existing Intake Queue workflow.
- The system seeds a default ELK integration automatically on first run, so existing users require no manual setup.

## Out of Scope

- Automatic field mapping for Linux, macOS, and cloud (Azure, AWS) Sigma rules in Phase 1 — planned as future additions
- Fan-out deployment: simultaneously deploying the same converted rule to multiple SIEM targets
- Automated reconversion triggered automatically when configuration changes (reconvert must be manually initiated)
- Creating or modifying Elasticsearch index mappings via this feature
- Role-based access control for SIEM integration settings — all authenticated users have equal access in Phase 1
- Automatic redeployment of implemented rules to Kibana when field mappings change — re-deploy is always a manual step
