# Feature Specification: MITRE Heatmap, Detection Report, and LogSource Coverage Fix

**Feature Branch**: `003-mitre-report-logsource`
**Created**: 2026-03-22
**Status**: Draft
**Input**: User description: "MITRE ATT&CK heatmap for detection gap visualization, detection status report page, and hierarchical logsource coverage matching fix"

## Clarifications

### Session 2026-03-22

- Q: Should the MITRE heatmap show sub-techniques individually (~600 cells) or roll them up to parent techniques (~200 cells)? → A: Roll up to parent techniques only. Sub-technique rule counts aggregate into the parent. Clicking a parent cell drills down to show its sub-techniques.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Log Source Coverage Accuracy (Priority: P1)

As a security analyst, I need the platform to correctly identify which log sources my organization has available, so that rule coverage status and scoring accurately reflect my real detection capabilities rather than showing false negatives due to rigid matching.

**Why this priority**: This is the foundation for all other features. Incorrect log source coverage cascades into wrong scores, misleading reports, and inaccurate MITRE gap analysis. Fixing this first ensures all downstream features display trustworthy data.

**Independent Test**: Can be tested by uploading a product-level log source (e.g., "windows" with winlogbeat) and verifying that all rules requiring any Windows log category (process_creation, file_event, network_connection, etc.) correctly show as covered.

**Acceptance Scenarios**:

1. **Given** a log source entry exists for product "windows" marked as available, **When** the system evaluates a rule with logsource `product: windows, category: process_creation`, **Then** the rule is marked as covered with a "product-level match" indicator.
2. **Given** a log source entry exists for `category: process_creation, product: windows` marked as available, **When** the system evaluates a rule with that exact logsource, **Then** the rule is marked as covered with an "exact match" indicator.
3. **Given** no log source entry exists matching a rule's product, **When** the system evaluates that rule, **Then** the rule is marked as "not covered" (unmatched).
4. **Given** a log source entry exists for the product but is marked unavailable, **When** the system evaluates rules for that product, **Then** rules are marked as "not covered" with the source shown as unavailable.
5. **Given** a rule has logsource `product: windows, category: file_event, service: sysmon`, **When** the system evaluates coverage, **Then** it first checks for an exact match (category+product+service), then falls back to category+product, then falls back to product-only.

---

### User Story 2 - Log Source Auto-Discovery (Priority: P1)

As a platform administrator, I need to automatically populate the log source inventory from the rules already in the system, so I don't have to manually create entries for every unique logsource combination across hundreds of rules.

**Why this priority**: Manually creating log source entries for every category/product/service combination is impractical. Auto-discovery enables administrators to quickly see what their rules require and toggle availability, directly supporting accurate coverage.

**Independent Test**: Can be tested by clicking "Auto-Discover from Rules" on the Log Sources page and verifying that all unique logsource combinations from the rules library appear as new entries ready to be toggled.

**Acceptance Scenarios**:

1. **Given** the system has 67 rules with 15 unique logsource combinations, **When** the administrator triggers auto-discovery, **Then** 15 log source entries are created (minus any that already exist), each defaulting to "unavailable".
2. **Given** some auto-discovered log sources already exist in the table, **When** auto-discovery runs, **Then** existing entries are not duplicated or overwritten.
3. **Given** auto-discovery has completed, **When** the administrator views the Log Sources page, **Then** they see a summary showing how many new entries were created and the overall match coverage stats.

---

### User Story 3 - MITRE ATT&CK Heatmap Visualization (Priority: P2)

As a security analyst, I need a visual MITRE ATT&CK matrix heatmap showing which techniques are covered by detection rules and which are not, so I can quickly identify detection gaps and prioritize rule development efforts.

**Why this priority**: The MITRE heatmap is the primary visual deliverable for detection gap analysis. It depends on accurate MITRE technique data already stored on rules and becomes more valuable once log source coverage (P1) is accurate.

**Independent Test**: Can be tested by navigating to the MITRE Coverage page and verifying that the matrix displays all 14 tactics with their techniques, color-coded by the number of rules covering each technique.

**Acceptance Scenarios**:

1. **Given** the system has rules covering techniques T1059, T1053, and T1566, **When** the analyst views the MITRE heatmap, **Then** those technique cells are highlighted with color intensity proportional to rule count, while uncovered techniques appear in a neutral/gray color.
2. **Given** a technique cell shows coverage, **When** the analyst hovers over it, **Then** a tooltip displays the technique name, number of detection rules, and number of deployed/implemented rules.
3. **Given** a technique cell is displayed, **When** the analyst clicks it, **Then** they are navigated to the Rules Library filtered to show only rules covering that technique.
4. **Given** the system has rules loaded, **When** the analyst views the heatmap page, **Then** a summary bar shows "X of Y techniques covered (Z%)" with total coverage statistics.
5. **Given** the heatmap is displayed on a smaller screen, **When** all 14 tactic columns don't fit, **Then** the matrix is horizontally scrollable.

---

### User Story 4 - Detection Status Report (Priority: P2)

As a security manager, I need a comprehensive detection status report showing the current state of my detection program, so I can communicate detection posture to stakeholders and track improvement over time.

**Why this priority**: The report aggregates data from all other features into an executive-level view. It is most valuable once log source coverage and MITRE data are accurate.

**Independent Test**: Can be tested by navigating to the Detection Report page and verifying that all summary sections populate with current data and the report can be printed or exported.

**Acceptance Scenarios**:

1. **Given** the system has rules at various pipeline stages, **When** the manager views the detection report, **Then** they see a rules summary showing total rules, rules by status (synced, converted, deployed, failed), and rules by severity.
2. **Given** the system has MITRE technique coverage data, **When** the manager views the report, **Then** they see a MITRE summary with covered vs total techniques, per-tactic coverage breakdown, and a list of uncovered high-priority techniques.
3. **Given** the system has log source data, **When** the manager views the report, **Then** they see a log source summary showing available vs unavailable sources, number of rules blocked by missing sources, and top coverage gaps.
4. **Given** the system has scored rules, **When** the manager views the report, **Then** they see a score summary with average score, score distribution, and count of rules above a quality threshold.
5. **Given** the report is displayed, **When** the manager clicks "Print Report", **Then** the browser print dialog opens with a clean, formatted layout (no sidebar or navigation elements).
6. **Given** the report is displayed, **When** the manager clicks "Export JSON", **Then** the raw report data downloads as a JSON file with a timestamp in the filename.

---

### User Story 5 - Graduated Scoring for Log Source Matches (Priority: P3)

As a security analyst, I need the rule relevance scoring to reflect the confidence level of log source matching, so that rules with exact log source matches score higher than rules matched only at the product level.

**Why this priority**: Builds on the hierarchical matching (P1) to provide nuanced scoring. Important for prioritization accuracy but not a blocker for other features.

**Independent Test**: Can be tested by comparing scores of two rules — one with an exact log source match and one with a product-only match — and verifying the exact match scores higher on the log source component.

**Acceptance Scenarios**:

1. **Given** a rule has an exact log source match, **When** its score is calculated, **Then** the log source component contributes the maximum score.
2. **Given** a rule has a category+product match (no service match), **When** its score is calculated, **Then** the log source component contributes a slightly reduced score (approximately 90% of maximum).
3. **Given** a rule has only a product-level match, **When** its score is calculated, **Then** the log source component contributes a moderately reduced score (approximately 70% of maximum).
4. **Given** a rule has no log source match at all, **When** its score is calculated, **Then** the log source component contributes a neutral score (approximately 50% of maximum).

---

### Edge Cases

- What happens when a rule has no logsource information (null product and category)? The system treats it as unmatched and assigns neutral scoring.
- What happens when auto-discovery runs on a system with no rules? The system returns zero new entries with an appropriate message.
- What happens when the MITRE heatmap loads but rules have no MITRE technique data? The matrix renders with all techniques in gray (uncovered), and the summary shows 0% coverage.
- What happens when a sub-technique (e.g., T1059.001) is stored on a rule? Its rule count is aggregated into the parent technique (T1059) for the heatmap display. Clicking the parent cell shows a drill-down with individual sub-technique coverage.
- What happens when the detection report is generated while the system has zero rules? All sections display zero counts with no errors.
- What happens when multiple log source entries exist for the same product with conflicting availability (one available, one not)? If any entry for the product is marked available, the product-level match resolves as available.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST match rules to log sources using hierarchical fallback: exact (category+product+service) first, then category+product, then product-only.
- **FR-002**: System MUST indicate the match confidence level (exact, partial, product-level, unmatched) for each rule's log source status.
- **FR-003**: System MUST provide a one-click auto-discovery action that scans all rules and populates the log source inventory with every unique logsource combination found.
- **FR-004**: Auto-discovery MUST NOT overwrite or duplicate existing log source entries.
- **FR-005**: System MUST display a MITRE ATT&CK matrix with all 14 Enterprise tactics and their associated techniques.
- **FR-006**: Each technique cell in the MITRE matrix MUST visually indicate coverage intensity based on number of detection rules.
- **FR-007**: System MUST provide technique-level drill-down from the MITRE matrix to the filtered Rules Library.
- **FR-008**: System MUST display a coverage summary (covered techniques count, total techniques, coverage percentage) on the MITRE matrix page.
- **FR-009**: System MUST provide a comprehensive detection report combining rules summary, MITRE coverage, log source status, and scoring distribution.
- **FR-010**: The detection report MUST be printable with a clean layout (no application navigation or chrome).
- **FR-011**: The detection report MUST be exportable as structured data (JSON format).
- **FR-012**: Rule relevance scoring MUST incorporate log source match confidence level, with higher confidence matches producing higher scores.
- **FR-013**: The Rules Library log source column MUST visually distinguish between exact matches, partial matches, and unmatched rules using color coding.
- **FR-014**: The MITRE matrix MUST roll up sub-techniques (e.g., T1059.001) into their parent technique cell, aggregating rule counts. Clicking a parent cell MUST show a drill-down with individual sub-technique coverage.

### Key Entities

- **Log Source**: Represents a type of security telemetry the organization can collect. Key attributes: category (event type), product (source platform), service (collection agent), availability status, match confidence when linked to rules.
- **MITRE Technique**: A specific adversary behavior from the MITRE ATT&CK framework. Key attributes: technique ID, name, parent tactic(s). Techniques are linked to detection rules via technique IDs stored on rules.
- **MITRE Tactic**: A high-level adversary objective (14 total in Enterprise ATT&CK). Tactics group techniques and form the columns of the ATT&CK matrix.
- **Detection Report**: A point-in-time snapshot of the organization's detection posture. Combines aggregated metrics from rules, MITRE coverage, log sources, and scoring into a single exportable artifact.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Rules with available log sources at the product level are correctly identified as covered — zero false negatives for product-level matches when the product source is marked available.
- **SC-002**: Auto-discovery populates all unique logsource combinations from rules in a single action, reducing manual log source entry effort to zero for initial setup.
- **SC-003**: The MITRE ATT&CK heatmap displays all 14 Enterprise tactics with their techniques, and analysts can identify uncovered techniques within 10 seconds of viewing the page.
- **SC-004**: The detection report loads all sections within 5 seconds and can be printed or exported in under 2 additional clicks.
- **SC-005**: Log source match confidence is visible at a glance in the Rules Library — analysts can distinguish exact, partial, and unmatched rules without clicking into individual rule details.
- **SC-006**: The MITRE coverage percentage accurately reflects the ratio of techniques with at least one detection rule to the total techniques in the Enterprise ATT&CK matrix.

## Assumptions

- The MITRE ATT&CK Enterprise matrix data (14 tactics, ~200 techniques) can be embedded as a static reference dataset, updated approximately once per year when MITRE publishes new versions.
- Rules already have `mitre_technique_ids` populated during the sync/enrichment pipeline. The heatmap relies on this existing data.
- The hierarchical log source matching assumes that if a product-level source (e.g., "windows") is available, all event categories for that product are collectible. This is a reasonable default for most SIEM deployments with agents like winlogbeat or sysmon.
- The detection report is generated on-demand (not scheduled). Caching or scheduling may be added in a future iteration if report generation becomes slow.
- Print formatting uses the browser's native print dialog and CSS print media queries. No server-side PDF generation is required.
