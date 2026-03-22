# Tasks: MITRE Heatmap, Detection Report, and LogSource Coverage Fix

**Input**: Design documents from `/specs/003-mitre-report-logsource/`
**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Tests**: No test tasks generated (not explicitly requested in the feature specification).

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Create new directories and modules needed by multiple user stories

- [x] T001 Create `backend/app/data/__init__.py` module directory for static reference data

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Model change needed by US1, US2, US5, and downstream features

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [x] T002 Add `log_source_match_type: Optional[str] = None` field to `DetectionRule` model in `backend/app/models/rule.py` (after `log_source_available` field, ~line 98)
- [x] T003 Add `log_source_match_type: Optional[str] = None` to `RuleSummaryOut` response model in `backend/app/routers/rules.py` and include it in the summary serialization

**Checkpoint**: Foundation ready - user story implementation can now begin

---

## Phase 3: User Story 1 - Log Source Coverage Accuracy (Priority: P1) 🎯 MVP

**Goal**: Fix hierarchical log source matching so rules with available product-level sources correctly show as "covered" instead of false negatives

**Independent Test**: Upload a product-level log source (e.g., "windows") marked available → verify rules requiring any Windows log category (process_creation, file_event, etc.) show as covered with appropriate match-type indicator

### Implementation for User Story 1

- [x] T004 [US1] Rewrite `_refresh_rule_log_availability()` in `backend/app/routers/log_sources.py` (~line 133): build three lookup dicts (`exact_keys`, `cat_product_keys`, `product_keys`) from LogSource table in one query, then match each rule with three-tier fallback (exact → category+product → product-only), setting both `log_source_available` and `log_source_match_type` on each rule
- [x] T005 [US1] Update the log source column in `frontend/src/pages/Rules.tsx` to show match-type color coding: green chip for exact match, amber chip for partial/product match, red chip for unmatched
- [x] T006 [US1] Add `getLogSourceCoverageSummary()` API function to `frontend/src/api/endpoints.ts` for the coverage summary endpoint

**Checkpoint**: At this point, toggling a product-level log source to "available" should correctly mark all rules for that product as covered, with green/amber/red indicators in the Rules Library

---

## Phase 4: User Story 2 - Log Source Auto-Discovery (Priority: P1)

**Goal**: One-click auto-discovery that scans rules and populates the LogSource table with all unique logsource combinations

**Independent Test**: Click "Auto-Discover from Rules" on Log Sources page → verify all unique logsource combinations from rules appear as new entries defaulting to unavailable

### Implementation for User Story 2

- [x] T007 [P] [US2] Add `POST /api/log-sources/auto-discover` endpoint in `backend/app/routers/log_sources.py`: scan all rules, extract unique (category, product, service) combos, insert missing entries as `is_available=False`, return `{inserted, skipped, total_unique}` counts
- [x] T008 [P] [US2] Add `GET /api/log-sources/coverage-summary` endpoint in `backend/app/routers/log_sources.py`: return `{total_unique_in_rules, exact_matches, partial_matches, product_matches, unmatched}` aggregated match statistics
- [x] T009 [US2] Add `autoDiscoverLogSources()` and wire `getLogSourceCoverageSummary()` to `frontend/src/api/endpoints.ts`
- [x] T010 [US2] Add "Auto-Discover from Rules" button and coverage summary banner to `frontend/src/pages/LogSources.tsx`: button calls auto-discover endpoint, banner shows match stats from coverage-summary endpoint, refresh table after discovery

**Checkpoint**: Auto-discover populates all logsource combos from rules. Coverage banner shows match breakdown. Combined with US1, the full LogSource workflow is functional.

---

## Phase 5: User Story 3 - MITRE ATT&CK Heatmap (Priority: P2)

**Goal**: Visual MITRE ATT&CK matrix heatmap showing detection coverage per technique, with tooltips and drill-down to filtered Rules Library

**Independent Test**: Navigate to `/mitre` → verify 14 tactic columns render with technique cells colored by rule count → hover shows tooltip → click navigates to filtered Rules Library

### Implementation for User Story 3

- [x] T011 [P] [US3] Create static MITRE ATT&CK Enterprise data in `backend/app/data/mitre_attack.py`: TACTICS list (14 entries with id, name, order) and TECHNIQUES dict (~200 parent techniques + ~400 sub-techniques with name, tactic_ids, subtechniques/parent fields)
- [x] T012 [US3] Add `GET /api/dashboard/mitre-matrix` endpoint in `backend/app/routers/dashboard.py`: query all rules, map `mitre_technique_ids` to static TECHNIQUES lookup, roll up sub-techniques into parents, return `{tactics: [{tactic_id, tactic_name, techniques: [{technique_id, name, rule_count, implemented_count, subtechniques: [...]}]}], summary: {total_techniques, covered_techniques, coverage_percent}}`
- [x] T013 [US3] Add `getMitreMatrix()` API function to `frontend/src/api/endpoints.ts`
- [x] T014 [US3] Create `frontend/src/pages/MitreHeatmap.tsx`: CSS grid layout with 14 tactic columns, technique cells with dynamic background color intensity (gray=0, light blue=1, dark blue/purple=many), hover tooltip (technique name + rule count + implemented count), click handler navigating to `/rules?search={technique_id}`, summary bar showing "X of Y techniques covered (Z%)", horizontal scroll for small screens
- [x] T015 [P] [US3] Add `/mitre` route to `frontend/src/App.tsx` pointing to MitreHeatmap page
- [x] T016 [P] [US3] Add "MITRE Coverage" navigation item to `frontend/src/components/layout/Sidebar.tsx` (use Grid3X3 or Shield icon from lucide-react)

**Checkpoint**: MITRE heatmap page renders full ATT&CK matrix with coverage visualization, tooltips, and drill-down to Rules Library

---

## Phase 6: User Story 4 - Detection Status Report (Priority: P2)

**Goal**: Comprehensive detection posture report page with executive summary, MITRE coverage, log source status, scoring distribution, plus print and JSON export

**Independent Test**: Navigate to `/report` → verify all 5 sections load with current data → click Print → clean layout → click Export JSON → valid file downloads

### Implementation for User Story 4

- [x] T017 [US4] Add `GET /api/dashboard/detection-report` endpoint in `backend/app/routers/dashboard.py`: aggregate rules_summary (total, by_status, by_severity, deployed_to_elk, failed), mitre_summary (techniques covered/total, per-tactic coverage, top_uncovered), log_source_summary (total, available, unavailable, rules_covered, rules_uncovered, top_gaps), score_summary (average, median, rules_above_70, distribution by 10-point ranges), include `generated_at` ISO timestamp
- [x] T018 [US4] Add `getDetectionReport()` API function to `frontend/src/api/endpoints.ts`
- [x] T019 [US4] Create `frontend/src/pages/DetectionReport.tsx`: clean print-friendly layout with sections — Executive Summary (KPI cards grid), Pipeline Status (horizontal progress bar), MITRE Coverage (compact tactic-level progress bars), Log Source Coverage (table with status), Score Distribution (histogram using Recharts BarChart); "Print Report" button calling `window.print()`; "Export JSON" button downloading data as timestamped JSON file; `@media print` CSS hiding sidebar and nav
- [x] T020 [P] [US4] Add `/report` route to `frontend/src/App.tsx` pointing to DetectionReport page
- [x] T021 [P] [US4] Add "Detection Report" navigation item to `frontend/src/components/layout/Sidebar.tsx` (use FileText icon from lucide-react)

**Checkpoint**: Detection report page renders all sections with live data. Print produces clean output. JSON export downloads valid data file.

---

## Phase 7: User Story 5 - Graduated Scoring for Log Source Matches (Priority: P3)

**Goal**: Rule relevance scoring reflects log source match confidence — exact matches score higher than product-only matches

**Independent Test**: Compare scores of two rules — one with exact log source match and one with product-only match — verify the exact match scores higher on the log source component

### Implementation for User Story 5

- [x] T022 [US5] Modify `_score_log_availability()` in `backend/app/services/scoring_engine.py` (~line 77): replace independent LogSource query with reading `rule.log_source_match_type` and `rule.log_source_available` directly; return graduated scores: exact+available=100, partial+available=90, product+available=70, no match type but fields present=50 (neutral), unavailable=0, no log source fields=50 (neutral)

**Checkpoint**: Scores now reflect match confidence. Recalculating scores shows differentiated log source component values.

---

## Phase 8: Polish & Cross-Cutting Concerns

**Purpose**: Edge cases, empty states, and final validation across all stories

- [x] T023 [P] Verify all pages handle empty state gracefully (zero rules, zero log sources, no MITRE data) — `frontend/src/pages/MitreHeatmap.tsx`, `frontend/src/pages/DetectionReport.tsx`, `frontend/src/pages/LogSources.tsx`
- [x] T024 [P] Verify sub-technique rollup works correctly: rules with T1059.001 aggregate into T1059 parent in heatmap — `backend/app/routers/dashboard.py`
- [x] T025 Run quickstart.md verification steps end-to-end for all three phases

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion — BLOCKS all user stories
- **US1 (Phase 3)**: Depends on Foundational (Phase 2) — no other story dependencies
- **US2 (Phase 4)**: Depends on Foundational (Phase 2) — enhanced by US1 being complete (coverage summary uses match types)
- **US3 (Phase 5)**: Depends on Foundational (Phase 2) — independent of US1/US2
- **US4 (Phase 6)**: Depends on Foundational (Phase 2) — benefits from US3 (reuses MITRE data module from T011) and US1/US2 (log source coverage data)
- **US5 (Phase 7)**: Depends on US1 (Phase 3) — reads `log_source_match_type` set by the hierarchical matching rewrite
- **Polish (Phase 8)**: Depends on all user stories being complete

### User Story Dependencies

- **US1 (P1)**: Can start after Phase 2 — no dependencies on other stories
- **US2 (P1)**: Can start after Phase 2 — independent but pairs naturally with US1
- **US3 (P2)**: Can start after Phase 2 — independent (T011 creates the MITRE data module)
- **US4 (P2)**: Can start after Phase 2 — but ideally after US3 (reuses mitre_attack.py from T011) and US1 (accurate log source data)
- **US5 (P3)**: MUST start after US1 (Phase 3) — depends on `log_source_match_type` field being populated

### Within Each User Story

- Backend endpoints before frontend pages
- API client functions before page components
- Core logic before UI polish

### Parallel Opportunities

- T007 and T008 (US2 backend endpoints) can run in parallel
- T011 (MITRE data) can run in parallel with any US1/US2 tasks
- T015, T016 (route + sidebar for MITRE) can run in parallel with T014 (page)
- T020, T021 (route + sidebar for report) can run in parallel with T019 (page)
- US1, US2, US3 can all proceed in parallel after Phase 2

---

## Parallel Example: Phase 3-5 Kickoff

```bash
# After Foundational (Phase 2) completes, launch in parallel:

# US1: Rewrite hierarchical matching
Task: T004 "Rewrite _refresh_rule_log_availability() in backend/app/routers/log_sources.py"

# US2: Auto-discover endpoint (parallel backend work)
Task: T007 "Add POST /api/log-sources/auto-discover in backend/app/routers/log_sources.py"
Task: T008 "Add GET /api/log-sources/coverage-summary in backend/app/routers/log_sources.py"

# US3: MITRE data (independent file)
Task: T011 "Create static MITRE data in backend/app/data/mitre_attack.py"
```

---

## Implementation Strategy

### MVP First (User Stories 1 + 2 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational (model field addition)
3. Complete Phase 3: US1 — Hierarchical matching fix
4. Complete Phase 4: US2 — Auto-discovery
5. **STOP and VALIDATE**: Toggle log sources, verify rules show correct coverage status
6. Deploy/demo if ready — the core bug fix is live

### Incremental Delivery

1. Setup + Foundational → Foundation ready
2. US1 + US2 → LogSource accuracy fixed → Deploy (MVP!)
3. US3 → MITRE heatmap live → Deploy
4. US4 → Detection report live → Deploy
5. US5 → Graduated scoring → Deploy
6. Each story adds value without breaking previous stories

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- Each user story should be independently completable and testable
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- US4 (Detection Report) imports `mitre_attack.py` from US3 — if implementing US4 before US3, create the data module first
- The `_refresh_rule_log_availability()` rewrite (T004) is the most complex single task — it replaces the current exact-match logic with three-tier hierarchical matching
