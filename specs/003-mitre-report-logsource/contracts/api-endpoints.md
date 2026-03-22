# API Contracts: MITRE Heatmap, Detection Report, and LogSource Coverage Fix

**Date**: 2026-03-22

## New Endpoints

### 1. MITRE Matrix

```
GET /api/dashboard/mitre-matrix
Auth: Required (admin)
Response: ApiResponse<MitreMatrixData>
```

Returns the full MITRE ATT&CK Enterprise matrix with per-technique rule coverage counts. Sub-techniques are rolled up into parent techniques. Each parent includes a `subtechniques` array for drill-down.

### 2. Detection Report

```
GET /api/dashboard/detection-report
Auth: Required (admin)
Response: ApiResponse<DetectionReportData>
```

Returns a comprehensive detection posture snapshot combining rules summary, MITRE coverage, log source status, and score distribution. Generated on-demand (not cached).

### 3. Auto-Discover Log Sources

```
POST /api/log-sources/auto-discover
Auth: Required (admin)
Response: ApiResponse<{ inserted: number, skipped: number, total_unique: number }>
```

Scans all rules, extracts unique (category, product, service) combinations, and inserts missing entries into the LogSource collection with `is_available=false`. Does not overwrite existing entries.

### 4. Log Source Coverage Summary

```
GET /api/log-sources/coverage-summary
Auth: Required (admin)
Response: ApiResponse<{ total_unique_in_rules: number, exact_matches: number, partial_matches: number, product_matches: number, unmatched: number }>
```

Returns aggregated match statistics showing how many rule logsource combinations have exact, partial, product-level, or no matches in the LogSource table.

## Modified Endpoints

### 5. Rules List (existing)

```
GET /api/rules
```

**Change**: `RuleSummaryOut` response model adds field `log_source_match_type: Optional[str]` (values: `"exact"`, `"partial"`, `"product"`, `null`).

## Modified Internal Functions

### 6. `_refresh_rule_log_availability()` — `log_sources.py`

**Before**: Exact key match only (`category/product[/service]`).
**After**: Hierarchical fallback (exact → category+product → product-only). Sets both `log_source_available` and `log_source_match_type` on each rule.

### 7. `_score_log_availability()` — `scoring_engine.py`

**Before**: Independent LogSource query per rule.
**After**: Reads `rule.log_source_match_type` and `rule.log_source_available` directly. Returns graduated scores based on match confidence.
