# Data Model: MITRE Heatmap, Detection Report, and LogSource Coverage Fix

**Date**: 2026-03-22

## Modified Entities

### DetectionRule (existing — `backend/app/models/rule.py`)

**New field**:
- `log_source_match_type: Optional[str] = None` — Values: `"exact"`, `"partial"`, `"product"`, `None`
  - Set by `_refresh_rule_log_availability()` alongside `log_source_available`
  - Read by `_score_log_availability()` for graduated scoring
  - Returned in `RuleSummaryOut` for frontend color coding

**Existing fields used** (no changes):
- `log_source_category: Optional[str]`
- `log_source_product: Optional[str]`
- `log_source_service: Optional[str]`
- `log_source_available: bool`
- `mitre_technique_ids: list[str]`
- `mitre_tactic: Optional[str]`
- `pipeline_status: PipelineStatus`
- `severity: Severity`
- `scoring: ScoringResult`

### LogSource (existing — `backend/app/models/log_source.py`)

No schema changes. Existing fields provide all needed data:
- `category`, `product`, `service` — used for hierarchical matching
- `is_available` — availability flag
- `key` property — composite key `category/product[/service]`

## New Reference Data

### MITRE ATT&CK Lookup (`backend/app/data/mitre_attack.py`)

Static Python data, not a database entity.

**TACTICS** (list of 14 dicts):
- `id: str` — e.g., "TA0001"
- `name: str` — e.g., "Initial Access"
- `order: int` — display order (1-14)

**TECHNIQUES** (dict keyed by technique ID):
- `name: str` — e.g., "Phishing"
- `tactic_ids: list[str]` — e.g., ["TA0001"] (techniques can span multiple tactics)
- `subtechniques: list[str]` — e.g., ["T1566.001", "T1566.002"] (only on parent techniques)
- `parent: str` — e.g., "T1566" (only on sub-techniques)

## API Response Shapes

### MITRE Matrix Response

```
GET /api/dashboard/mitre-matrix

{
  tactics: [
    {
      tactic_id: string,
      tactic_name: string,
      techniques: [
        {
          technique_id: string,
          name: string,
          rule_count: number,          // total rules (parent + sub-technique rollup)
          implemented_count: number,    // rules with status IMPLEMENTED
          subtechniques: [
            {
              technique_id: string,
              name: string,
              rule_count: number,
              implemented_count: number
            }
          ]
        }
      ]
    }
  ],
  summary: {
    total_techniques: number,
    covered_techniques: number,
    coverage_percent: number
  }
}
```

### Detection Report Response

```
GET /api/dashboard/detection-report

{
  generated_at: string (ISO datetime),
  rules_summary: {
    total: number,
    by_status: { [status: string]: number },
    by_severity: { [severity: string]: number },
    deployed_to_elk: number,
    failed: number
  },
  mitre_summary: {
    techniques_covered: number,
    techniques_total: number,
    coverage_percent: number,
    tactics_coverage: [
      { tactic: string, covered: number, total: number }
    ],
    top_uncovered: [
      { technique_id: string, name: string, tactic: string }
    ]
  },
  log_source_summary: {
    total_sources: number,
    available: number,
    unavailable: number,
    rules_covered: number,
    rules_uncovered: number,
    top_gaps: [
      { source: string, blocked_rules: number }
    ]
  },
  score_summary: {
    average_score: number,
    median_score: number,
    rules_above_70: number,
    distribution: [
      { range: string, count: number }
    ]
  }
}
```

### Auto-Discover Response

```
POST /api/log-sources/auto-discover

{
  inserted: number,
  skipped: number,
  total_unique: number
}
```

### Coverage Summary Response

```
GET /api/log-sources/coverage-summary

{
  total_unique_in_rules: number,
  exact_matches: number,
  partial_matches: number,
  product_matches: number,
  unmatched: number
}
```

## State Transitions

No new state transitions. The `log_source_match_type` field is computed (not user-set) and updates whenever `_refresh_rule_log_availability()` runs (after log source upload, toggle, or auto-discover).

## Relationships

```
DetectionRule --[has logsource]--> LogSource (via category/product/service matching)
DetectionRule --[has techniques]--> MITRE Technique (via mitre_technique_ids array)
MITRE Technique --[belongs to]--> MITRE Tactic (via tactic_ids in static lookup)
MITRE Technique --[has subtechniques]--> MITRE Technique (parent/child via static lookup)
```
