# Research: MITRE Heatmap, Detection Report, and LogSource Coverage Fix

**Date**: 2026-03-22
**Branch**: `003-mitre-report-logsource`

## R1: MITRE ATT&CK Static Data Source

**Decision**: Embed a static Python dict in `backend/app/data/mitre_attack.py` containing the Enterprise ATT&CK v16 matrix (14 tactics, ~200 parent techniques, ~400 sub-techniques).

**Rationale**: Runtime API calls to MITRE STIX server add latency and a failure point. The matrix changes ~once/year. A static dict is fast, reliable, and simple. The file will be ~400 lines.

**Alternatives considered**:
- `mitreattack-python` package: Adds dependency, slower startup, overkill for a lookup table.
- STIX JSON download at runtime: Network dependency, caching complexity.
- Database collection: Unnecessary indirection for read-only reference data.

**Data structure**:
```python
TACTICS = [
    {"id": "TA0001", "name": "Initial Access", "order": 1},
    {"id": "TA0002", "name": "Execution", "order": 2},
    ...
]

TECHNIQUES = {
    "T1566": {"name": "Phishing", "tactic_ids": ["TA0001"], "subtechniques": ["T1566.001", "T1566.002", "T1566.003"]},
    "T1566.001": {"name": "Spearphishing Attachment", "tactic_ids": ["TA0001"], "parent": "T1566"},
    ...
}
```

## R2: Hierarchical Log Source Matching Strategy

**Decision**: Three-tier fallback with lookup dicts built once per refresh cycle.

**Rationale**: The current `_refresh_rule_log_availability()` does one DB query per rule (N+1). Building dicts from all LogSource entries first (one query) then matching in-memory is O(N+M) instead of O(N*M). The three tiers (exact → category+product → product) match real-world SIEM deployment patterns where agents collect all event types for a product.

**Alternatives considered**:
- MongoDB aggregation pipeline: More complex, harder to debug, same result.
- Single product-level matching only: Too coarse — loses value of exact matches.
- Fuzzy/regex matching: Over-engineered, unpredictable results.

**Conflict resolution**: When multiple LogSource entries exist for the same product with different availability, use OR logic — if ANY entry is available, the product-level match resolves as available. This matches the real-world assumption: if you have any Windows log source, you can collect Windows events.

## R3: Scoring Integration for Match Types

**Decision**: Modify `_score_log_availability()` to use the pre-computed `log_source_match_type` field on the rule rather than doing its own LogSource query.

**Rationale**: Currently `_score_log_availability()` independently queries LogSource with filters (lines 77-93 of scoring_engine.py). After the hierarchical matching rewrite, `_refresh_rule_log_availability()` already computes and stores both `log_source_available` and `log_source_match_type` on the rule. The scoring function should read these cached values instead of re-querying, which is faster and consistent.

**Score mapping**:
- `match_type == "exact"` and available → 100.0
- `match_type == "partial"` and available → 90.0
- `match_type == "product"` and available → 70.0
- No match type but log source fields present → 50.0 (neutral)
- `log_source_available == False` (exists but unavailable) → 0.0
- No log source fields at all → 50.0 (neutral)

## R4: Frontend Heatmap Rendering Approach

**Decision**: Custom CSS grid with Tailwind classes. No additional charting library needed.

**Rationale**: The MITRE ATT&CK matrix is a columnar grid (14 tactic columns, variable-height technique lists). Recharts is designed for data charts (bar, line, pie), not grid/matrix layouts. A CSS grid with `grid-template-columns: repeat(14, minmax(120px, 1fr))` handles this naturally. Each cell is a `<div>` with dynamic `bg-opacity` or HSL lightness for color intensity. Tooltips use a simple `title` attribute or a lightweight hover state component.

**Alternatives considered**:
- Recharts TreeMap: Wrong visual metaphor — TreeMap shows proportional area, not a matrix layout.
- D3.js: Overkill dependency for a static grid; React integration adds complexity.
- Canvas rendering: Not needed for ~200 cells; loses DOM accessibility and click handling.

## R5: Detection Report Print Formatting

**Decision**: CSS `@media print` rules added to the report page component. No external PDF library.

**Rationale**: Browser print-to-PDF is universally available and produces high-quality output. Adding a server-side PDF library (e.g., WeasyPrint, Puppeteer) would add significant dependency weight for minimal gain. The print stylesheet hides the sidebar, removes hover effects, and sets white background.

**Alternatives considered**:
- Server-side PDF generation: Heavy dependency, deployment complexity.
- html2canvas + jsPDF: Client-side but produces lower quality than native print.
- Dedicated PDF endpoint: Over-engineered for on-demand reports.

## R6: Sub-Technique Rollup Strategy

**Decision**: Rules store raw technique IDs (including sub-techniques like T1059.001). The heatmap endpoint aggregates sub-technique counts into parent techniques for the matrix display. Clicking a parent cell shows a drill-down modal or expanded view with per-sub-technique counts.

**Rationale**: Storing raw IDs preserves granularity. Rollup at query time is simple (split on ".", take first part). The drill-down provides analysts with sub-technique detail when needed without cluttering the matrix.

**Implementation**: In the `/api/dashboard/mitre-matrix` endpoint, for each rule's technique IDs:
1. If ID contains "." → it's a sub-technique; aggregate into parent (e.g., T1059.001 → T1059)
2. If ID has no "." → it's a parent technique; count directly
3. Return both parent-level counts and per-technique sub-technique breakdown
