# Quickstart: MITRE Heatmap, Detection Report, and LogSource Coverage Fix

**Date**: 2026-03-22

## Verification Steps

### Phase 1: LogSource Hierarchical Matching

1. **Start backend**: `cd backend && uvicorn app.main:app --reload --port 8080`
2. **Start frontend**: `cd frontend && npm run dev`
3. **Navigate to Log Sources page** (`/log-sources`)
4. **Click "Auto-Discover from Rules"** — verify:
   - Toast/message shows number of new log source entries created
   - Table populates with all unique logsource combinations from rules
   - New entries default to "unavailable" (red/off toggle)
5. **Toggle a product-level entry** (e.g., "windows") to available
6. **Navigate to Rules Library** (`/rules`) — verify:
   - Rules with `product: windows` now show log source as covered
   - Color coding: green (exact match), amber (partial/product match), red (unmatched)
7. **Check scoring**: Navigate to a rule detail → Score Breakdown → verify log source component reflects match type

### Phase 2: MITRE ATT&CK Heatmap

1. **Navigate to MITRE Coverage page** (`/mitre`) via sidebar
2. **Verify matrix renders**: 14 tactic columns with technique cells
3. **Verify color coding**: Techniques with rules show color intensity; uncovered = gray
4. **Verify summary bar**: "X of Y techniques covered (Z%)"
5. **Hover a covered technique**: Tooltip shows technique name + rule count + implemented count
6. **Click a covered technique**: Navigates to Rules Library filtered by that technique ID
7. **Test scrolling**: Resize browser narrow — matrix should scroll horizontally

### Phase 3: Detection Report

1. **Navigate to Detection Report page** (`/report`) via sidebar
2. **Verify all sections load**:
   - Executive Summary KPIs
   - Pipeline Status bar
   - MITRE Coverage (tactic-level progress bars)
   - Log Source Coverage table
   - Score Distribution histogram
3. **Click "Print Report"**: Browser print dialog opens, clean layout (no sidebar)
4. **Click "Export JSON"**: JSON file downloads with timestamp in filename
5. **Verify zero-state**: If no rules exist, all sections show zero counts without errors

## Manual Acceptance Checklist

- [ ] Auto-discover creates entries for all unique rule logsource combinations
- [ ] Hierarchical matching correctly resolves product-level matches
- [ ] Rules Library shows match type color coding (green/amber/red)
- [ ] Scoring reflects graduated match confidence
- [ ] MITRE matrix displays 14 tactic columns
- [ ] Technique cells colored by coverage intensity
- [ ] Click-through from technique to filtered Rules Library works
- [ ] Sub-technique counts aggregate into parent techniques
- [ ] Detection report loads all 5 sections
- [ ] Print produces clean output
- [ ] JSON export downloads valid data
- [ ] All pages handle empty state gracefully
