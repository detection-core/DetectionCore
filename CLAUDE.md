# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**DetectionCore** is an on-premises detection engineering platform. It pulls SIGMA rules from DetectionHub SaaS, converts them to Elasticsearch/Kibana queries, scores their relevance to the local environment, and manages analyst intake.

Stack: FastAPI + Beanie ODM (MongoDB) backend, React 18 + TypeScript + Vite frontend, pySigma for rule conversion, pluggable AI providers (Gemini, OpenRouter, Anthropic).

---

## Development Commands

### Backend
```bash
cd backend
# Install deps
pip install -r requirements.txt
# Or use the local venv (required — uvicorn runs from here):
.venv/Scripts/pip install -r requirements.txt

# Run dev server (port 8080, NOT 8000 — 8000 is DetectionHub)
uvicorn app.main:app --reload --port 8080
```

### Frontend
```bash
cd frontend
npm install
npm run dev      # Vite dev server (proxies /api → http://localhost:8080)
npm run build    # Production build to dist/
```

### Docker (full stack)
```bash
docker compose up -d        # Start all services (MongoDB, backend, frontend)
docker compose logs -f backend  # Watch backend logs
```

---

## Architecture & Data Flow

```
DetectionHub SaaS
      ↓  (sync_service.py pulls SIGMA rules via HTTP)
DetectionRule (MongoDB)
      ↓  (pipeline_service.py — 6 sequential async stages)
  1. CONVERTED  → sigma_converter.py (pySigma YAML → Lucene query + ELK rule JSON)
  2. ENHANCED   → ai_enhancer.py (LLM improves Lucene query, non-blocking)
  3. TESTED     → unit_test_generator.py (LLM generates attack commands, non-blocking)
  4. METADATA   → metadata_enricher.py (MITRE, references, non-blocking)
  5. SCORED     → scoring_engine.py (0–100 relevance score)
  6. QUEUED     → IntakeItem (analyst inbox, sorted by score)
      ↓  (analyst reviews, tunes, deploys)
  IMPLEMENTED → elk_client.py (POST to Kibana Detection Engine API)
```

Non-blocking stages (ENHANCED, TESTED, METADATA) log warnings and continue on failure — only conversion failure marks a rule FAILED.

---

## Key Files

### Backend
| File | Role |
|------|------|
| `backend/app/main.py` | FastAPI app, lifespan hooks, router registration, APScheduler |
| `backend/app/config.py` | Settings via pydantic-settings — loaded once at startup, **server restart required after .env changes** |
| `backend/app/models/rule.py` | `DetectionRule` document — central data model |
| `backend/app/models/intake_item.py` | `IntakeItem` — analyst queue, links to `DetectionRule` |
| `backend/app/models/scoring_config.py` | Scoring weights + org context (industries, regions, assets) |
| `backend/app/services/pipeline_service.py` | Orchestrates all 6 pipeline stages |
| `backend/app/services/sigma_converter.py` | pySigma conversion; builds Kibana rule JSON; `_ensure_list()` normalises author; `_build_threat_entries()` builds MITRE tactic+technique |
| `backend/app/services/elk_client.py` | Kibana Detection Engine deployment; normalises `author` (must be array) and `threat[].tactic` (required) at deploy time |
| `backend/app/services/ai_provider.py` | Unified LLM interface — provider selected by `DEFAULT_AI_PROVIDER` env var |
| `backend/app/services/sync_service.py` | Pulls rules from DetectionHub; parses Sigma YAML as fallback for title/tags/logsource when API metadata is empty |

### Frontend
| File | Role |
|------|------|
| `frontend/src/pages/RuleDetail.tsx` | Rule detail — Reprocess button, polling on `pipeline_status` while in-progress stages |
| `frontend/src/pages/IntakeQueue.tsx` | Analyst queue sorted by score |
| `frontend/src/api/endpoints.ts` | All API method exports |
| `frontend/vite.config.ts` | Dev proxy: `/api` → `http://localhost:8080` |

---

## Important Behaviours & Gotchas

### Settings require server restart
`config.py` loads `.env` once via pydantic-settings at import time. Changes to `.env` are not picked up until uvicorn is restarted.

### Kibana vs Elasticsearch — separate URLs
`ELK_USE_SSL=true` applies only to Elasticsearch (port 9200, HTTPS). Kibana uses `KIBANA_URL` (defaults to `http://localhost:5601`). Never set `KIBANA_URL` to an HTTPS address unless Kibana itself is TLS-terminated.

### Kibana Detection Engine API constraints
- `author` field **must be an array** (string in Sigma YAML → normalised in `sigma_converter.py` and again in `elk_client.py`)
- `threat[].tactic` is **required** — built from ATT&CK tactic tags; stale stored rules normalised at deploy time

### Sigma YAML is the source of truth
DetectionHub API `metadata` is often empty. `sync_service.py` parses the raw Sigma YAML for title, tags, and logsource as fallback. Use `_parse_sigma_yaml()` / `_extract_*_from_sigma()` helpers.

### Backfill endpoint
`POST /rules/backfill-titles` re-parses stored Sigma content for all rules missing title, MITRE, or log source — useful after sync metadata bugs are fixed.

### Beanie query syntax
Beanie `find_one()` takes filter expressions, not kwargs:
```python
# Correct
await LogSource.find_one(LogSource.category == "process_creation", LogSource.is_available == True)
# Wrong — raises Cursor.__init__() unexpected keyword argument
await LogSource.find_one(category="process_creation")
```

### AI provider selection
Set in `.env`:
```
DEFAULT_AI_PROVIDER=anthropic   # gemini | openrouter | anthropic
DEFAULT_AI_MODEL=claude-sonnet-4-6
ANTHROPIC_API_KEY=sk-ant-...
```
The `anthropic` package must be installed in the **backend `.venv`** (not the global Python), since uvicorn runs from `.venv/Scripts/python.exe`.

### Frontend polling (RuleDetail)
After clicking Reprocess, `RuleDetail.tsx` polls `/rules/{id}` every 2 seconds while `pipeline_status` is `queued`, `converted`, `enhanced`, or `tested`. Polling stops automatically at `scored` or `failed`.

---

## API Route Prefixes

All backend routes are prefixed `/api` by the FastAPI app:

| Router | Prefix |
|--------|--------|
| auth | `/api/auth` |
| rules | `/api/rules` |
| intake | `/api/intake` |
| sync | `/api/sync` |
| log_sources | `/api/log-sources` |
| elk | `/api/elk` |
| scoring | `/api/scoring` |
| dashboard | `/api/dashboard` |
| settings | `/api/settings` |

---

## Pipeline Status Enum

```
SYNCED → CONVERTED → ENHANCED → TESTED → METADATA (internal) → SCORED → QUEUED → IMPLEMENTED
                                                                                ↘ FAILED (any stage)
```

Stored as lowercase strings in MongoDB (e.g. `"queued"`, `"scored"`, `"failed"`).
