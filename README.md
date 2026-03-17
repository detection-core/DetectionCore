# DetectionCore

On-premises detection engineering platform. Pulls SIGMA rules from DetectionHub, converts them to ELK queries, scores their relevance to your environment, and manages a prioritized analyst intake queue.

## Architecture

```
DetectionHub SaaS (API Key)
        │
        ▼ pull rules
  ┌─────────────┐    SIGMA→ELK    ┌─────────────────┐
  │  DetectionCore  │ ──pySigma──▶ │  ELK / Docker   │
  │  (FastAPI +     │  AI enhance  │  Elasticsearch  │
  │   MongoDB)      │  Unit tests  └─────────────────┘
  └─────────────┘
        │
        ▼ scored & queued
   Analyst In-Take Queue (React UI)
```

## Quick Start

### 1. Configure environment
```bash
cp .env.example .env
# Edit .env with your API keys and settings
```

### 2. Start all services
```bash
docker compose up -d
```

### 3. Access the platform
- **Frontend**: http://localhost:3000
- **API Docs**: http://localhost:8000/docs
- **Default login**: `admin` / `DetectionCore@2024!`

### 4. First-time setup
1. Login at http://localhost:3000
2. Go to **Settings** → set DetectionHub API key + ELK credentials
3. Upload log sources (CSV/JSON) at **Log Sources**
4. Trigger first sync at **Sync Status** → "Sync Now"
5. Rules will flow through the pipeline automatically

## Development (local, no Docker)

```bash
# Backend
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# Frontend
cd frontend
npm install
npm run dev
```

## Pipeline Stages

| Stage | Description |
|-------|-------------|
| `synced` | Pulled from DetectionHub |
| `converted` | SIGMA → ELK Lucene query (pySigma) |
| `enhanced` | AI-improved query (Gemini/OpenRouter) |
| `tested` | AI-generated attack simulation commands |
| `scored` | Relevance score calculated |
| `queued` | In analyst In-Take Queue |
| `implemented` | Deployed and confirmed by analyst |

## Scoring Dimensions

| Dimension | Default Weight |
|-----------|---------------|
| Log Availability | 30% |
| Industry Match | 20% |
| Severity | 20% |
| Region Match | 15% |
| Threat Actor | 10% |
| Asset Type | 5% |

Configure weights in **Settings**.

## Log Source Upload Format

**CSV:**
```csv
category,product,service,elk_index_pattern,is_available,notes
process_creation,windows,sysmon,winlogbeat-*,true,Primary Windows endpoint telemetry
network_connection,windows,,logs-endpoint.events.network-*,true,
file_event,linux,,auditbeat-*,false,Not deployed yet
```

**JSON:**
```json
[
  {"category": "process_creation", "product": "windows", "service": "sysmon",
   "elk_index_pattern": "winlogbeat-*", "is_available": true}
]
```

## Unit Tests

Unit tests are AI-generated attack simulation commands (PowerShell, bash, curl) that produce log events triggering the detection rule. Example:

```powershell
# Test: T1059.001 - PowerShell encoded command execution
powershell -EncodedCommand WwBTAHkAcwB0AGUAbQAuAEQAaQBhAGcAbgBvAHMAdABpAGMAcwAuAFAAcgBvAGMAZQBzAHMAXQA6ADoAUwB0AGEAcgB0ACgAIgBjAGEAbABjAC4AZQB4AGUAIgApAA==
```

Run tests from the **Rule Detail** page → Unit Tests tab → "Run Test" (checks ELK for matching events).

## spec-kit Methodology

This project follows [spec-driven development](https://github.com/github/spec-kit):
- `.spec-kit/constitution.md` — non-negotiable constraints
- `.spec-kit/spec.md` — full product specification
- `.spec-kit/tasks/` — implementation task breakdown
