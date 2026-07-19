# CaseIntel v3.0

Case-Correlated, Explainable Malware Investigation Platform for law enforcement.

**This deployment's scope:** static analysis + VirusTotal + threat-intel enrichment +
Case Knowledge Base + Correlation Engine + Investigation Acceleration + Dashboard +
Reports. **Dynamic sandbox analysis (CAPE) is intentionally not included** — it
requires nested-virtualization infrastructure that Render (and most PaaS free
tiers) don't provide. See "Known Limitations" below.

## Stack

- **Frontend:** Next.js 14, TypeScript, Tailwind CSS
- **Backend:** FastAPI, SQLAlchemy
- **Database:** PostgreSQL
- **Static analysis:** pefile, yara-python
- **Threat intel:** VirusTotal (mandatory), MalwareBazaar, AlienVault OTX, URLhaus, AbuseIPDB (all optional/free)

## Local development

### Backend
```bash
cd backend
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env    # fill in API keys
uvicorn app.main:app --reload
```
Runs on http://localhost:8000. Uses SQLite automatically if `DATABASE_URL` isn't set.

### Frontend
```bash
cd frontend
npm install
cp .env.example .env.local
npm run dev
```
Runs on http://localhost:3000, proxies `/api/*` to the backend.

## Deploying to Render (free tier)

1. Push this repo to GitHub.
2. In Render: **New > Blueprint**, point it at the repo — `render.yaml` at the root
   defines both services (`caseintel-backend`, `caseintel-frontend`) and a free
   Postgres instance.
3. After the first deploy, set these env vars on `caseintel-backend` (Render
   dashboard, not in git): `VIRUSTOTAL_API_KEY`, `OTX_API_KEY`, `ABUSEIPDB_API_KEY`,
   `MALWAREBAZAAR_API_KEY` (optional but included).
4. Update `CORS_ORIGINS` on the backend and `NEXT_PUBLIC_API_URL` on the frontend
   to match your actual `*.onrender.com` URLs once assigned.

Free tier services sleep after inactivity and cold-start on the next request —
expected on Render's free plan, not a bug.

## Getting API keys (all free)

| Service | Sign up |
|---|---|
| VirusTotal | virustotal.com → profile → API key |
| MalwareBazaar | bazaar.abuse.ch (key optional, raises limits) |
| AlienVault OTX | otx.alienvault.com |
| URLhaus | urlhaus.abuse.ch (no key needed for basic lookups) |
| AbuseIPDB | abuseipdb.com |

## Known Limitations (this deployment)

- **Auth is a shared API key, not real accounts.** `CASEINTEL_API_KEY` on the
  backend gates write actions (upload, notes, outcomes, report generation).
  The frontend sends it via `NEXT_PUBLIC_API_KEY`, which means it's visible
  to anyone inspecting requests from the deployed site — fine for blocking
  anonymous bots on a single-team pilot, not a substitute for per-analyst
  login. Replace with real authentication before handling actual case data
  beyond a pilot.
- **No dynamic sandbox analysis.** Risk scoring and MITRE mapping reflect
  static + threat-intel signals only. Persistence, Process Injection, and
  Network Communication risk rules will not fire until sandbox infrastructure
  (e.g. a self-hosted CAPE instance reachable by the backend) is added.
- **Correlation is a linear scan** over the Knowledge Base, pruned by exact-match
  indexing (hash/certificate/domain) first. Fine at pilot scale (hundreds of
  cases); an ANN index is future work if the KB grows much larger.
- **Correlation ≠ attribution**, always. The platform never states "same actor,"
  "same gang," or "confirmed related" — see `backend/app/services/reports.py` and
  the PRD's Section 8 for the full non-negotiable wording rules.

## Project structure

```
caseintel/
├── backend/
│   ├── app/
│   │   ├── main.py            # FastAPI entrypoint
│   │   ├── models.py          # SQLAlchemy models (Knowledge Base schema)
│   │   ├── database.py
│   │   ├── config.py
│   │   ├── schemas.py
│   │   ├── services/
│   │   │   ├── static_analysis.py
│   │   │   ├── virustotal.py
│   │   │   ├── threat_intel.py
│   │   │   ├── risk_score.py        # evidence-group dedup logic
│   │   │   ├── correlation.py       # ★ Correlation Engine
│   │   │   ├── acceleration.py      # Investigation Acceleration
│   │   │   └── reports.py           # PDF/HTML/CSV generation
│   │   ├── routers/
│   │   │   ├── upload.py            # full pipeline, sandbox step skipped
│   │   │   ├── cases.py
│   │   │   ├── dashboard.py
│   │   │   └── reports.py
│   │   └── yara_rules/
│   └── requirements.txt
├── frontend/
│   ├── app/                    # Next.js App Router pages
│   ├── components/             # Sidebar, CorrelationCard, AccelerationCard, etc.
│   └── lib/api.ts
└── render.yaml                 # one-click Render Blueprint
```
