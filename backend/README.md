# PRIORIS API — Backend Foundation

This is the first backend milestone for the existing PRIORIS React/Vite dashboard.
It deliberately imports the dashboard export format already produced by
`scripts/export_dashboard_data.py`; it does not fabricate enterprise data or
change the PySpark matching/scoring methodology.

## Current scope

- FastAPI read-only API
- PostgreSQL snapshot and exposure persistence
- Alembic database migration
- Idempotent, SHA-256 checked import of dashboard exports
- Paginated confirmed-exposure and review-queue endpoints
- Asset and CVE summary endpoints
- Liveness/readiness health checks
- Restricted CORS and baseline response security headers

The current export is labelled synthetic by the existing export pipeline. The
API preserves that label. Do not upload confidential enterprise inventories to
a public deployment: authentication, authorization, tenant isolation, and
privacy controls must be completed before real organization data is accepted.

## Local setup (PowerShell)

From this `backend` directory:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
```

Create a local PostgreSQL database named `prioris`, then set `DATABASE_URL` in
`.env`. Do not share or commit the real connection string.

Apply the migration and start the API:

```powershell
alembic upgrade head
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/docs`.

## Import existing dashboard exports

Generate the dashboard export with the existing root-level script first. It
creates `web/public/data/dashboard-summary.json`,
`confirmed-exposures.json.gz`, and `review-queue.json.gz`.

From this backend directory:

```powershell
python -m app.importer --input-dir ..\web\public\data
```

The importer streams the compressed exposure arrays in batches. It is
idempotent: identical export files are identified by SHA-256 and are not
imported twice. A changed export creates a new immutable snapshot.

## API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health/live` | Process liveness |
| GET | `/health/ready` | Database readiness |
| GET | `/api/v1/dashboard/summary` | Latest dashboard summary |
| GET | `/api/v1/assets` | Asset summary rows |
| GET | `/api/v1/vulnerabilities` | CVE summary rows |
| GET | `/api/v1/exposures/confirmed` | Scored exposure rows |
| GET | `/api/v1/exposures/review` | Unscored/review rows |

Exposure endpoints support `offset`, `limit` (maximum 200), `asset_id`,
`cve_id`, and `risk_tier` query parameters.

## Render deployment settings (when repository changes are approved)

Keep the Render service root directory at the repository root so the API
container can access the existing `web/public/data` export files for import.

- Build command: `pip install -r backend/requirements.txt`
- Start command: `cd backend && uvicorn app.main:app --host 0.0.0.0 --port $PORT`
- Health check path: `/health/ready`
- Required environment variable: `DATABASE_URL`
- Set `CORS_ORIGINS` to the exact deployed Vercel origin(s), comma-separated.
- Set `ENVIRONMENT=production`.

Do not create a Render PostgreSQL database or service until its current plan,
storage, retention, and usage charges have been checked against the project
budget. The API can be tested locally first. The Free web-service plan does not
support pre-deploy commands or shell access, so the first schema migration and
snapshot import are run from your local machine through the database's
external connection URL. Put that URL only in your local `backend/.env`, run
the commands below, then leave Render's internal `DATABASE_URL` setting as
configured by the Blueprint.

```powershell
Set-Location D:\Projects\Prioris-git\backend
alembic upgrade head
python -m app.importer --input-dir ..\web\public\data
```

Do not paste the database URL into chat or commit it.

## Tests

```powershell
pytest -q
```

The initial tests cover liveness, service identity, and read-only API behavior.
A live PostgreSQL integration test should be added when a local test database
is available.

## Connect the existing Vercel frontend

The archive includes an API-aware replacement for `web/src/lib/data.ts`.
Copy it into the repository only after the Render API has deployed and the
first dashboard snapshot has been imported. Then add this Vercel Production
environment variable and redeploy:

`VITE_API_BASE_URL=https://<your-api-service>.onrender.com`

Until that variable is configured, the existing frontend continues to read its
current static JSON exports. Once configured, API errors are surfaced instead
of silently falling back to potentially stale static files.
