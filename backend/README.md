# PRIORIS API — Backend and Enterprise Workspace

The FastAPI backend serves the existing synthetic React/Vite dashboard and an
independent, organisation-scoped enterprise workspace. Enterprise imports do
not modify or combine with synthetic dashboard snapshots.

## Current scope

- FastAPI API
- PostgreSQL snapshot and exposure persistence
- Alembic schema migrations
- Idempotent, SHA-256 checked import of dashboard exports
- Paginated confirmed-exposure and review-queue endpoints
- Asset and CVE summary endpoints
- Argon2 password hashing, signed bearer tokens, persisted logout revocation
- Organisation registration, invitations, membership roles, audit events and RBAC
- CSV/JSON upload preview, column mapping, row validation and tenant-scoped import history
- Latest-import asset, vulnerability finding, risk summary and review views
- Scanner connector protocol for future vendor adapters
- Liveness/readiness health checks
- Restricted CORS and baseline response security headers

The current export is labelled synthetic by the existing export pipeline. The
API preserves that label. Company findings are explicitly labelled
`reported_unverified` unless they require review, and are not represented as
independently confirmed CVE-to-product matches. No live NVD/CPE matching or
scanner API connector is included in this onboarding layer.

## Local setup (PowerShell)

From this `backend` directory:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
if (!(Test-Path .env)) { Copy-Item .env.example .env }
```

Create a local PostgreSQL database named `prioris`, then set `DATABASE_URL` in
`.env`. Set `AUTH_SECRET_KEY` to a locally generated random value of at least
32 characters and set `CORS_ORIGINS` to the exact frontend origin. Never share
or commit either secret. Existing `.env` files are intentionally not overwritten.

Apply the migration and start the API:

```powershell
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
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
| POST | `/api/v1/auth/register` | Register a user and create an organisation |
| POST | `/api/v1/auth/login` | Sign in and issue a signed bearer token |
| POST | `/api/v1/auth/logout` | Revoke the current access token |
| GET | `/api/v1/auth/me` | Current user and active memberships |
| POST | `/api/v1/organizations/invitations` | Admin creates a manual-delivery invitation |
| POST | `/api/v1/organizations/invitations/accept` | Accept an invitation |
| GET/PATCH | `/api/v1/organizations/current/members` | Admin-only member listing and role/status updates |
| GET | `/api/v1/organizations/current/audit-logs` | Admin-only organisation audit history |
| POST | `/api/v1/enterprise/imports/preview` | Detect columns, apply mappings and validate CSV/JSON |
| POST | `/api/v1/enterprise/imports` | Import valid rows into the active organisation |
| GET | `/api/v1/enterprise/imports` | Tenant-scoped import history |
| GET | `/api/v1/enterprise/imports/{id}/errors.csv` | Download retained validation errors |
| GET | `/api/v1/enterprise/summary` | Latest-import aggregates and ranked assets/CVEs/software |
| GET | `/api/v1/enterprise/assets` | Paginated, organisation-scoped assets |
| GET | `/api/v1/enterprise/exposures` | Paginated findings and evidence |

Exposure endpoints support `offset`, `limit` (maximum 200), `asset_id`,
`cve_id`, and `risk_tier` query parameters.

## Enterprise dataset onboarding

The company workspace in the frontend supports CSV and JSON files up to 10 MiB
and 100,000 rows. JSON may be an array, an object containing a `records` array,
or a single record object. Uploads are parsed in a bounded streaming pass,
previewed before import, mapped to canonical fields, and re-uploaded for the
final import. Only valid, non-duplicate rows are imported; the first 500
validation errors are retained and downloadable, with truncation reported.
The uploaded file itself is not persisted.

`asset_id` is required. CVE identifiers, severity, CVSS (0–10), boolean
evidence, criticality, exposure class and complete ISO dates are validated.
Common aliases are detected automatically; the user can correct mappings.
Identical file content is
rejected within an organisation instead of overwriting earlier data. New
imports are additive; APIs and dashboard aggregates read the latest completed
import. All enterprise queries derive their organisation from a verified
active membership and enforce the organisation ID on the server.

Enterprise scoring uses the same component implementation and thresholds as
the existing PRIORIS scoring pipeline. A score requires valid CVSS, explicit
KEV membership, recognized business criticality, and a recognized exposure
class (`internet-facing`, `internal`, or `restricted`). A reported
`internet_exposed=true` supplies the `internet-facing` class; false or missing
does not identify whether an asset is internal or restricted and therefore
does not supply that class. Incomplete scoring evidence leaves the finding
unscored and lists the missing evidence. The existing weights remain: CVSS,
+2 for explicitly true KEV, +1 per criticality level (low 0 through critical
3), +2 internet-facing, +1 internal, and 0 restricted; scores are bounded
0–17 with tiers beginning at 6, 10 and 14. Source `confirmed_match` labels
are retained as source evidence but reported as `reported_unverified`;
unresolved-product, unsupported-matching and manual-review states remain
distinct and unscored. Unresolved, unsupported and unscored records must not
be interpreted as safe.

The demonstration files `examples/enterprise_sample.csv` and
`examples/enterprise_sample.json` describe the same fictional company estate.
They include multiple assets, repeated software/CVE records, explicitly
internet-exposed systems, missing KEV evidence, an unresolved product, an
unsupported matching case, and an illustrative source `confirmed_match`.
Every CVE-like identifier starts with year `2099` and is a placeholder, not a
real vulnerability, KEV assertion, vendor advisory, or remediation instruction.
The importer intentionally downgrades source `confirmed_match` labels to
`reported_unverified`.

## End-to-end local demonstration

Use a **dedicated local PostgreSQL database**. Do not point the demonstration
at the Render production URL, and do not import these sample records into the
public Synthetic Demo dataset.

1. Configure `backend/.env` with a local-only `DATABASE_URL`, a random
   `AUTH_SECRET_KEY` of at least 32 characters, and
   `CORS_ORIGINS=http://127.0.0.1:5173`. Do not print or share the secrets.
2. From `backend/`, apply migrations to that local database and start the API:

   ```powershell
   .\.venv\Scripts\python.exe -m alembic upgrade head
   .\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
   ```

3. In a second terminal, start the existing Vite application:

   ```powershell
   Set-Location ..\web
   npm ci
   $env:VITE_API_BASE_URL = "http://127.0.0.1:8000"
   npm run dev
   ```

4. Open `http://127.0.0.1:5173`, select **Enterprise Workspace**, create a
   demo organisation using a test-only email/password, and upload either
   `backend/examples/enterprise_sample.csv` or
   `backend/examples/enterprise_sample.json`.
5. Review the detected column mapping and validation results before importing.
   The overview then shows latest-import-only asset/CVE/software rankings,
   KEV-reported cases, evidence and missing-evidence indicators, and
   prioritised remediation. A second user/org can be registered to check
   tenant isolation. Do not reuse credentials from any real account.

CSV and JSON imports have different file hashes; importing both creates two
separate imports. The workspace analyzes only the latest completed import for
the selected organisation. Use a fresh demo organisation when you want a clean
walkthrough.

## Production migration preparation — approval required

The inspected Render database was at `0001_initial`; migrations `0002` through
`0004` have **not** been applied. Do not run these commands against Render
until an operator explicitly approves the change window. The migrations are
forward-only in the safe execution plan; do not use `alembic downgrade` as a
rollback because downgrades drop the newly added tables and columns.

Before approval:

1. Confirm the Render service and database identities in the Render console
   without copying credentials into chat or logs. Confirm the current revision
   with `alembic current` and verify the existing snapshot/confirmed/review
   counts using read-only queries.
2. Take a PostgreSQL backup/snapshot and verify that it can be restored to an
   isolated database. Record the current revision and baseline counts in the
   change ticket.
3. Review the migration SQL from this exact branch with
   `.\.venv\Scripts\python.exe -m alembic upgrade head --sql`. Verify the
   target head is `0004_access_token_revocation`.
4. Schedule a maintenance window, pause writes/imports, and apply once from a
   trusted machine using the Render **external** database URL stored only in
   `backend/.env`:

   ```powershell
   .\.venv\Scripts\python.exe -m alembic upgrade head
   ```

5. Verify the recorded revision is `0004_access_token_revocation`; confirm
   `dashboard_snapshots` and `exposure_records` still have their baseline
   record counts and existing rows retain a null `organization_id`; check
   the new enterprise tables and foreign keys; then resume the API and writes.
6. If anything differs, stop, preserve logs with URLs/secrets removed, and
   restore/recover under the database operator's approved procedure. Do not
   guess with destructive SQL or downgrade migrations.

Migration review: `0002` adds organisation/user tables and nullable tenant
columns to existing dashboard tables; `0003` adds separate enterprise import,
asset and exposure tables; `0004` adds token revocation storage. None of their
upgrade functions deletes, truncates, or rewrites synthetic records. This is a
code-level review, not proof from applying the migrations to a production
copy; a backup restore rehearsal is still required.

## Frontend development

From `web/`, install dependencies and run the existing Vite app:

```powershell
npm ci
$env:VITE_API_BASE_URL = "http://127.0.0.1:8000"
npm run dev
```

The Synthetic Demo remains available independently. Enterprise authentication
uses the configured API. The browser stores only the short-lived bearer token
in tab-scoped `sessionStorage`; passwords are never persisted.

## Security and deployment limitations

- Use HTTPS, exact CORS origins, database backups, secret rotation and a
  reviewed production deployment before accepting sensitive inventories.
- Authentication currently has no rate limiting, MFA, email verification or
  invitation email delivery. Invitations are manually shared one-time tokens.
- Scanner adapters are interfaces only; no vendor credentials or integration
  are implemented.
- `reported_unverified` records are not checked against NVD/CPE data. The
  supplied CVE, CVSS, KEV, criticality and network values are not independently
  validated against external sources.
- Protect the frontend against XSS; tab-scoped `sessionStorage` is accessible
  to same-origin scripts. Consider a reviewed HttpOnly-cookie design before
  public production use.
- Configure web-server request/body limits as well as the API's 10 MiB file
  limit, and define tenant data retention and deletion policies.

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
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m app.importer --input-dir ..\web\public\data
```

Do not paste the database URL into chat or commit it.

## Tests

```powershell
pytest -q
```

The tests cover authentication primitives, tenant role enforcement, upload
mapping/validation, risk evidence and ranking, read-only tenant scoping,
synthetic-route preservation and liveness. Run them with
`.\.venv\Scripts\python.exe -m pytest -v`. Database-backed registration and
import demonstration requires a local isolated PostgreSQL instance; the
checked Render database must not be used as a substitute for a test database.
The frontend logout regression tests can be run from `web/` with
`node --experimental-strip-types --test tests/logout.test.ts` (Node.js 22.6+).

## Connect the existing Vercel frontend

Set this Vercel Production environment variable only after the backend and
required schema migrations are intentionally deployed. Replace the example
value in `web/.env.example` with the exact API origin shown in the Render
service settings; the repository cannot establish the assigned Render
hostname:

`VITE_API_BASE_URL=https://<your-api-service>.onrender.com`

Until configured, the Synthetic Demo continues to read static JSON exports.
Once configured, enterprise login and uploads use the API, and API errors are
surfaced instead of silently falling back to stale data.
