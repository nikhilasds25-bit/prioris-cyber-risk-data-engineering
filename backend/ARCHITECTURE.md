# PRIORIS Backend Architecture — Milestone 1

```text
PySpark pipeline + dashboard export
            |
            | dashboard-summary.json
            | confirmed-exposures.json.gz
            | review-queue.json.gz
            v
    Idempotent import command
            |
            v
     PostgreSQL snapshots
       |             |
       |             +-- exposure_records (JSONB payload + indexed filter fields)
       +---------------- dashboard_snapshots (summary JSONB + provenance)
            |
            v
        FastAPI read API
            |
            v
   React/Vite dashboard (Vercel)
```

## Decisions

1. **Keep the existing pipeline intact.** The first API consumes the current
   dashboard export contract instead of changing the matcher or scorer.
2. **Snapshots are immutable.** Each import is fingerprinted; a new export
   creates a new snapshot rather than overwriting the previous one.
3. **Evidence is retained.** Exposure payloads are stored as JSONB without
   dropping the evidence, status, or review fields created by the exporter.
4. **Pagination is server-side.** Exposure queries are limited to 200 rows and
   filter on indexed asset, CVE, and risk-tier columns.
5. **No public write endpoints.** Imports run as a controlled CLI operation.
6. **Synthetic status is explicit.** The summary's `synthetic` flag is kept.
   This milestone does not turn demo data into production enterprise data.

## Deliberately deferred

- Authentication, role-based access control, tenant isolation, and audit trail
  for human actions.
- Real organization inventory upload and ingestion.
- Job queue / background worker for PySpark execution.
- NVD/KEV refresh scheduler and source-data retention policy.
- Frontend API adapter and safe static-data fallback.
- Production backup/restore exercise, monitoring, rate limiting, and load tests.

These are follow-on requirements, not claims that the initial API is a
complete production security boundary.
