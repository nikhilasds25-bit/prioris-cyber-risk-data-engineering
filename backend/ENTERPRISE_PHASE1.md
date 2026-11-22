# PRIORIS Enterprise — Phase 1

## Scope

Phase 1 establishes identity and tenant boundaries while preserving the existing
synthetic demo API. It adds email/password authentication, organisation
registration, membership roles, invitation acceptance, audit events, and
nullable organisation ownership on snapshots and exposure rows.

## Roles

- **admin**: manage organisation invitations, inspect members and audit logs.
- **analyst**: authenticated organisation member; reserved for upcoming ingestion
  and analysis permissions.
- **viewer**: read-only organisation member.

The demo endpoints remain unauthenticated and return only synthetic snapshots
whose organisation_id is NULL. Enterprise identity endpoints require a bearer
token. Organisation endpoints additionally require X-Organization-ID and verify
active membership on every request.

## Environment

Set AUTH_SECRET_KEY to a cryptographically random value of at least 32
characters. Generate one with:

    python -c "import secrets; print(secrets.token_urlsafe(48))"

Set ACCESS_TOKEN_EXPIRE_MINUTES (default 60). Never commit secrets.

## Migration

From backend:

    alembic upgrade head

Migration 0002 creates organizations, users, memberships, invitations and
audit_logs. It adds nullable organization_id foreign keys to dashboard
snapshots and exposure records. Existing synthetic rows remain NULL.

## API

- POST /api/v1/auth/register — create first user and organisation (admin)
- POST /api/v1/auth/login — email/password login
- POST /api/v1/auth/logout — stateless logout acknowledgement; client discards token
- GET /api/v1/auth/me — current user and memberships
- GET /api/v1/organizations/current — selected organisation (X-Organization-ID)
- POST /api/v1/organizations/invitations — admin creates analyst/viewer invite
- POST /api/v1/organizations/invitations/accept — accept invite
- GET /api/v1/organizations/current/members — admin member list
- GET /api/v1/organizations/current/audit-logs — admin audit log

Invitation tokens are returned once to the admin because email delivery is not
configured. Share through a secure channel.

## Security limitations

Passwords use Argon2 via pwdlib. Access tokens are signed JWTs (HS256), expire
after a configurable period, and are checked against active user and membership
records. Invitation tokens are stored as SHA-256 digests and expire after seven
days. Tenant-scoped routes require active membership and organisation header.

This milestone is an identity foundation, not a production security certification.
Email verification, password reset, MFA, refresh-token rotation/revocation,
rate limiting, SSO, email delivery, and an independent security review remain
outstanding. Do not onboard confidential customer data until those controls,
tenant-scoped data APIs, upload validation, backups, and monitoring are complete.
