"""Email/password authentication and organisation registration."""
from datetime import datetime, timezone
import re
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.dependencies import get_current_user
from app.models import AuditLog, Organization, OrganizationMembership, RevokedToken, User
from app.security import create_access_token, decode_access_token_payload, hash_password, verify_password

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])
_bearer = HTTPBearer(auto_error=False)


class Credentials(BaseModel):
    email: str
    password: str = Field(min_length=12, max_length=128)

    @field_validator("email")
    @classmethod
    def normalise_email(cls, value: str) -> str:
        value = value.strip().lower()
        if len(value) > 320 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
            raise ValueError("A valid email address is required")
        return value


class RegistrationRequest(Credentials):
    organization_name: str = Field(min_length=2, max_length=160)

    @field_validator("organization_name")
    @classmethod
    def clean_organization_name(cls, value: str) -> str:
        value = value.strip()
        if len(value) < 2:
            raise ValueError("Organization name must contain at least two characters")
        return value


class LoginRequest(BaseModel):
    email: str
    password: str = Field(min_length=1, max_length=128)

    @field_validator("email")
    @classmethod
    def normalise_email(cls, value: str) -> str:
        value = value.strip().lower()
        if len(value) > 320 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
            raise ValueError("A valid email address is required")
        return value


def ensure_auth_configured() -> None:
    secret = get_settings().auth_secret_key
    if not secret or len(secret) < 32:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Enterprise authentication is not configured on this deployment",
        )


def make_slug(name: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:150] or "organization"
    return f"{base}-{uuid.uuid4().hex[:8]}"


def token_response(user: User, db: Session) -> dict:
    ensure_auth_configured()
    token, expires_in = create_access_token(str(user.id))
    memberships = db.scalars(
        select(OrganizationMembership).where(
            OrganizationMembership.user_id == user.id,
            OrganizationMembership.is_active.is_(True),
        )
    ).all()
    org_ids = [membership.organization_id for membership in memberships]
    organizations = db.scalars(
        select(Organization).where(Organization.id.in_(org_ids), Organization.is_active.is_(True))
    ).all() if org_ids else []
    org_by_id = {organization.id: organization for organization in organizations}
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": expires_in,
        "user": {"id": str(user.id), "email": user.email},
        "organizations": [
            {
                "id": str(membership.organization_id),
                "name": org_by_id[membership.organization_id].name,
                "slug": org_by_id[membership.organization_id].slug,
                "role": membership.role,
            }
            for membership in memberships if membership.organization_id in org_by_id
        ],
    }


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(payload: RegistrationRequest, db: Session = Depends(get_db)):
    ensure_auth_configured()
    organization = Organization(name=payload.organization_name, slug=make_slug(payload.organization_name))
    user = User(email=payload.email, password_hash=hash_password(payload.password))
    try:
        db.add_all([organization, user])
        db.flush()
        membership = OrganizationMembership(
            organization_id=organization.id, user_id=user.id, role="admin"
        )
        db.add(membership)
        db.add(AuditLog(
            organization_id=organization.id,
            actor_user_id=user.id,
            action="organization.created",
            target_type="organization",
            target_id=str(organization.id),
            details={"source": "self_service_registration"},
        ))
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        if db.scalar(select(User).where(User.email == payload.email)):
            raise HTTPException(status_code=409, detail="An account with this email already exists") from exc
        raise
    db.refresh(user)
    return token_response(user, db)


@router.post("/login")
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    ensure_auth_configured()
    user = db.scalar(select(User).where(User.email == payload.email))
    if not user or not user.is_active or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    db.add(AuditLog(
        actor_user_id=user.id,
        action="auth.login",
        target_type="user",
        target_id=str(user.id),
        details={},
    ))
    db.commit()
    return token_response(user, db)


@router.post("/logout")
def logout(
    user: User = Depends(get_current_user),
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
):
    payload = decode_access_token_payload(credentials.credentials) if credentials else None
    if not payload or payload.get("sub") != str(user.id):
        raise HTTPException(status_code=401, detail="Invalid or expired access token")
    expires_at = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
    db.execute(delete(RevokedToken).where(RevokedToken.expires_at < datetime.now(timezone.utc)))
    db.add(RevokedToken(token_id=payload["jti"], user_id=user.id, expires_at=expires_at))
    db.add(AuditLog(
        actor_user_id=user.id,
        action="auth.logout",
        target_type="user",
        target_id=str(user.id),
        details={},
    ))
    db.commit()
    return {"status": "ok", "message": "Access token revoked"}


@router.get("/me")
def me(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    memberships = db.scalars(
        select(OrganizationMembership).where(
            OrganizationMembership.user_id == user.id,
            OrganizationMembership.is_active.is_(True),
        )
    ).all()
    organizations = {
        organization.id: organization
        for organization in db.scalars(
            select(Organization).where(
                Organization.id.in_([m.organization_id for m in memberships]),
                Organization.is_active.is_(True),
            )
        ).all()
    } if memberships else {}
    return {
        "id": str(user.id),
        "email": user.email,
        "organizations": [
            {
                "id": str(m.organization_id),
                "name": organizations[m.organization_id].name,
                "slug": organizations[m.organization_id].slug,
                "role": m.role,
            }
            for m in memberships if m.organization_id in organizations
        ],
    }
