"""Organisation membership, invitation and audit APIs."""
from datetime import datetime, timedelta, timezone
import re
import secrets
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_membership, get_current_user, require_roles
from app.models import AuditLog, Organization, OrganizationInvitation, OrganizationMembership, User
from app.security import hash_invitation_token, hash_password

router = APIRouter(prefix="/api/v1/organizations", tags=["organizations"])


class InvitationRequest(BaseModel):
    email: str
    role: str = Field(pattern="^(admin|analyst|viewer)$")

    @field_validator("email")
    @classmethod
    def normalise_email(cls, value: str) -> str:
        value = value.strip().lower()
        if len(value) > 320 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
            raise ValueError("A valid email address is required")
        return value


class AcceptInvitationRequest(BaseModel):
    token: str = Field(min_length=32, max_length=128)
    password: str | None = Field(default=None, min_length=12, max_length=128)


class MembershipUpdateRequest(BaseModel):
    role: str | None = Field(default=None, pattern="^(admin|analyst|viewer)$")
    is_active: bool | None = None

    @model_validator(mode="after")
    def require_update(self):
        if self.role is None and self.is_active is None:
            raise ValueError("Provide a role or active-state change")
        return self


def audit(db: Session, organization_id, actor_id, action: str, target_type=None, target_id=None, details=None):
    db.add(AuditLog(
        organization_id=organization_id,
        actor_user_id=actor_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        details=details or {},
    ))


@router.get("/current")
def current_organization(
    membership: OrganizationMembership = Depends(get_current_membership),
    db: Session = Depends(get_db),
):
    organization = db.get(Organization, membership.organization_id)
    return {
        "id": str(organization.id),
        "name": organization.name,
        "slug": organization.slug,
        "role": membership.role,
        "created_at": organization.created_at,
    }


@router.post("/invitations", status_code=status.HTTP_201_CREATED)
def create_invitation(
    payload: InvitationRequest,
    membership: OrganizationMembership = Depends(require_roles("admin")),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    organization_id = membership.organization_id
    existing_user = db.scalar(select(User).where(User.email == payload.email))
    if existing_user and db.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.organization_id == organization_id,
            OrganizationMembership.user_id == existing_user.id,
            OrganizationMembership.is_active.is_(True),
        )
    ):
        raise HTTPException(status_code=409, detail="This user is already an organization member")

    raw_token = secrets.token_urlsafe(36)
    invitation = OrganizationInvitation(
        organization_id=organization_id,
        email=payload.email,
        role=payload.role,
        token_hash=hash_invitation_token(raw_token),
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        created_by=user.id,
    )
    db.add(invitation)
    audit(db, organization_id, user.id, "organization.invitation_created",
          "invitation", str(invitation.id), {"email": payload.email, "role": payload.role})
    db.commit()
    return {
        "invitation_id": str(invitation.id),
        "email": invitation.email,
        "role": invitation.role,
        "expires_at": invitation.expires_at,
        "invitation_token": raw_token,
        "delivery": "manual",
        "note": "Share this token securely with the invited user. Email delivery is not configured yet.",
    }


@router.post("/invitations/accept", status_code=status.HTTP_201_CREATED)
def accept_invitation(payload: AcceptInvitationRequest, db: Session = Depends(get_db)):
    invitation = db.scalar(
        select(OrganizationInvitation)
        .where(OrganizationInvitation.token_hash == hash_invitation_token(payload.token))
        .with_for_update()
    )
    now = datetime.now(timezone.utc)
    if invitation is None or invitation.accepted_at is not None or invitation.expires_at <= now:
        raise HTTPException(status_code=400, detail="Invitation is invalid, expired or already used")

    user = db.scalar(select(User).where(User.email == invitation.email))
    if user is None:
        if not payload.password:
            raise HTTPException(status_code=422, detail="A password of at least 12 characters is required")
        user = User(email=invitation.email, password_hash=hash_password(payload.password))
        db.add(user)
        db.flush()
    elif not user.is_active:
        raise HTTPException(status_code=403, detail="This user account is disabled")

    existing = db.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.organization_id == invitation.organization_id,
            OrganizationMembership.user_id == user.id,
        )
    )
    if existing:
        raise HTTPException(status_code=409, detail="User already has a membership in this organization")

    membership = OrganizationMembership(
        organization_id=invitation.organization_id,
        user_id=user.id,
        role=invitation.role,
    )
    invitation.accepted_at = now
    db.add(membership)
    audit(db, invitation.organization_id, user.id, "organization.invitation_accepted",
          "membership", str(membership.id), {"role": invitation.role})
    db.commit()
    return {"status": "accepted", "organization_id": str(invitation.organization_id), "role": invitation.role}


@router.get("/current/members")
def list_members(
    membership: OrganizationMembership = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
):
    rows = db.execute(
        select(User, OrganizationMembership)
        .join(OrganizationMembership, OrganizationMembership.user_id == User.id)
        .where(OrganizationMembership.organization_id == membership.organization_id)
        .order_by(User.email)
    ).all()
    return [
        {
            "user_id": str(user.id),
            "email": user.email,
            "role": member.role,
            "is_active": member.is_active,
            "joined_at": member.created_at,
        }
        for user, member in rows
    ]


@router.patch("/current/members/{user_id}")
def update_member(
    user_id: uuid.UUID,
    payload: MembershipUpdateRequest,
    membership: OrganizationMembership = Depends(require_roles("admin")),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    target = db.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.organization_id == membership.organization_id,
            OrganizationMembership.user_id == user_id,
        )
    )
    if target is None:
        raise HTTPException(status_code=404, detail="Organization member not found")
    resulting_role = payload.role if payload.role is not None else target.role
    resulting_active = payload.is_active if payload.is_active is not None else target.is_active
    removes_admin = target.role == "admin" and (resulting_role != "admin" or not resulting_active)
    if removes_admin:
        db.scalar(
            select(Organization).where(Organization.id == membership.organization_id).with_for_update()
        )
        active_admins = db.scalar(
            select(func.count()).select_from(OrganizationMembership).where(
                OrganizationMembership.organization_id == membership.organization_id,
                OrganizationMembership.role == "admin",
                OrganizationMembership.is_active.is_(True),
            )
        ) or 0
        if active_admins <= 1:
            raise HTTPException(status_code=409, detail="The last active organization admin cannot be removed")
    target.role = resulting_role
    target.is_active = resulting_active
    audit(
        db, membership.organization_id, user.id, "organization.member_updated",
        "membership", str(target.id),
        {"user_id": str(user_id), "role": resulting_role, "is_active": resulting_active},
    )
    db.commit()
    return {"user_id": str(user_id), "role": target.role, "is_active": target.is_active}


@router.get("/current/audit-logs")
def list_audit_logs(
    membership: OrganizationMembership = Depends(require_roles("admin")),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    rows = db.scalars(
        select(AuditLog)
        .where(AuditLog.organization_id == membership.organization_id)
        .order_by(desc(AuditLog.created_at))
        .limit(limit)
    ).all()
    return [
        {
            "id": str(row.id),
            "actor_user_id": str(row.actor_user_id) if row.actor_user_id else None,
            "action": row.action,
            "target_type": row.target_type,
            "target_id": row.target_id,
            "details": row.details,
            "created_at": row.created_at,
        }
        for row in rows
    ]
