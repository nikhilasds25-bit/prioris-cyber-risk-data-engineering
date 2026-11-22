"""Authentication and tenant-membership dependencies."""
import uuid

from fastapi import Depends, Header, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Organization, OrganizationMembership, User
from app.security import decode_access_token

_bearer = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Bearer access token required")
    subject = decode_access_token(credentials.credentials)
    if not subject:
        raise HTTPException(status_code=401, detail="Invalid or expired access token")
    try:
        user_id = uuid.UUID(subject)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid access token subject")
    user = db.scalar(select(User).where(User.id == user_id, User.is_active.is_(True)))
    if user is None:
        raise HTTPException(status_code=401, detail="User account is unavailable")
    return user


def get_current_membership(
    user: User = Depends(get_current_user),
    organization_id: str = Header(alias="X-Organization-ID"),
    db: Session = Depends(get_db),
) -> OrganizationMembership:
    try:
        org_id = uuid.UUID(organization_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="X-Organization-ID must be a valid UUID")
    membership = db.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.user_id == user.id,
            OrganizationMembership.organization_id == org_id,
            OrganizationMembership.is_active.is_(True),
        )
    )
    if membership is None:
        raise HTTPException(status_code=403, detail="You do not belong to this organization")
    organization = db.scalar(
        select(Organization).where(Organization.id == org_id, Organization.is_active.is_(True))
    )
    if organization is None:
        raise HTTPException(status_code=403, detail="Organization is unavailable")
    return membership


def require_roles(*roles: str):
    def dependency(membership: OrganizationMembership = Depends(get_current_membership)):
        if membership.role not in roles:
            raise HTTPException(status_code=403, detail="Your organization role cannot perform this action")
        return membership
    return dependency
