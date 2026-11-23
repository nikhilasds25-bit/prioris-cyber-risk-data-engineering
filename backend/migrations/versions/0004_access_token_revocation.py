"""Persist access-token revocations for logout.

Revision ID: 0004_access_token_revocation
Revises: 0003_enterprise_onboarding
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0004_access_token_revocation"
down_revision = "0003_enterprise_onboarding"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "revoked_access_tokens",
        sa.Column("token_id", sa.String(length=64), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("token_id"),
    )
    op.create_index("ix_revoked_access_tokens_user_id", "revoked_access_tokens", ["user_id"], unique=False)
    op.create_index("ix_revoked_access_tokens_expires_at", "revoked_access_tokens", ["expires_at"], unique=False)


def downgrade():
    op.drop_index("ix_revoked_access_tokens_expires_at", table_name="revoked_access_tokens")
    op.drop_index("ix_revoked_access_tokens_user_id", table_name="revoked_access_tokens")
    op.drop_table("revoked_access_tokens")
