"""Add tenant-scoped enterprise imports, assets and exposures.

Revision ID: 0003_enterprise_onboarding
Revises: 0002_enterprise_identity
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0003_enterprise_onboarding"
down_revision = "0002_enterprise_identity"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "enterprise_imports",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("uploaded_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("rows_total", sa.Integer(), server_default="0", nullable=False),
        sa.Column("rows_valid", sa.Integer(), server_default="0", nullable=False),
        sa.Column("rows_invalid", sa.Integer(), server_default="0", nullable=False),
        sa.Column("rows_duplicate", sa.Integer(), server_default="0", nullable=False),
        sa.Column("records_imported", sa.Integer(), server_default="0", nullable=False),
        sa.Column("detected_columns", postgresql.JSONB(astext_type=sa.Text()), server_default="[]", nullable=False),
        sa.Column("column_mapping", postgresql.JSONB(astext_type=sa.Text()), server_default="{}", nullable=False),
        sa.Column("validation_errors", postgresql.JSONB(astext_type=sa.Text()), server_default="[]", nullable=False),
        sa.Column("validation_errors_truncated", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["uploaded_by"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "content_sha256", name="uq_enterprise_import_org_hash"),
    )
    op.create_index(
        "ix_enterprise_import_org_created", "enterprise_imports",
        ["organization_id", "created_at"], unique=False,
    )
    op.create_table(
        "enterprise_assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("import_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", sa.String(length=255), nullable=False),
        sa.Column("asset_name", sa.String(length=255), nullable=True),
        sa.Column("asset_type", sa.String(length=120), nullable=True),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("operating_system", sa.String(length=255), nullable=True),
        sa.Column("business_criticality", sa.String(length=32), nullable=True),
        sa.Column("internet_exposed", sa.Boolean(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["import_id"], ["enterprise_imports.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "asset_id", name="uq_enterprise_asset_org_asset"),
    )
    op.create_index(
        "ix_enterprise_asset_org_import", "enterprise_assets",
        ["organization_id", "import_id"], unique=False,
    )
    op.create_table(
        "enterprise_exposures",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("import_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", sa.String(length=255), nullable=False),
        sa.Column("row_sha256", sa.String(length=64), nullable=False),
        sa.Column("software_name", sa.String(length=255), nullable=True),
        sa.Column("installed_version", sa.String(length=255), nullable=True),
        sa.Column("cve_id", sa.String(length=32), nullable=True),
        sa.Column("vulnerability_name", sa.String(length=500), nullable=True),
        sa.Column("severity", sa.String(length=24), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("known_exploited", sa.Boolean(), nullable=True),
        sa.Column("remediation_status", sa.String(length=120), nullable=True),
        sa.Column("first_detected", sa.Date(), nullable=True),
        sa.Column("applicability_status", sa.String(length=40), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("risk_tier", sa.String(length=16), nullable=True),
        sa.Column("risk_factors", postgresql.JSONB(astext_type=sa.Text()), server_default="{}", nullable=False),
        sa.Column("missing_evidence", postgresql.JSONB(astext_type=sa.Text()), server_default="[]", nullable=False),
        sa.Column("source_evidence", postgresql.JSONB(astext_type=sa.Text()), server_default="{}", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["import_id"], ["enterprise_imports.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["organization_id", "asset_id"],
            ["enterprise_assets.organization_id", "enterprise_assets.asset_id"],
            ondelete="CASCADE",
            name="fk_enterprise_exposure_org_asset",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("import_id", "row_sha256", name="uq_enterprise_exposure_import_row"),
    )
    op.create_index(
        "ix_enterprise_exposure_org_import", "enterprise_exposures",
        ["organization_id", "import_id"], unique=False,
    )
    op.create_index(
        "ix_enterprise_exposure_asset", "enterprise_exposures",
        ["organization_id", "asset_id"], unique=False,
    )
    op.create_index(
        "ix_enterprise_exposure_cve", "enterprise_exposures",
        ["organization_id", "cve_id"], unique=False,
    )
    op.create_index(
        "ix_enterprise_exposure_tier", "enterprise_exposures",
        ["organization_id", "risk_tier"], unique=False,
    )


def downgrade():
    op.drop_index("ix_enterprise_exposure_tier", table_name="enterprise_exposures")
    op.drop_index("ix_enterprise_exposure_cve", table_name="enterprise_exposures")
    op.drop_index("ix_enterprise_exposure_asset", table_name="enterprise_exposures")
    op.drop_index("ix_enterprise_exposure_org_import", table_name="enterprise_exposures")
    op.drop_table("enterprise_exposures")
    op.drop_index("ix_enterprise_asset_org_import", table_name="enterprise_assets")
    op.drop_table("enterprise_assets")
    op.drop_index("ix_enterprise_import_org_created", table_name="enterprise_imports")
    op.drop_table("enterprise_imports")
