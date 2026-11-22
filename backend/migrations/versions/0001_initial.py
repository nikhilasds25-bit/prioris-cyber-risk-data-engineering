"""Create dashboard snapshot and exposure record tables."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "dashboard_snapshots",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("snapshot_hash", sa.String(length=64), nullable=False),
        sa.Column("snapshot_date", sa.Date(), nullable=True),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_synthetic", sa.Boolean(), nullable=False),
        sa.Column("summary", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("snapshot_hash"),
    )
    op.create_table(
        "exposure_records",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("snapshot_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("view_name", sa.String(length=16), nullable=False),
        sa.Column("record_id", sa.Integer(), nullable=False),
        sa.Column("asset_id", sa.String(length=255), nullable=True),
        sa.Column("cve_id", sa.String(length=32), nullable=True),
        sa.Column("risk_tier", sa.String(length=16), nullable=True),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("known_exploited", sa.Boolean(), nullable=True),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.ForeignKeyConstraint(["snapshot_id"], ["dashboard_snapshots.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("snapshot_id", "view_name", "record_id", name="uq_exposure_snapshot_view_record"),
    )
    op.create_index("ix_exposure_snapshot_view", "exposure_records", ["snapshot_id", "view_name"])
    op.create_index("ix_exposure_asset_id", "exposure_records", ["asset_id"])
    op.create_index("ix_exposure_cve_id", "exposure_records", ["cve_id"])
    op.create_index("ix_exposure_risk_tier", "exposure_records", ["risk_tier"])


def downgrade():
    op.drop_index("ix_exposure_risk_tier", table_name="exposure_records")
    op.drop_index("ix_exposure_cve_id", table_name="exposure_records")
    op.drop_index("ix_exposure_asset_id", table_name="exposure_records")
    op.drop_index("ix_exposure_snapshot_view", table_name="exposure_records")
    op.drop_table("exposure_records")
    op.drop_table("dashboard_snapshots")
