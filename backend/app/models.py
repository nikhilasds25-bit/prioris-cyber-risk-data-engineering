import uuid
from datetime import date, datetime
from sqlalchemy import (
    Boolean, Date, DateTime, Float, ForeignKey, Index, Integer, String,
    UniqueConstraint, func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class DashboardSnapshot(Base):
    __tablename__ = "dashboard_snapshots"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    snapshot_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    snapshot_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    summary: Mapped[dict] = mapped_column(JSONB, nullable=False)
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ExposureRecord(Base):
    __tablename__ = "exposure_records"
    __table_args__ = (
        UniqueConstraint("snapshot_id", "view_name", "record_id", name="uq_exposure_snapshot_view_record"),
        Index("ix_exposure_snapshot_view", "snapshot_id", "view_name"),
        Index("ix_exposure_asset_id", "asset_id"),
        Index("ix_exposure_cve_id", "cve_id"),
        Index("ix_exposure_risk_tier", "risk_tier"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    snapshot_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("dashboard_snapshots.id", ondelete="CASCADE"), nullable=False
    )
    view_name: Mapped[str] = mapped_column(String(16), nullable=False)  # confirmed | review
    record_id: Mapped[int] = mapped_column(Integer, nullable=False)
    asset_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cve_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    risk_tier: Mapped[str | None] = mapped_column(String(16), nullable=True)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    known_exploited: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
